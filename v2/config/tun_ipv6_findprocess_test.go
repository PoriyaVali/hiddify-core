package config

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func processRule(t *testing.T, value string) option.Rule {
	t.Helper()
	var rule option.Rule
	require.NoError(t, json.Unmarshal([]byte(value), &rule))
	return rule
}

// The measured defect: ipv6-mode was ipv4_only and the TUN still took an IPv6
// address, because the only input was whether the device could resolve ::1.
func TestTunCarriesIPv6HonoursMode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   C.DomainStrategy
		device bool
		want   bool
	}{
		{"ipv4_only is refused even on a v6-capable device", C.DomainStrategyIPv4Only, true, false},
		{"as-is keeps IPv6", C.DomainStrategyAsIS, true, true},
		{"prefer_ipv4 keeps IPv6", C.DomainStrategyPreferIPv4, true, true},
		{"prefer_ipv6 keeps IPv6", C.DomainStrategyPreferIPv6, true, true},
		{"ipv6_only keeps IPv6", C.DomainStrategyIPv6Only, true, true},
		{"a device without IPv6 is refused whatever the mode", C.DomainStrategyPreferIPv6, false, false},
		{"ipv4_only on a device without IPv6", C.DomainStrategyIPv4Only, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tunCarriesIPv6(option.DomainStrategy(tc.mode), tc.device))
		})
	}
}

// find_process only ever feeds a rule that matches on the owning process. An
// IP rule switching it on is the defect measured on the owner's phone.
func TestRulesMatchProcess(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule string
		want bool
	}{
		{"the block-page IP range does not need a process lookup", `{"ip_cidr":["10.10.34.0/24"],"outbound":"select"}`, false},
		{"a domain rule does not need one", `{"domain_suffix":".ir","outbound":"direct"}`, false},
		{"a rule-set rule does not need one", `{"rule_set":["geoip-ir"],"outbound":"direct"}`, false},
		{"package_name needs one", `{"package_name":["app.drmobile.com"],"outbound":"direct"}`, true},
		{"process_name needs one", `{"process_name":["browser.exe"],"outbound":"direct"}`, true},
		{"process_path needs one", `{"process_path":["/usr/bin/curl"],"outbound":"direct"}`, true},
		{"process_path_regex needs one", `{"process_path_regex":["curl$"],"outbound":"direct"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, rulesMatchProcess([]option.Rule{processRule(t, tc.rule)}))
		})
	}

	require.False(t, rulesMatchProcess(nil), "no manual rules means no lookup")

	// The old gate said yes to this set purely because it was non-empty.
	measured := []option.Rule{
		processRule(t, `{"ip_cidr":["10.10.34.0/24"],"outbound":"select"}`),
		processRule(t, `{"domain_suffix":"drmobjay.com","outbound":"direct"}`),
	}
	require.False(t, rulesMatchProcess(measured))
	require.Positive(t, len(measured), "the old gate would have enabled find_process for exactly this")

	require.True(t, rulesMatchProcess(append(measured,
		processRule(t, `{"package_name":["org.telegram.messenger"],"outbound":"direct"}`))),
		"one process rule anywhere in the list is enough")
}

// The two fixes above are only worth anything if they survive the real
// builder, so this drives BuildConfig and reads the config the core would
// actually be handed - the same shape that was pulled off the owner's phone.
func TestBuiltConfigMatchesTheMeasuredDevice(t *testing.T) {
	build := func(t *testing.T, mode C.DomainStrategy, routeRules string) *option.Options {
		t.Helper()
		h := DefaultHiddifyOptions()
		if routeRules != "" {
			require.NoError(t, json.Unmarshal([]byte(routeRules), h))
		}
		h.EnableTun = true
		h.IPv6Mode = option.DomainStrategy(mode)
		got, err := BuildConfig(context.Background(), h, manualTestInput())
		require.NoError(t, err)
		return got
	}

	tunAddresses := func(t *testing.T, got *option.Options) []netip.Prefix {
		t.Helper()
		for _, inbound := range got.Inbounds {
			if inbound.Type != C.TypeTun {
				continue
			}
			opts, ok := inbound.Options.(*option.TunInboundOptions)
			require.True(t, ok, "tun inbound carried %T", inbound.Options)
			return opts.Address
		}
		t.Fatal("no tun inbound was built")
		return nil
	}

	// The device's own setting, and the address it wrongly kept: tun0 held
	// fdfe:dcba:9876::1/126 while the whole DNS layer was ipv4_only.
	t.Run("ipv4_only builds a TUN with no IPv6 address", func(t *testing.T) {
		for _, address := range tunAddresses(t, build(t, C.DomainStrategyIPv4Only, "")) {
			require.True(t, address.Addr().Is4(), "unexpected IPv6 address %s", address)
		}
	})

	t.Run("a mode that asks for IPv6 still gets it", func(t *testing.T) {
		if !isIPv6Supported() {
			t.Skip("this host cannot resolve ::1, so the veto applies first")
		}
		var sawIPv6 bool
		for _, address := range tunAddresses(t, build(t, C.DomainStrategyPreferIPv6, "")) {
			sawIPv6 = sawIPv6 || address.Addr().Is6()
		}
		require.True(t, sawIPv6, "prefer_ipv6 must keep the IPv6 address")
	})

	// The rule that was actually on the phone: an IP range, no process match.
	t.Run("an IP-only manual rule does not switch on find_process", func(t *testing.T) {
		got := build(t, C.DomainStrategyIPv4Only,
			`{"route-rule":{"rules":[{"enabled":true,"outbound":"proxy","ip_cidr":["10.10.34.0/24"]}]}}`)
		data, err := json.Marshal(got.Route)
		require.NoError(t, err)
		require.Contains(t, string(data), "10.10.34.0/24", "the rule must still reach the config")
		require.False(t, got.Route.FindProcess)
	})

	t.Run("a package rule still switches it on", func(t *testing.T) {
		got := build(t, C.DomainStrategyIPv4Only,
			`{"route-rule":{"rules":[{"enabled":true,"outbound":"direct","package_name":["org.telegram.messenger"]}]}}`)
		require.True(t, got.Route.FindProcess)
	})
}

// Timestamps were explicitly suppressed, which is what made 696 logged lines
// undatable on the owner's device.
func TestLogKeepsTimestamps(t *testing.T) {
	var options option.Options
	setLog(&options, &HiddifyOptions{LogLevel: "warn", LogFile: "data/box.log"})
	require.NotNil(t, options.Log)
	require.True(t, options.Log.Timestamp)
	require.False(t, options.Log.Disabled)
	require.Equal(t, "data/box.log", options.Log.Output)
}
