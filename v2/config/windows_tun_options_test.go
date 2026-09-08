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

func windowsRule(t *testing.T, value string) option.Rule {
	t.Helper()
	var rule option.Rule
	require.NoError(t, json.Unmarshal([]byte(value), &rule))
	return rule
}

func TestWindowsPolicyPreservesEarlierDecisions(t *testing.T) {
	direct := windowsRule(t, `{"ip_cidr":"5.160.0.0/16","outbound":"direct §hide§"}`)
	for _, tc := range []struct {
		name, earlier string
		allowed       bool
	}{
		{"none", "", true},
		{"sniff", `{"action":"sniff"}`, true},
		{"DNS hijack", `{"protocol":"dns","action":"hijack-dns"}`, true},
		{"disjoint sinkhole", `{"ip_cidr":["10.10.34.0/24"],"outbound":"proxy"}`, true},
		{"domain proxy", `{"domain_suffix":"example.ir","outbound":"proxy"}`, false},
		{"ad blocker", `{"rule_set":"geosite-ads","action":"reject"}`, false},
		{"IP proxy", `{"ip_cidr":"5.160.1.0/24","outbound":"proxy"}`, false},
		{"process rule", `{"process_name":"browser.exe","outbound":"proxy"}`, false},
		{"fragment direct", `{"domain_suffix":"example.ir","outbound":"direct-fragment §hide§"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := []option.Rule{}
			if tc.earlier != "" {
				rules = append(rules, windowsRule(t, tc.earlier))
			}
			rules = append(rules, direct)
			got := windowsSafeDirectPrefixes(rules)
			if tc.allowed {
				require.Equal(t, []netip.Prefix{netip.MustParsePrefix("5.160.0.0/16")}, got)
			} else {
				require.Empty(t, got)
			}
		})
	}
	require.Empty(t, windowsSafeDirectPrefixes(nil), "region alone never enables country bypass")
	countrySet := windowsRule(t, `{"rule_set":"geoip-ir","outbound":"direct §hide§"}`)
	require.Empty(t, windowsSafeDirectPrefixes([]option.Rule{countrySet}), "do not guess another rule set's IP content")
	portLimited := windowsRule(t, `{"port":443,"rule_set":"geoip-ir","outbound":"direct §hide§"}`)
	require.Empty(t, windowsSafeDirectPrefixes([]option.Rule{portLimited}))
	explicit := windowsRule(t, `{"ip_cidr":"203.0.113.8/32","outbound":"direct §hide§"}`)
	reject := windowsRule(t, `{"action":"reject"}`)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("203.0.113.8/32")}, windowsSafeDirectPrefixes([]option.Rule{explicit, reject}))
}

func TestWindowsRuntimeReachesFinalConfigWithoutWeakeningStrictRouting(t *testing.T) {
	tun := &option.TunInboundOptions{AutoRoute: true, StrictRoute: true}
	options := &option.Options{
		Inbounds: []option.Inbound{{Type: C.TypeTun, Options: tun}},
		Route:    &option.RouteOptions{AutoDetectInterface: true},
		DNS: &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
			Servers: []option.DNSServerOptions{{Type: C.DNSTypeUDP, Tag: DNSDirectTag, Options: &option.RemoteDNSServerOptions{}}},
		}},
	}
	require.NoError(t, applyWindowsTUNOptions(options, WindowsTUNOptions{
		Interface: "Wi-Fi", DirectDNS: []string{"178.22.122.100", "185.51.200.2"},
	}))
	require.Equal(t, "Wi-Fi", options.Route.DefaultInterface)
	require.False(t, options.Route.AutoDetectInterface)
	require.True(t, tun.StrictRoute)
	require.Len(t, tun.RouteExcludeAddress, 2)
	require.Equal(t, C.DNSTypeMulti, options.DNS.Servers[0].Type)
	pool := options.DNS.Servers[0].Options.(*option.MultiDNSServerOptions)
	require.True(t, pool.Parallel)
	require.Len(t, pool.Servers, 4)
	protocols := make(map[string]int)
	for _, server := range options.DNS.Servers[1:] {
		protocols[server.Type]++
		remote := server.Options.(*option.RemoteDNSServerOptions)
		require.Equal(t, "Wi-Fi", remote.BindInterface)
		require.Empty(t, remote.Detour)
	}
	require.Equal(t, map[string]int{C.DNSTypeUDP: 2, C.DNSTypeTCP: 2}, protocols)
}

// The country set is only useful once it leaves the tunnel: a DIRECT rule on
// Windows still hands the packet to the TUN, because there is no
// VpnService.protect() to exempt the socket.
func TestWindowsDomesticPrefixesLeaveTheTunnelOnlyWhenTheRulesSaySo(t *testing.T) {
	direct := option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{
		RawDefaultRule: option.RawDefaultRule{RuleSet: []string{"geoip-ir", "geosite-ir"}},
		RuleAction:     option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: OutboundDirectTag}},
	}}
	sinkhole := option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{
		RawDefaultRule: option.RawDefaultRule{IPCIDR: []string{"10.10.34.0/24"}},
		RuleAction:     option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: OutboundSelectTag}},
	}}
	country := []string{"5.160.0.0/16", "10.10.34.0/24", "not-a-prefix", "0.0.0.0/0"}

	// Nothing is lifted while no rule sends the country's own IP set direct.
	require.Empty(t, windowsDomesticPrefixes([]option.Rule{sinkhole}, country))
	// And nothing is lifted when the app supplies nothing.
	require.Empty(t, windowsDomesticPrefixes([]option.Rule{direct}, nil))

	lifted := windowsDomesticPrefixes([]option.Rule{sinkhole, direct}, country)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("5.160.0.0/16")}, lifted,
		"the sinkhole claims 10.10.34.0/24 by address, and /0 or junk is never a candidate")

	// End to end, through the real entry point.
	tun := &option.TunInboundOptions{AutoRoute: true, StrictRoute: true}
	options := &option.Options{
		Inbounds: []option.Inbound{{Type: C.TypeTun, Options: tun}},
		Route:    &option.RouteOptions{AutoDetectInterface: true, Rules: []option.Rule{sinkhole, direct}},
	}
	require.NoError(t, applyWindowsTUNOptions(options, WindowsTUNOptions{
		Interface: "Wi-Fi", DomesticPrefixes: country,
	}))
	require.Len(t, tun.RouteExcludeAddress, 1)
	require.Equal(t, netip.MustParsePrefix("5.160.0.0/16"), tun.RouteExcludeAddress[0])
	require.True(t, tun.StrictRoute, "strict route protects other applications and is not ours to relax")
}

func TestWindowsBuildConfigWiringAndOtherPlatformsUnchanged(t *testing.T) {
	hopts := DefaultHiddifyOptions()
	hopts.EnableTun = true
	hopts.Region = "ir"
	hopts.WindowsTUN = WindowsTUNOptions{Interface: "Ethernet", DirectDNS: []string{"178.22.122.100"}}
	input := &option.Options{Outbounds: []option.Outbound{{
		Type: C.TypeSOCKS, Tag: "test-node", Options: &option.SOCKSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "192.0.2.1", ServerPort: 1080},
		},
	}}}
	got, err := BuildConfig(context.Background(), hopts, &ReadOptions{Options: input})
	require.NoError(t, err)
	if C.IsWindows {
		require.Equal(t, "Ethernet", got.Route.DefaultInterface)
	} else {
		require.Empty(t, got.Route.DefaultInterface)
	}
}
