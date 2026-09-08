package config

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func manualTestInput() *ReadOptions {
	return &ReadOptions{Options: &option.Options{Outbounds: []option.Outbound{{Type: C.TypeSOCKS, Tag: "node", Options: &option.SOCKSOutboundOptions{ServerOptions: option.ServerOptions{Server: "192.0.2.1", ServerPort: 1080}}}}}}
}

func TestManualProtoJSONReachesFinalBuilder(t *testing.T) {
	h := DefaultHiddifyOptions()
	require.NoError(t, json.Unmarshal([]byte(`{"route-rule":{"rules":[{"enabled":true,"outbound":"direct","domain":["manual.invalid"],"ip_cidr":["203.0.113.17/32"]}]}}`), h))
	require.Len(t, h.Rules, 1)
	got, err := BuildConfig(context.Background(), h, manualTestInput())
	require.NoError(t, err)
	data, err := json.Marshal(got.Route)
	require.NoError(t, err)
	require.Contains(t, string(data), "manual.invalid")
	require.Contains(t, string(data), "203.0.113.17/32")
	require.NoError(t, json.Unmarshal([]byte(`{"route-rule":{"rules":[]}}`), h))
	require.Empty(t, h.Rules, "clearing UI rules must clear old native rules")
	require.NoError(t, json.Unmarshal([]byte(`{"rules":[{"enabled":true,"outbound":1,"domains":["legacy.invalid"]}]}`), h))
	require.Equal(t, []string{"legacy.invalid"}, h.Rules[0].Domains)
}

func TestManualRulesPreserveOrderConstraintsAndDNS(t *testing.T) {
	h := DefaultHiddifyOptions()
	require.NoError(t, json.Unmarshal([]byte(`{"route-rule":{"rules":[
 {"enabled":true,"list_order":2,"outbound":"direct","domain_suffix":["example.ir"]},
 {"enabled":false,"outbound":"direct","domain":["disabled.invalid"]},
 {"enabled":true,"list_order":1,"outbound":"proxy","domain":["private.example.ir"],"network":"tcp","protocol":["tls"],"port_range":["443","8000-8100"],"source_ip_cidr":["192.168.1.0/24"],"process_name":["browser.exe"]}
 ]}}`), h))
	routes, dnsRules, err := manualRouteRules(h)
	require.NoError(t, err)
	require.Len(t, routes, 2)
	require.Len(t, dnsRules, 1, "constrained connection rules must not become unconditional DNS rules")
	raw := routes[0].DefaultOptions
	require.Equal(t, OutboundMainDetour, raw.RouteOptions.Outbound)
	require.Equal(t, []string{"tcp"}, []string(raw.Network))
	require.Equal(t, []string{"tls"}, []string(raw.Protocol))
	require.Equal(t, []uint16{443}, []uint16(raw.Port))
	require.Equal(t, []string{"8000:8100"}, []string(raw.PortRange))
	require.Equal(t, []string{"192.168.1.0/24"}, []string(raw.SourceIPCIDR))
	require.Equal(t, []string{"browser.exe"}, []string(raw.ProcessName))
	require.Equal(t, DNSMultiDirectTag, dnsRules[0].RouteOptions.Server)
}

func TestInvalidManualRulesFailWithoutBroadening(t *testing.T) {
	for _, r := range []Rule{
		{Enabled: true},
		{Enabled: true, Domains: []string{"x.invalid"}, IpCidrs: []string{"bad"}},
		{Enabled: true, Domains: []string{"x.invalid"}, PortRanges: []string{"100:2"}},
		{Enabled: true, Domains: []string{"x.invalid"}, Network: Network(99)},
	} {
		_, _, err := manualRouteRules(&HiddifyOptions{Rules: []Rule{r}})
		require.Error(t, err)
	}
}

func TestFinalLocalRulesetsReplaceGeneratedRemoteAndAlias(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "rules.srs")
	require.NoError(t, os.WriteFile(file, []byte("non-empty fixture; parser validates at core startup"), 0600))
	for _, full := range []bool{false, true} {
		h := DefaultHiddifyOptions()
		h.Region = "ir"
		h.BlockAds = true
		h.EnableFullConfig = full
		h.LocalRuleSets = map[string]string{"geoip-ir": file, "geosite-ir": file, "geosite-category-ads-all": file}
		got, err := BuildConfig(context.Background(), h, manualTestInput())
		require.NoError(t, err)
		found := 0
		for _, rs := range got.Route.RuleSet {
			if rs.Tag == "geoip-ir" || rs.Tag == "geosite-ir" || rs.Tag == "geosite-ads" {
				found++
				require.Equal(t, C.RuleSetTypeLocal, rs.Type)
				require.Equal(t, file, rs.LocalOptions.Path)
				require.Empty(t, rs.RemoteOptions.URL)
			}
		}
		require.Equal(t, 3, found)
	}
	h := DefaultHiddifyOptions()
	h.Region = "ir"
	h.LocalRuleSets = map[string]string{"geosite-ir": filepath.Join(dir, "missing.srs")}
	_, err := BuildConfig(context.Background(), h, manualTestInput())
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "geosite-ir"))
}
