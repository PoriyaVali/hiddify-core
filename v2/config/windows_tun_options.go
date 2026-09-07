package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

type WindowsTUNOptions struct {
	Interface string   `json:"interface,omitempty"`
	DirectDNS []string `json:"direct-dns,omitempty"`
}

// Called only on Windows after the ordinary builder has produced the FINAL
// route/DNS rules. Patching the subscription before BuildConfig loses these
// fields, since that builder creates its own TUN and built-in direct outbounds.
func applyWindowsTUNOptions(options *option.Options, runtime WindowsTUNOptions) error {
	if runtime.Interface == "" || options.Route == nil {
		return nil // Older clients retain their existing configuration.
	}
	options.Route.DefaultInterface = runtime.Interface
	options.Route.AutoDetectInterface = false

	excluded := windowsSafeDirectPrefixes(options.Route.Rules)
	if options.DNS != nil && len(runtime.DirectDNS) > 0 {
		var tags []string
		var servers []option.DNSServerOptions
		for i, address := range runtime.DirectDNS {
			ip, err := netip.ParseAddr(address)
			if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || netip.MustParsePrefix("198.18.0.0/15").Contains(ip) {
				return fmt.Errorf("invalid Windows direct DNS address")
			}
			tag := fmt.Sprintf("dm-windows-direct-%d", i)
			tags = append(tags, tag)
			server, err := getDNSServerOptions(tag, "tcp://"+ip.String(), "", "")
			if err != nil {
				return err
			}
			remote := server.Options.(*option.RemoteDNSServerOptions)
			remote.BindInterface = runtime.Interface
			remote.ConnectTimeout = badoption.Duration(5 * time.Second)
			servers = append(servers, *server)
			excluded = append(excluded, netip.PrefixFrom(ip, 32))
		}
		// Keep the tag every existing DNS rule references, but try the local
		// country pool in parallel. Never send this fallback through a proxy.
		for i := range options.DNS.Servers {
			if options.DNS.Servers[i].Tag == DNSDirectTag {
				options.DNS.Servers[i] = option.DNSServerOptions{
					Tag: DNSDirectTag, Type: C.DNSTypeMulti,
					Options: &option.MultiDNSServerOptions{
						Servers: tags, Parallel: true,
						IgnoreRanges: []badoption.Prefix{
							badoption.Prefix(netip.MustParsePrefix("198.18.0.0/15")),
							badoption.Prefix(netip.MustParsePrefix("10.10.34.0/24")),
						},
					},
				}
			}
		}
		options.DNS.Servers = append(options.DNS.Servers, servers...)
	}
	for i := range options.Inbounds {
		if tun, ok := options.Inbounds[i].Options.(*option.TunInboundOptions); ok {
			seen := make(map[netip.Prefix]bool)
			for _, prefix := range append(tun.RouteExcludeAddress, excluded...) {
				seen[prefix.Masked()] = true
			}
			tun.RouteExcludeAddress = nil
			for prefix := range seen {
				tun.RouteExcludeAddress = append(tun.RouteExcludeAddress, prefix)
			}
			sort.Slice(tun.RouteExcludeAddress, func(i, j int) bool {
				return tun.RouteExcludeAddress[i].String() < tun.RouteExcludeAddress[j].String()
			})
			// StrictRoute is deliberately untouched: OS bypass is not permission
			// for ordinary applications' DNS to escape the existing WFP guard.
		}
	}
	return nil
}

// A route exclusion bypasses the rule engine, so it is safe only when an
// unconditional IP-DIRECT rule wins for the WHOLE prefix. Earlier domain,
// process, port, logical, reject or proxy rules remain authoritative. Unknown
// predicates fail closed (no exclusion), never silently broaden DIRECT.
func windowsSafeDirectPrefixes(rules []option.Rule) []netip.Prefix {
	var candidates []netip.Prefix
	var decoded []map[string]any
	for _, rule := range rules {
		data, err := json.Marshal(rule)
		if err != nil {
			return nil
		}
		var value map[string]any
		if json.Unmarshal(data, &value) != nil {
			return nil
		}
		decoded = append(decoded, value)
		if isWindowsPlainDirect(value) {
			for _, raw := range jsonStrings(value["ip_cidr"]) {
				if p, err := netip.ParsePrefix(raw); err == nil && p.Addr().Is4() && p.Bits() > 0 {
					candidates = append(candidates, p.Masked())
				}
			}
		}
	}
	var result []netip.Prefix
	for _, candidate := range candidates {
		for _, rule := range decoded {
			action, _ := rule["action"].(string)
			if action == C.RuleActionTypeSniff || action == C.RuleActionTypeHijackDNS || action == C.RuleActionTypeResolve {
				continue
			}
			if isWindowsPlainDirect(rule) {
				matches := false
				for _, raw := range jsonStrings(rule["ip_cidr"]) {
					p, err := netip.ParsePrefix(raw)
					matches = matches || (err == nil && p.Bits() <= candidate.Bits() && p.Contains(candidate.Addr()))
				}
				if matches {
					result = append(result, candidate)
					break
				}
				continue
			}
			if isWindowsDirect(rule) {
				continue
			}
			// An earlier proxy rule restricted to disjoint IP ranges cannot
			// override this candidate (e.g. the built-in censorship sinkhole).
			if windowsDisjointIPRule(rule, candidate) {
				continue
			}
			break
		}
	}
	return result
}

func isWindowsDirect(rule map[string]any) bool {
	outbound, _ := rule["outbound"].(string)
	return outbound == OutboundDirectTag
}

func isWindowsPlainDirect(rule map[string]any) bool {
	if !isWindowsDirect(rule) {
		return false
	}
	for key := range rule {
		switch key {
		case "ip_cidr", "action", "outbound":
		default:
			return false
		}
	}
	return true
}

func windowsDisjointIPRule(rule map[string]any, candidate netip.Prefix) bool {
	for key := range rule {
		if key != "ip_cidr" && key != "action" && key != "outbound" {
			return false
		}
	}
	ips := jsonStrings(rule["ip_cidr"])
	if len(ips) == 0 {
		return false
	}
	for _, raw := range ips {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p.Overlaps(candidate) {
			return false
		}
	}
	return true
}

func jsonStrings(value any) []string {
	if text, ok := value.(string); ok {
		return []string{text}
	}
	var result []string
	if list, ok := value.([]any); ok {
		for _, value := range list {
			if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
				result = append(result, text)
			}
		}
	}
	return result
}
