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
	// The country's own IP set, supplied by the app because the list is an app
	// asset. See windowsDomesticPrefixes for why a DIRECT rule is not enough.
	DomesticPrefixes []string `json:"domestic-prefixes,omitempty"`
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
	excluded = append(excluded, windowsDomesticPrefixes(options.Route.Rules, runtime.DomesticPrefixes)...)
	if options.DNS != nil && len(runtime.DirectDNS) > 0 {
		var tags []string
		var servers []option.DNSServerOptions
		for i, address := range runtime.DirectDNS {
			ip, err := netip.ParseAddr(address)
			if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || netip.MustParsePrefix("198.18.0.0/15").Contains(ip) {
				return fmt.Errorf("invalid Windows direct DNS address")
			}
			// DHCP/local resolvers often accept UDP/53 without accepting TCP.
			// Keep TCP as an alternative, not a prerequisite for all DIRECT DNS.
			for _, protocol := range []string{"udp", "tcp"} {
				tag := fmt.Sprintf("dm-windows-direct-%d-%s", i, protocol)
				tags = append(tags, tag)
				server, err := getDNSServerOptions(tag, protocol+"://"+ip.String(), "", "")
				if err != nil {
					return err
				}
				remote := server.Options.(*option.RemoteDNSServerOptions)
				remote.BindInterface = runtime.Interface
				remote.ConnectTimeout = badoption.Duration(5 * time.Second)
				servers = append(servers, *server)
			}
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

// The country's own IP set, taken off the tunnel entirely.
//
// 🔑 A DIRECT rule cannot move a packet on Windows. Android exempts the socket
// with VpnService.protect(); Windows has no equivalent, so the direct dial is
// bound to the physical NIC while the route table still hands its packets to
// the TUN, and the core meets its own traffic arriving back. Measured on
// 1.9.6: mihomo, which detects that loop, rejected 8,205 of its own direct
// connections in one session; sing-box has no such detector and simply times
// out. Only a route exclusion takes the address off the tunnel.
//
// The list is an app asset, so it arrives as runtime input rather than being
// read here. Two guards keep that honest:
//
//   - the final rules must actually send this country's IP set direct, so an
//     exclusion can never outlive the decision that justified it;
//   - a prefix an earlier non-direct rule claims BY ADDRESS is left alone. That
//     rule names the same kind of thing an exclusion removes, so it still wins
//     (the built-in censorship sinkhole is the case that matters).
//
// ⚠️ What this gives up: an ad or malware domain hosted on a domestic address
// is no longer filtered, because its packets leave before the rule engine sees
// them. Foreign ad networks are unaffected - they are not in the country set.
func windowsDomesticPrefixes(rules []option.Rule, values []string) []netip.Prefix {
	if len(values) == 0 {
		return nil
	}
	var claimed []netip.Prefix
	var countryIsDirect bool
	for _, rule := range rules {
		data, err := json.Marshal(rule)
		if err != nil {
			return nil
		}
		var value map[string]any
		if json.Unmarshal(data, &value) != nil {
			return nil
		}
		switch action, _ := value["action"].(string); action {
		case C.RuleActionTypeSniff, C.RuleActionTypeHijackDNS, C.RuleActionTypeResolve:
			continue
		}
		if isWindowsDirect(value) {
			for _, tag := range jsonStrings(value["rule_set"]) {
				if strings.HasPrefix(tag, "geoip-") {
					countryIsDirect = true
				}
			}
			continue
		}
		for _, raw := range jsonStrings(value["ip_cidr"]) {
			if prefix, err := netip.ParsePrefix(raw); err == nil {
				claimed = append(claimed, prefix.Masked())
			}
		}
	}
	if !countryIsDirect {
		return nil
	}
	var result []netip.Prefix
	for _, raw := range values {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 {
			continue
		}
		prefix = prefix.Masked()
		overlapped := false
		for _, owner := range claimed {
			if owner.Overlaps(prefix) {
				overlapped = true
				break
			}
		}
		if !overlapped {
			result = append(result, prefix)
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
