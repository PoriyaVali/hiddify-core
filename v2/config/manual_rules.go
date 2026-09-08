package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Flutter sends ProtoJSON (enum names and singular json_name fields) inside
// route-rule. encoding/json on generated Go messages silently loses those
// fields, or rejects the enum names. Keep the older top-level rules compatible.
func (h *HiddifyOptions) UnmarshalJSON(data []byte) error {
	type plain HiddifyOptions
	wire := struct {
		*plain
		RouteRule json.RawMessage `json:"route-rule"`
		Rules     json.RawMessage `json:"rules"`
	}{plain: (*plain)(h)}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	raw := wire.RouteRule
	if len(raw) == 0 && len(wire.Rules) != 0 {
		raw = append(append([]byte(`{"rules":`), wire.Rules...), '}')
	}
	if len(raw) == 0 {
		return nil
	}
	if string(raw) == "null" {
		h.Rules = nil
		return nil
	}
	var wrapper RouteRule
	if err := protojson.Unmarshal(raw, &wrapper); err != nil {
		return fmt.Errorf("route-rule: %w", err)
	}
	h.Rules = make([]Rule, len(wrapper.Rules))
	for i, rule := range wrapper.Rules {
		proto.Merge(&h.Rules[i], rule)
	}
	return nil
}

func manualRouteRules(h *HiddifyOptions) ([]option.Rule, []option.DefaultDNSRule, error) {
	ordered := make([]*Rule, 0, len(h.Rules))
	for i := range h.Rules {
		if h.Rules[i].Enabled {
			ordered = append(ordered, &h.Rules[i])
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].ListOrder < ordered[j].ListOrder })
	var routes []option.Rule
	var dnsRules []option.DefaultDNSRule
	for _, rule := range ordered {
		raw := option.RawDefaultRule{
			Domain: rule.Domains, DomainSuffix: rule.DomainSuffixes,
			DomainKeyword: rule.DomainKeywords, DomainRegex: rule.DomainRegexes,
			PackageName: rule.PackageNames, ProcessName: rule.ProcessNames,
			ProcessPath: rule.ProcessPaths, RuleSet: rule.RuleSets,
		}
		var err error
		if raw.IPCIDR, err = manualPrefixes(rule.IpCidrs); err != nil {
			return nil, nil, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
		if raw.SourceIPCIDR, err = manualPrefixes(rule.SourceIpCidrs); err != nil {
			return nil, nil, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
		if raw.Port, raw.PortRange, err = manualPorts(rule.PortRanges); err != nil {
			return nil, nil, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
		if raw.SourcePort, raw.SourcePortRange, err = manualPorts(rule.SourcePortRanges); err != nil {
			return nil, nil, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
		for _, expr := range raw.DomainRegex {
			if _, err = regexp.Compile(expr); err != nil {
				return nil, nil, fmt.Errorf("rule %q: %w", rule.Name, err)
			}
		}
		switch rule.Network {
		case Network_all:
		case Network_tcp, Network_udp:
			raw.Network = []string{rule.Network.String()}
		default:
			return nil, nil, fmt.Errorf("rule %q: unknown network", rule.Name)
		}
		for _, protocol := range rule.Protocols {
			if _, ok := Protocol_name[int32(protocol)]; !ok {
				return nil, nil, fmt.Errorf("rule %q: unknown protocol", rule.Name)
			}
			raw.Protocol = append(raw.Protocol, protocol.String())
		}
		if reflect.DeepEqual(raw, option.RawDefaultRule{}) {
			return nil, nil, fmt.Errorf("rule %q has no conditions", rule.Name)
		}
		action := option.RuleAction{Action: C.RuleActionTypeRoute}
		server := DNSMultiDirectTag
		switch rule.Outbound {
		case Outbound_direct:
			action.RouteOptions.Outbound = OutboundDirectTag
		case Outbound_direct_with_fragment:
			action.RouteOptions.Outbound = OutboundDirectFragmentTag
		case Outbound_proxy:
			action.RouteOptions.Outbound = OutboundMainDetour
			server = DNSMultiRemoteTag
		case Outbound_block:
			action.Action = C.RuleActionTypeReject
		default:
			return nil, nil, fmt.Errorf("rule %q: unknown outbound", rule.Name)
		}
		routes = append(routes, option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RawDefaultRule: raw, RuleAction: action}})
		// DNS requests do not have the destination connection's port/protocol/
		// network. Never broaden a constrained traffic rule into a domain-only
		// DNS rule. Route matching still preserves every original constraint.
		if len(raw.Port)+len(raw.PortRange)+len(raw.SourcePort)+len(raw.SourcePortRange)+len(raw.Network)+len(raw.Protocol)+len(raw.IPCIDR) != 0 {
			continue
		}
		dnsRaw := option.RawDefaultDNSRule{
			Domain: raw.Domain, DomainSuffix: raw.DomainSuffix,
			DomainKeyword: raw.DomainKeyword, DomainRegex: raw.DomainRegex,
			SourceIPCIDR: raw.SourceIPCIDR, PackageName: raw.PackageName,
			ProcessName: raw.ProcessName, ProcessPath: raw.ProcessPath, RuleSet: raw.RuleSet,
		}
		dnsAction := option.DNSRuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.DNSRouteActionOptions{Server: server}}
		if rule.Outbound == Outbound_block {
			dnsAction = option.DNSRuleAction{Action: C.RuleActionTypeReject}
		}
		dnsRules = append(dnsRules, option.DefaultDNSRule{RawDefaultDNSRule: dnsRaw, DNSRuleAction: dnsAction})
	}
	return routes, dnsRules, nil
}

func manualPrefixes(values []string) ([]string, error) {
	var result []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if ip, err := netip.ParseAddr(value); err == nil {
			result = append(result, netip.PrefixFrom(ip, ip.BitLen()).String())
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid IP/CIDR %q", value)
		}
		result = append(result, prefix.Masked().String())
	}
	return result, nil
}

func manualPorts(values []string) ([]uint16, []string, error) {
	var ports []uint16
	var ranges []string
	for _, value := range values {
		value = strings.ReplaceAll(strings.TrimSpace(value), "-", ":")
		parts := strings.Split(value, ":")
		if len(parts) < 1 || len(parts) > 2 {
			return nil, nil, fmt.Errorf("invalid port range %q", value)
		}
		numbers := make([]uint64, len(parts))
		for i, part := range parts {
			n, err := strconv.ParseUint(part, 10, 16)
			if err != nil || n == 0 {
				return nil, nil, fmt.Errorf("invalid port range %q", value)
			}
			numbers[i] = n
		}
		if len(parts) == 1 {
			ports = append(ports, uint16(numbers[0]))
		} else {
			if numbers[0] > numbers[1] {
				return nil, nil, fmt.Errorf("reversed port range %q", value)
			}
			ranges = append(ranges, fmt.Sprintf("%d:%d", numbers[0], numbers[1]))
		}
	}
	return ports, ranges, nil
}

// Runtime local assets are authoritative. A missing supplied asset is a clear
// startup error, never an empty remote set silently disabling bypass/blocking.
func applyLocalRuleSets(options *option.Options, paths map[string]string) error {
	if options.Route == nil {
		return nil
	}
	known := make(map[string]bool)
	for _, rs := range options.Route.RuleSet {
		known[rs.Tag] = true
	}
	for _, rule := range options.Route.Rules {
		for _, tag := range rule.DefaultOptions.RuleSet {
			if known[tag] {
				continue
			}
			rs := option.RuleSet{Tag: tag, Format: C.RuleSetFormatBinary}
			if _, ok := paths[tag]; ok {
				rs.Type = C.RuleSetTypeLocal
			} else {
				u, err := url.Parse(tag)
				if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
					return fmt.Errorf("unknown manual rule-set %q: supply a local asset or HTTP(S) URL", tag)
				}
				rs.Type = C.RuleSetTypeRemote
				if strings.HasSuffix(u.Path, ".json") {
					rs.Format = C.RuleSetFormatSource
				}
				rs.RemoteOptions = option.RemoteRuleSet{URL: tag, DownloadDetour: OutboundSelectTag, UpdateInterval: badoption.Duration(24 * time.Hour)}
			}
			options.Route.RuleSet = append(options.Route.RuleSet, rs)
			known[tag] = true
		}
	}
	for i := range options.Route.RuleSet {
		rs := &options.Route.RuleSet[i]
		path, found := paths[rs.Tag]
		if !found && rs.Tag == "geosite-ads" {
			path, found = paths["geosite-category-ads-all"]
		}
		if !found {
			continue
		}
		if !filepath.IsAbs(path) {
			return fmt.Errorf("local rule-set %q path is not absolute", rs.Tag)
		}
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("local rule-set %q: %w", rs.Tag, err)
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("local rule-set %q is empty or not a file", rs.Tag)
		}
		*rs = option.RuleSet{Type: C.RuleSetTypeLocal, Tag: rs.Tag, Format: C.RuleSetFormatBinary, LocalOptions: option.LocalRuleSet{Path: path}}
	}
	return nil
}
