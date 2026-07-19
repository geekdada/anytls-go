package acl

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"anytls/acl/v2geo"

	lru "github.com/hashicorp/golang-lru/v2"
)

type Protocol int

const (
	ProtocolBoth Protocol = iota
	ProtocolTCP
	ProtocolUDP
)

func (p Protocol) String() string {
	switch p {
	case ProtocolBoth:
		return "tcp+udp"
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	default:
		return fmt.Sprintf("Protocol(%d)", int(p))
	}
}

// Action is what a matched rule does with the request. anytls has no
// outbounds list, so Hysteria's built-in outbounds collapse to: "direct" and
// "default" forward to the system dialer, "reject" refuses the request.
type Action int

const (
	ActionDirect Action = iota
	ActionReject
)

func (a Action) String() string {
	switch a {
	case ActionDirect:
		return "direct"
	case ActionReject:
		return "reject"
	default:
		return fmt.Sprintf("Action(%d)", int(a))
	}
}

// outboundActions is the fixed set of rule targets, matching Hysteria's
// built-in outbounds when no outbounds list is configured.
var outboundActions = map[string]Action{
	"direct":  ActionDirect,
	"default": ActionDirect,
	"reject":  ActionReject,
}

type HostInfo struct {
	Name string
	IPv4 net.IP
	IPv6 net.IP
}

func (h HostInfo) String() string {
	return fmt.Sprintf("%s|%s|%s", h.Name, h.IPv4, h.IPv6)
}

type CompiledRuleSet interface {
	Match(host HostInfo, proto Protocol, port uint16) (Action, bool, net.IP)
}

type compiledRule struct {
	Action        Action
	HostMatcher   hostMatcher
	Protocol      Protocol
	StartPort     uint16
	EndPort       uint16
	HijackAddress net.IP
}

func (r *compiledRule) Match(host HostInfo, proto Protocol, port uint16) bool {
	if r.Protocol != ProtocolBoth && r.Protocol != proto {
		return false
	}
	if r.StartPort != 0 && (port < r.StartPort || port > r.EndPort) {
		return false
	}
	return r.HostMatcher.Match(host)
}

type matchResult struct {
	Action        Action
	Matched       bool
	HijackAddress net.IP
}

type compiledRuleSetImpl struct {
	Rules []compiledRule
	Cache *lru.Cache[matchResultCacheKey, matchResult]
}

type matchResultCacheKey struct {
	Host  string
	Proto Protocol
	Port  uint16
}

func (s *compiledRuleSetImpl) Match(host HostInfo, proto Protocol, port uint16) (Action, bool, net.IP) {
	host.Name = strings.TrimRight(strings.ToLower(host.Name), ".") // Normalize host name (lower case, no trailing dots)
	key := matchResultCacheKey{
		Host:  host.String(),
		Proto: proto,
		Port:  port,
	}
	if result, ok := s.Cache.Get(key); ok {
		return result.Action, result.Matched, result.HijackAddress
	}
	for _, rule := range s.Rules {
		if rule.Match(host, proto, port) {
			result := matchResult{rule.Action, true, rule.HijackAddress}
			s.Cache.Add(key, result)
			return result.Action, result.Matched, result.HijackAddress
		}
	}
	// No match should also be cached
	s.Cache.Add(key, matchResult{})
	return ActionDirect, false, nil
}

type CompilationError struct {
	LineNum int
	Message string
}

func (e *CompilationError) Error() string {
	return fmt.Sprintf("error at line %d: %s", e.LineNum, e.Message)
}

type GeoLoader interface {
	LoadGeoIP() (map[string]*v2geo.GeoIP, error)
	LoadGeoSite() (map[string]*v2geo.GeoSite, error)
}

// Compile compiles TextRules into a CompiledRuleSet.
// We want on-demand loading of GeoIP/GeoSite databases, so instead of passing the
// databases directly, we use a GeoLoader interface to load them only when needed
// by at least one rule.
func Compile(rules []TextRule, cacheSize int, geoLoader GeoLoader) (CompiledRuleSet, error) {
	compiledRules := make([]compiledRule, len(rules))
	for i, rule := range rules {
		action, ok := outboundActions[strings.ToLower(rule.Outbound)]
		if !ok {
			return nil, &CompilationError{rule.LineNum, fmt.Sprintf("outbound %s not found (anytls ACL supports only direct/reject/default)", rule.Outbound)}
		}
		hm, errStr := compileHostMatcher(rule.Address, geoLoader)
		if errStr != "" {
			return nil, &CompilationError{rule.LineNum, errStr}
		}
		proto, startPort, endPort, ok := parseProtoPort(rule.ProtoPort)
		if !ok {
			return nil, &CompilationError{rule.LineNum, fmt.Sprintf("invalid protocol/port: %s", rule.ProtoPort)}
		}
		var hijackAddress net.IP
		if rule.HijackAddress != "" {
			hijackAddress = net.ParseIP(rule.HijackAddress)
			if hijackAddress == nil {
				return nil, &CompilationError{rule.LineNum, fmt.Sprintf("invalid hijack address (must be an IP address): %s", rule.HijackAddress)}
			}
		}
		compiledRules[i] = compiledRule{action, hm, proto, startPort, endPort, hijackAddress}
	}
	cache, err := lru.New[matchResultCacheKey, matchResult](cacheSize)
	if err != nil {
		return nil, err
	}
	return &compiledRuleSetImpl{compiledRules, cache}, nil
}

// parseProtoPort parses the protocol and port from a protoPort string.
// protoPort must be in one of the following formats:
//
//	proto/port
//	proto/*
//	proto
//	*/port
//	*/*
//	*
//	[empty] (same as *)
//
// proto must be either "tcp" or "udp", case-insensitive.
func parseProtoPort(protoPort string) (Protocol, uint16, uint16, bool) {
	protoPort = strings.ToLower(protoPort)
	if protoPort == "" || protoPort == "*" || protoPort == "*/*" {
		return ProtocolBoth, 0, 0, true
	}
	parts := strings.SplitN(protoPort, "/", 2)
	if len(parts) == 1 {
		// No port, only protocol
		switch parts[0] {
		case "tcp":
			return ProtocolTCP, 0, 0, true
		case "udp":
			return ProtocolUDP, 0, 0, true
		default:
			return ProtocolBoth, 0, 0, false
		}
	} else {
		// Both protocol and port
		var proto Protocol
		var startPort, endPort uint16
		switch parts[0] {
		case "tcp":
			proto = ProtocolTCP
		case "udp":
			proto = ProtocolUDP
		case "*":
			proto = ProtocolBoth
		default:
			return ProtocolBoth, 0, 0, false
		}
		if parts[1] != "*" {
			// We allow either a single port or a range (e.g. "1000-2000")
			ports := strings.SplitN(strings.TrimSpace(parts[1]), "-", 2)
			if len(ports) == 1 {
				p64, err := strconv.ParseUint(parts[1], 10, 16)
				if err != nil {
					return ProtocolBoth, 0, 0, false
				}
				startPort = uint16(p64)
				endPort = startPort
			} else {
				p64, err := strconv.ParseUint(ports[0], 10, 16)
				if err != nil {
					return ProtocolBoth, 0, 0, false
				}
				startPort = uint16(p64)
				p64, err = strconv.ParseUint(ports[1], 10, 16)
				if err != nil {
					return ProtocolBoth, 0, 0, false
				}
				endPort = uint16(p64)
				if startPort > endPort {
					return ProtocolBoth, 0, 0, false
				}
			}
		}
		return proto, startPort, endPort, true
	}
}

func compileHostMatcher(addr string, geoLoader GeoLoader) (hostMatcher, string) {
	addr = strings.TrimRight(strings.ToLower(addr), ".") // Normalize host pattern (lower case, no trailing dots)
	if addr == "*" || addr == "all" {
		// Match all hosts
		return &allMatcher{}, ""
	}
	if strings.HasPrefix(addr, "geoip:") {
		// GeoIP matcher
		country := addr[6:]
		if len(country) == 0 {
			return nil, "empty GeoIP country code"
		}
		gMap, err := geoLoader.LoadGeoIP()
		if err != nil {
			return nil, err.Error()
		}
		list, ok := gMap[country]
		if !ok || list == nil {
			return nil, fmt.Sprintf("GeoIP country code %s not found", country)
		}
		m, err := newGeoIPMatcher(list)
		if err != nil {
			return nil, err.Error()
		}
		return m, ""
	}
	if strings.HasPrefix(addr, "geosite:") {
		// GeoSite matcher
		name, attrs := parseGeoSiteName(addr[8:])
		if len(name) == 0 {
			return nil, "empty GeoSite name"
		}
		gMap, err := geoLoader.LoadGeoSite()
		if err != nil {
			return nil, err.Error()
		}
		list, ok := gMap[name]
		if !ok || list == nil {
			return nil, fmt.Sprintf("GeoSite name %s not found", name)
		}
		m, err := newGeositeMatcher(list, attrs)
		if err != nil {
			return nil, err.Error()
		}
		return m, ""
	}
	if strings.HasPrefix(addr, "suffix:") {
		// Domain suffix matcher
		suffix := addr[7:]
		if len(suffix) == 0 {
			return nil, "empty domain suffix"
		}
		return &domainMatcher{
			Pattern: suffix,
			Mode:    domainMatchSuffix,
		}, ""
	}
	if strings.Contains(addr, "/") {
		// CIDR matcher
		_, ipnet, err := net.ParseCIDR(addr)
		if err != nil {
			return nil, fmt.Sprintf("invalid CIDR address: %s", addr)
		}
		return &cidrMatcher{ipnet}, ""
	}
	if ip := net.ParseIP(addr); ip != nil {
		// Single IP matcher
		return &ipMatcher{ip}, ""
	}
	if strings.Contains(addr, "*") {
		// Wildcard domain matcher
		return &domainMatcher{
			Pattern: addr,
			Mode:    domainMatchWildcard,
		}, ""
	}
	// Nothing else matched, treat it as a non-wildcard domain
	return &domainMatcher{
		Pattern: addr,
		Mode:    domainMatchExact,
	}, ""
}

func parseGeoSiteName(s string) (string, []string) {
	parts := strings.Split(s, "@")
	base := strings.TrimSpace(parts[0])
	attrs := parts[1:]
	for i := range attrs {
		attrs[i] = strings.TrimSpace(attrs[i])
	}
	return base, attrs
}
