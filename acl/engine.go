package acl

import (
	"net"
	"os"
)

const (
	aclCacheSize = 1024
)

// Engine dispatches anytls server requests through the compiled rule set.
// Without an outbounds list, a no-match falls through to "default", which is
// equal to direct here (mirroring Hysteria with an empty outbounds list).
type Engine struct {
	RuleSet CompiledRuleSet
}

func NewEngineFromString(rules string, geoLoader GeoLoader) (*Engine, error) {
	trs, err := ParseTextRules(rules)
	if err != nil {
		return nil, err
	}
	rs, err := Compile(trs, aclCacheSize, geoLoader)
	if err != nil {
		return nil, err
	}
	return &Engine{rs}, nil
}

func NewEngineFromFile(filename string, geoLoader GeoLoader) (*Engine, error) {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return NewEngineFromString(string(bs), geoLoader)
}

// Lookup resolves the ACL decision for one request. It returns the action to
// take and, when the matched rule carries one, the hijack address. The
// returned port is always the request port; rewriting the address to a
// hijack IP keeps it.
func (e *Engine) Lookup(host string, ipv4, ipv6 net.IP, proto Protocol, port uint16) (Action, net.IP) {
	action, _, hijack := e.RuleSet.Match(HostInfo{Name: host, IPv4: ipv4, IPv6: ipv6}, proto, port)
	return action, hijack
}
