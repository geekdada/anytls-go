package acl

import (
	"errors"
	"net"
	"os"
)

const (
	aclCacheSize = 1024
)

// Engine dispatches requests through the compiled rule set. A request that
// matches no rule falls through to Default, which the caller sets from its
// "default" outbound, mirroring hysteria.
type Engine[O any] struct {
	RuleSet CompiledRuleSet[O]
	Default O
}

// NewEngineFromString fails without a non-nil "default" outbound. A nil
// Default would only surface as a panic on the first unmatched request, and on
// the UoT path that panic runs in a goroutine with no recover.
func NewEngineFromString[O any](rules string, outbounds map[string]O, geoLoader GeoLoader) (*Engine[O], error) {
	if ob, ok := outbounds["default"]; !ok || any(ob) == nil {
		return nil, errors.New(`acl: no "default" outbound`)
	}
	trs, err := ParseTextRules(rules)
	if err != nil {
		return nil, err
	}
	rs, err := Compile(trs, outbounds, aclCacheSize, geoLoader)
	if err != nil {
		return nil, err
	}
	return &Engine[O]{RuleSet: rs, Default: outbounds["default"]}, nil
}

func NewEngineFromFile[O any](filename string, outbounds map[string]O, geoLoader GeoLoader) (*Engine[O], error) {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return NewEngineFromString(string(bs), outbounds, geoLoader)
}

// Lookup resolves the ACL decision for one request. It returns the outbound
// selected for the request and, when the matched rule carries one, the hijack
// address. The returned port is always the request port; rewriting the address
// to a hijack IP keeps it. Default applies when no rule matches.
func (e *Engine[O]) Lookup(host string, ipv4, ipv6 net.IP, proto Protocol, port uint16) (O, net.IP) {
	ob, matched, hijack := e.RuleSet.Match(HostInfo{Name: host, IPv4: ipv4, IPv6: ipv6}, proto, port)
	if !matched {
		ob = e.Default
	}
	return ob, hijack
}
