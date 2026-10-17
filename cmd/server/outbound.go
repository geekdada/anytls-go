package main

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"anytls/config"
	"anytls/outbound"

	"github.com/sirupsen/logrus"
)

// newOutbounds builds the named outbound map from the outbounds config. Only
// the built-in direct and socks5 types are supported; direct takes no options.
func newOutbounds(entries []config.OutboundEntry) (map[string]outbound.Outbound, error) {
	list := make([]namedOutbound, 0, len(entries))
	for _, entry := range entries {
		switch entry.Kind() {
		case "direct":
			list = append(list, namedOutbound{entry.Name, outbound.NewDirect()})
		case "socks5":
			socks5 := entry.SOCKS5
			list = append(list, namedOutbound{entry.Name, outbound.NewSOCKS5(socks5.Addr, socks5.Username, socks5.Password)})
		default:
			return nil, fmt.Errorf("outbound %q: unsupported type %q", entry.Name, entry.Type)
		}
	}
	return outboundMap(list, outbound.NewDirect()), nil
}

// warnLocalProxies warns about SOCKS5 proxies on a loopback or private
// address. The private filter only checks what the server resolved, and such a
// proxy resolves domains itself and can reach its own network.
func warnLocalProxies(entries []config.OutboundEntry) {
	for _, entry := range entries {
		if entry.Kind() == "socks5" && isLocalProxyAddr(entry.SOCKS5.Addr) {
			logrus.Warnf("[Outbound] %s: socks5 proxy %s is on a private address and resolves domains itself; restrict private destinations on the proxy", entry.Name, entry.SOCKS5.Addr)
		}
	}
}

// isLocalProxyAddr reports whether addr names localhost or a non-public IP.
// Other host names are not resolved, so they are never reported.
func isLocalProxyAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && isPrivateAddr(ip)
}

// namedOutbound pairs an outbound with its configured name.
type namedOutbound struct {
	name     string
	outbound outbound.Outbound
}

// outboundMap builds the name lookup ACL rules and the default fallback use.
// Names are lowercased because rules match them case-insensitively. The
// built-ins fill only names the user has not defined, and default is the first
// configured entry, so rules written for the built-in names keep working
// without an outbounds list.
func outboundMap(entries []namedOutbound, direct outbound.Outbound) map[string]outbound.Outbound {
	outbounds := make(map[string]outbound.Outbound, len(entries)+3)
	for _, entry := range entries {
		outbounds[strings.ToLower(entry.name)] = entry.outbound
	}
	if _, ok := outbounds["direct"]; !ok {
		outbounds["direct"] = direct
	}
	if _, ok := outbounds["reject"]; !ok {
		outbounds["reject"] = outbound.Reject{}
	}
	if _, ok := outbounds["default"]; !ok {
		if len(entries) > 0 {
			outbounds["default"] = entries[0].outbound
		} else {
			outbounds["default"] = outbounds["direct"]
		}
	}
	return outbounds
}
