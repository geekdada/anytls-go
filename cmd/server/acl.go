package main

import (
	"errors"
	"net"
	"net/netip"

	"anytls/acl"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var errACLRejected = errors.New("rejected by ACL")

// Mirrors hysteria's per-UDP-session ACL decision cache bound.
const maxSessionACLCache = 256

// aclHostInfo builds the (host, ipv4, ipv6) tuple used for matching. Domain
// destinations are resolved so IP-based rules apply to them (hysteria puts a
// resolver in front of the ACL engine for the same reason). A resolution
// failure yields nil IPs, and matching falls back to the domain name alone.
func aclHostInfo(destination M.Socksaddr) (string, net.IP, net.IP) {
	if !destination.IsFqdn() {
		ip := net.IP(destination.Addr.AsSlice())
		if destination.IsIPv4() {
			return ip.String(), ip, nil
		}
		return ip.String(), nil, ip
	}
	ipv4, ipv6 := aclResolve(destination.Fqdn)
	return destination.Fqdn, ipv4, ipv6
}

func aclResolve(host string) (net.IP, net.IP) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, nil
	}
	var ipv4, ipv6 net.IP
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			if ipv4 == nil {
				ipv4 = ip4
			}
		} else if ipv6 == nil {
			ipv6 = ip
		}
	}
	return ipv4, ipv6
}

func ipToNetip(ip net.IP) netip.Addr {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// aclTCPDialAddr applies the ACL to a TCP stream destination. It returns the
// address to dial: the hijack IP when the matched rule carries one, otherwise
// the resolved IP (so the connection goes to the IP that was matched), or the
// original destination. The second return value is false when the request is
// rejected.
func aclTCPDialAddr(engine *acl.Engine, destination M.Socksaddr) (M.Socksaddr, bool) {
	host, ipv4, ipv6 := aclHostInfo(destination)
	action, hijack := engine.Lookup(host, ipv4, ipv6, acl.ProtocolTCP, destination.Port)
	if action == acl.ActionReject {
		return M.Socksaddr{}, false
	}
	if hijack != nil {
		return M.SocksaddrFrom(ipToNetip(hijack), destination.Port), true
	}
	if ipv4 != nil {
		return M.SocksaddrFrom(ipToNetip(ipv4), destination.Port), true
	}
	if ipv6 != nil {
		return M.SocksaddrFrom(ipToNetip(ipv6), destination.Port), true
	}
	return destination, true
}

type aclUDPPacketDecision struct {
	rejected bool
	dest     M.Socksaddr
}

// aclPacketConn wraps a UDP socket with per-packet ACL checks for
// udp-over-tcp. Rejected packets are dropped silently (mirroring hysteria,
// which ignores per-packet Feed errors); decisions are cached per destination
// for the life of the stream.
type aclPacketConn struct {
	N.PacketConn
	engine *acl.Engine
	cache  map[string]aclUDPPacketDecision
}

func newACLPacketConn(conn N.PacketConn, engine *acl.Engine) N.PacketConn {
	return &aclPacketConn{
		PacketConn: conn,
		engine:     engine,
		cache:      make(map[string]aclUDPPacketDecision),
	}
}

func (c *aclPacketConn) decide(destination M.Socksaddr) aclUDPPacketDecision {
	host, ipv4, ipv6 := aclHostInfo(destination)
	action, hijack := c.engine.Lookup(host, ipv4, ipv6, acl.ProtocolUDP, destination.Port)
	if action == acl.ActionReject {
		return aclUDPPacketDecision{rejected: true}
	}
	if hijack != nil {
		return aclUDPPacketDecision{dest: M.SocksaddrFrom(ipToNetip(hijack), destination.Port)}
	}
	if ipv4 != nil {
		return aclUDPPacketDecision{dest: M.SocksaddrFrom(ipToNetip(ipv4), destination.Port)}
	}
	if ipv6 != nil {
		return aclUDPPacketDecision{dest: M.SocksaddrFrom(ipToNetip(ipv6), destination.Port)}
	}
	return aclUDPPacketDecision{dest: destination}
}

func (c *aclPacketConn) WritePacket(b *buf.Buffer, destination M.Socksaddr) error {
	key := destination.String()
	d, ok := c.cache[key]
	if !ok {
		d = c.decide(destination)
		if len(c.cache) >= maxSessionACLCache {
			for k := range c.cache {
				delete(c.cache, k)
				break
			}
		}
		c.cache[key] = d
	}
	if d.rejected {
		return nil
	}
	return c.PacketConn.WritePacket(b, d.dest)
}
