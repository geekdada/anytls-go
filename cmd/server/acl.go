package main

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"anytls/acl"
	"anytls/resolver"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sirupsen/logrus"
)

var errACLRejected = errors.New("rejected by ACL")

// Mirrors hysteria's per-UDP-session ACL decision cache bound.
const maxSessionACLCache = 256

// outboundPolicy carries the per-request policy dependencies: the optional ACL
// engine and the optional custom DNS resolver. Either may be nil. A nil
// resolver means the system resolver which, as in hysteria, is only consulted
// when the ACL needs the destination IPs.
type outboundPolicy struct {
	acl      *acl.Engine
	resolver resolver.Resolver
}

func newOutboundPolicy(engine *acl.Engine, res resolver.Resolver) *outboundPolicy {
	return &outboundPolicy{acl: engine, resolver: res}
}

// active reports whether the policy has anything to enforce.
func (p *outboundPolicy) active() bool {
	return p != nil && (p.acl != nil || p.resolver != nil)
}

// hostInfo builds the host and addresses used for ACL matching and for picking
// the dial address. Domain destinations are resolved first so IP-based rules
// apply to them (hysteria puts a resolver in front of the ACL engine for the
// same reason).
//
// The third return value reports whether a resolution attempt actually ran, and
// so whether an empty result is fatal. No attempt is made for an IP literal, or
// when neither a resolver nor the ACL needs the addresses — in which case the
// dialer resolves at connect time, as hysteria's directOutbound does.
func (p *outboundPolicy) hostInfo(ctx context.Context, destination M.Socksaddr) (string, resolver.Result, bool) {
	if !destination.IsFqdn() {
		ip := net.IP(destination.Addr.AsSlice())
		if destination.IsIPv4() {
			return ip.String(), resolver.Result{IPv4: ip}, false
		}
		return ip.String(), resolver.Result{IPv6: ip}, false
	}
	if p.resolver != nil {
		return destination.Fqdn, p.resolver.Resolve(ctx, destination.Fqdn), true
	}
	if p.acl == nil {
		return destination.Fqdn, resolver.Result{}, false
	}
	return destination.Fqdn, systemResolve(ctx, destination.Fqdn), true
}

// systemResolve looks host up through net.DefaultResolver, keeping the first
// address of each family. This is the pre-resolver path, used when the ACL needs
// the destination IPs but no custom resolver is configured.
func systemResolve(ctx context.Context, host string) resolver.Result {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return resolver.Result{Err: err}
	}
	var result resolver.Result
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			if result.IPv4 == nil {
				result.IPv4 = ip4
			}
		} else if result.IPv6 == nil {
			result.IPv6 = ip
		}
	}
	return result
}

func ipToNetip(ip net.IP) netip.Addr {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// dialAddr applies the policy to one destination and returns the address to
// use: the hijack IP when the matched rule carries one, otherwise the resolved
// IP (so the connection goes to the IP that was matched), or the original
// destination when no resolution was attempted. It returns errACLRejected when a
// rule rejects the request, or a resolver.Error when resolution ran but yielded
// nothing.
//
// The order matters and mirrors hysteria's Resolver(ACL(outbound)) chain:
// resolution failure is not fatal until after the ACL has had its say, so
// name-based reject rules still fire on an unresolvable domain and a hijack rule
// can still redirect one.
func (p *outboundPolicy) dialAddr(ctx context.Context, destination M.Socksaddr, proto acl.Protocol) (M.Socksaddr, error) {
	host, result, attempted := p.hostInfo(ctx, destination)
	if p.acl != nil {
		action, hijack := p.acl.Lookup(host, result.IPv4, result.IPv6, proto, destination.Port)
		if action == acl.ActionReject {
			return M.Socksaddr{}, errACLRejected
		}
		if hijack != nil {
			return M.SocksaddrFrom(ipToNetip(hijack), destination.Port), nil
		}
	}
	switch {
	case result.IPv4 != nil:
		return M.SocksaddrFrom(ipToNetip(result.IPv4), destination.Port), nil
	case result.IPv6 != nil:
		return M.SocksaddrFrom(ipToNetip(result.IPv6), destination.Port), nil
	case attempted:
		// Resolution ran and produced nothing. Failing here is the point of
		// pinning DNS to a specific server: the request must not quietly fall
		// back to the dialer's own system lookup.
		return M.Socksaddr{}, resolver.Error{Err: result.Err}
	default:
		return destination, nil
	}
}

type policyDecision struct {
	rejected bool
	dest     M.Socksaddr
}

// policyPacketConn wraps a UDP socket with per-packet policy checks for
// udp-over-tcp: ACL matching and, when a custom resolver is configured,
// resolution of domain destinations. Rejected packets are dropped silently
// (mirroring hysteria, which ignores per-packet Feed errors), and so are packets
// whose destination cannot be resolved: returning an error here would tear down
// the whole stream inside bufio.CopyPacketConn, taking every other destination
// it multiplexes with it. Decisions are cached per destination for the life of
// the stream.
type policyPacketConn struct {
	N.PacketConn
	ctx    context.Context
	policy *outboundPolicy
	cache  map[string]policyDecision
}

func newPolicyPacketConn(ctx context.Context, conn N.PacketConn, p *outboundPolicy) N.PacketConn {
	return &policyPacketConn{
		PacketConn: conn,
		ctx:        ctx,
		policy:     p,
		cache:      make(map[string]policyDecision),
	}
}

func (c *policyPacketConn) decide(destination M.Socksaddr) policyDecision {
	dest, err := c.policy.dialAddr(c.ctx, destination, acl.ProtocolUDP)
	if err != nil {
		if !errors.Is(err, errACLRejected) {
			logrus.Debugln("policyPacketConn drop:", destination, err)
		}
		return policyDecision{rejected: true}
	}
	return policyDecision{dest: dest}
}

func (c *policyPacketConn) WritePacket(b *buf.Buffer, destination M.Socksaddr) error {
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
		// CopyPacketConn hands us ownership of the buffer on every call.
		b.Release()
		return nil
	}
	return c.PacketConn.WritePacket(b, d.dest)
}
