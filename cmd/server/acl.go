package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"anytls/acl"
	"anytls/outbound"
	"anytls/resolver"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sirupsen/logrus"
)

var (
	errACLRejected        = outbound.ErrRejected
	errPrivateDestination = errors.New("private destination not allowed")
)

// Mirrors hysteria's per-UDP-session ACL decision cache bound.
const maxSessionACLCache = 256

// outboundPolicy carries the per-request policy dependencies: the optional ACL
// engine, the optional custom DNS resolver, the private-destination filter and
// the outbound used when no rule matches. A nil resolver means the system
// resolver which, as in hysteria, is only consulted when the ACL or the private
// filter needs the destination IPs.
type outboundPolicy struct {
	acl          *acl.Engine[outbound.Outbound]
	resolver     resolver.Resolver
	blockPrivate bool
	fallback     outbound.Outbound
}

func newOutboundPolicy(engine *acl.Engine[outbound.Outbound], res resolver.Resolver, blockPrivate bool, fallback outbound.Outbound) *outboundPolicy {
	if fallback == nil {
		fallback = outbound.NewDirect()
	}
	return &outboundPolicy{acl: engine, resolver: res, blockPrivate: blockPrivate, fallback: fallback}
}

// route is one policy decision: the outbound to use and the address to hand it.
type route struct {
	outbound outbound.Outbound
	target   M.Socksaddr
}

// hostInfo builds the host and addresses used for ACL matching and for picking
// the dial address. Domain destinations are resolved first so IP-based rules
// apply to them (hysteria puts a resolver in front of the ACL engine for the
// same reason).
//
// The third return value reports whether a resolution attempt actually ran, and
// so whether an empty result is fatal. No attempt is made for an IP literal, or
// when no resolver is set and neither the ACL nor the private filter needs the
// addresses; in that case the chosen outbound resolves the name itself, as
// hysteria's outbounds do.
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
	if p.acl == nil && !p.blockPrivate {
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

// selectRoute applies the policy to one destination and returns the outbound to
// use and the address to give it: the hijack IP when the matched rule carries
// one, the resolved IP (so the connection goes to the IP that was matched), or
// the original destination when no resolution was attempted or the outbound
// resolves names itself. A remote-resolving outbound also keeps the original
// destination when local resolution fails, unless the private filter needs the
// resolved address.
//
// It returns errACLRejected when a rule rejects the request, or a resolver.Error
// when resolution ran but yielded nothing and the outbound cannot resolve the
// name itself (or the private filter is on), or errPrivateDestination when the
// private filter is on and the address to dial is not public. A hijack address
// is exempt from the filter because the operator chose it. For a
// remote-resolving outbound the filter checks every resolved family, not only
// the address it would have dialed.
//
// The order matters and mirrors hysteria's Resolver(ACL(outbound)) chain:
// resolution failure is not fatal until after the ACL has had its say, so
// name-based reject rules still fire on an unresolvable domain and a hijack rule
// can still redirect one.
func (p *outboundPolicy) selectRoute(ctx context.Context, destination M.Socksaddr, proto acl.Protocol) (route, error) {
	host, result, attempted := p.hostInfo(ctx, destination)
	ob := p.fallback
	if p.acl != nil {
		var hijack net.IP
		ob, hijack = p.acl.Lookup(host, result.IPv4, result.IPv6, proto, destination.Port)
		if _, ok := ob.(outbound.Reject); ok {
			return route{}, errACLRejected
		}
		if hijack != nil {
			return route{ob, M.SocksaddrFrom(ipToNetip(hijack), destination.Port)}, nil
		}
	}
	addr, err := pickDialAddr(destination, result, attempted)
	if err != nil {
		// A remote-resolving outbound can still reach a name the local resolver
		// cannot, unless the private filter needs the IP to decide.
		if !ob.RemoteResolve() || p.blockPrivate {
			return route{}, err
		}
		return route{ob, destination}, nil
	}
	if p.blockPrivate && reachesPrivate(ob, addr, result) {
		return route{}, errPrivateDestination
	}
	if ob.RemoteResolve() {
		return route{ob, destination}, nil
	}
	return route{ob, addr}, nil
}

// reachesPrivate reports whether ob may connect to a non-public address. A
// remote-resolving outbound looks the name up again and may use either family,
// so both resolved records are checked. Other outbounds dial addr itself.
func reachesPrivate(ob outbound.Outbound, addr M.Socksaddr, result resolver.Result) bool {
	if ob.RemoteResolve() {
		return isPrivateIP(result.IPv4) || isPrivateIP(result.IPv6)
	}
	return addr.IsIP() && isPrivateAddr(addr.Addr)
}

func isPrivateIP(ip net.IP) bool {
	return ip != nil && isPrivateAddr(ipToNetip(ip))
}

// pickDialAddr prefers the resolved IPv4 address, then IPv6, and keeps the
// original destination when no resolution was attempted.
func pickDialAddr(destination M.Socksaddr, result resolver.Result, attempted bool) (M.Socksaddr, error) {
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
	route    route
}

// routedPacketConn applies the policy per packet for udp-over-tcp and sends the
// allowed packets through the outbound the ACL picked. The outbound socket is
// opened lazily on the first allowed packet, so a stream that only carries
// rejected or unresolvable traffic never opens one. That socket then serves the
// whole stream: packets the ACL routes to a different outbound are dropped,
// which differs from hysteria on purpose, because there a stream can otherwise
// leave through an egress its ACL decision did not choose.
//
// Rejected packets are dropped silently (mirroring hysteria, which ignores
// per-packet Feed errors), and so are packets whose destination cannot be
// resolved: returning an error here would tear down the whole stream inside
// bufio.CopyPacketConn, taking every other destination it multiplexes with it.
// A ListenUDP failure is the exception; it ends the stream, as it does in
// hysteria. Decisions are cached per destination for the life of the stream.
type routedPacketConn struct {
	ctx    context.Context
	policy *outboundPolicy
	cache  map[string]policyDecision

	// mu guards the lazily opened socket, which Close may race against.
	mu       sync.Mutex
	outbound outbound.Outbound
	conn     N.PacketConn
	closed   bool
	// ready is closed once conn is set or the stream is closed, so a blocked
	// ReadPacket returns even if no packet is ever allowed.
	ready chan struct{}
}

func newRoutedPacketConn(ctx context.Context, p *outboundPolicy) *routedPacketConn {
	return &routedPacketConn{
		ctx:    ctx,
		policy: p,
		cache:  make(map[string]policyDecision),
		ready:  make(chan struct{}),
	}
}

func (c *routedPacketConn) decide(destination M.Socksaddr) policyDecision {
	r, err := c.policy.selectRoute(c.ctx, destination, acl.ProtocolUDP)
	if err != nil {
		if !errors.Is(err, errACLRejected) && !errors.Is(err, errPrivateDestination) {
			logrus.Debugln("routedPacketConn drop:", destination, err)
		}
		return policyDecision{rejected: true}
	}
	return policyDecision{route: r}
}

func (c *routedPacketConn) WritePacket(b *buf.Buffer, destination M.Socksaddr) error {
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

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		b.Release()
		return net.ErrClosed
	}
	if c.conn == nil {
		conn, err := d.route.outbound.ListenUDP(c.ctx)
		if err != nil {
			logrus.Debugln("routedPacketConn ListenUDP:", err)
			c.mu.Unlock()
			b.Release()
			return err
		}
		c.outbound = d.route.outbound
		c.conn = conn
		close(c.ready)
	}
	conn := c.conn
	bound := c.outbound
	c.mu.Unlock()

	if d.route.outbound != bound {
		b.Release()
		logrus.Debugln("routedPacketConn drop:", destination, "belongs to another outbound")
		return nil
	}
	return conn.WritePacket(b, d.route.target)
}

func (c *routedPacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	<-c.ready
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return M.Socksaddr{}, net.ErrClosed
	}
	return conn.ReadPacket(b)
}

// Close is idempotent. It also releases a ReadPacket blocked on the lazy open.
func (c *routedPacketConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	select {
	case <-c.ready:
	default:
		close(c.ready)
	}
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// FrontHeadroom leaves room for a SOCKS5 UDP header, which a remote outbound
// writes in place.
func (c *routedPacketConn) FrontHeadroom() int {
	return 3 + M.MaxSocksaddrLength
}

func (c *routedPacketConn) currentConn() N.PacketConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn
}

func (c *routedPacketConn) LocalAddr() net.Addr {
	if conn := c.currentConn(); conn != nil {
		return conn.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (c *routedPacketConn) SetDeadline(t time.Time) error {
	if conn := c.currentConn(); conn != nil {
		return conn.SetDeadline(t)
	}
	return nil
}

func (c *routedPacketConn) SetReadDeadline(t time.Time) error {
	if conn := c.currentConn(); conn != nil {
		return conn.SetReadDeadline(t)
	}
	return nil
}

func (c *routedPacketConn) SetWriteDeadline(t time.Time) error {
	if conn := c.currentConn(); conn != nil {
		return conn.SetWriteDeadline(t)
	}
	return nil
}
