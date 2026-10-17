package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"anytls/acl"
	"anytls/outbound"
	"anytls/resolver"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func testEngine(t *testing.T, rules string) *acl.Engine[outbound.Outbound] {
	t.Helper()
	return testEngineWith(t, rules, outboundMap(nil, outbound.NewDirect()))
}

// stubResolver records the hosts it was asked about and answers with a fixed
// result.
type stubResolver struct {
	mu     sync.Mutex
	calls  []string
	result resolver.Result
}

func (s *stubResolver) Resolve(_ context.Context, host string) resolver.Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, host)
	return s.result
}

func (s *stubResolver) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// tcpDialAddr is the TCP-path shorthand used throughout these tests.
func tcpDialAddr(t *testing.T, p *outboundPolicy, addr string) (M.Socksaddr, error) {
	t.Helper()
	r, err := p.selectRoute(context.Background(), M.ParseSocksaddr(addr), acl.ProtocolTCP)
	return r.target, err
}

func TestPolicyDialAddrReject(t *testing.T) {
	p := newOutboundPolicy(testEngine(t, "reject(10.0.0.0/8)\ndirect(all)\n"), nil, false, nil)
	if _, err := tcpDialAddr(t, p, "10.1.2.3:443"); !errors.Is(err, errACLRejected) {
		t.Fatalf("expected reject for 10.1.2.3, got err = %v", err)
	}
	if _, err := tcpDialAddr(t, p, "11.1.2.3:443"); err != nil {
		t.Fatalf("expected direct for 11.1.2.3, got err = %v", err)
	}
}

func TestPolicyDialAddrHijack(t *testing.T) {
	p := newOutboundPolicy(testEngine(t, "direct(8.8.8.8,*,1.1.1.1)\ndirect(all)\n"), nil, false, nil)
	addr, err := tcpDialAddr(t, p, "8.8.8.8:53")
	if err != nil {
		t.Fatalf("expected direct, got err = %v", err)
	}
	if addr.String() != "1.1.1.1:53" {
		t.Fatalf("dial addr = %s, want 1.1.1.1:53", addr)
	}
}

func TestPolicyDialAddrResolvesFqdn(t *testing.T) {
	p := newOutboundPolicy(testEngine(t, "reject(127.0.0.1)\ndirect(all)\n"), nil, false, nil)
	// localhost resolves locally to 127.0.0.1, so the IP rule must apply to
	// the domain request. This covers the system-resolver path.
	if _, err := tcpDialAddr(t, p, "localhost:443"); !errors.Is(err, errACLRejected) {
		t.Fatalf("expected localhost to match the 127.0.0.1 reject rule, got err = %v", err)
	}
}

func TestPolicyDialAddrNoRuleMatchKeepsDestination(t *testing.T) {
	p := newOutboundPolicy(testEngine(t, "reject(1.2.3.4)\n"), nil, false, nil)
	dst := M.ParseSocksaddr("9.9.9.9:443")
	addr, err := tcpDialAddr(t, p, "9.9.9.9:443")
	if err != nil || addr != dst {
		t.Fatalf("expected (%v, nil), got (%v, %v)", dst, addr, err)
	}
}

func TestPolicyDialAddrResolverWithoutACL(t *testing.T) {
	res := &stubResolver{result: resolver.Result{IPv4: net.IPv4(1, 2, 3, 4).To4()}}
	p := newOutboundPolicy(nil, res, false, nil)
	addr, err := tcpDialAddr(t, p, "example.com:443")
	if err != nil {
		t.Fatalf("unexpected err = %v", err)
	}
	if addr.String() != "1.2.3.4:443" {
		t.Fatalf("dial addr = %s, want 1.2.3.4:443", addr)
	}
	if res.callCount() != 1 {
		t.Fatalf("resolver calls = %d, want 1", res.callCount())
	}
}

func TestPolicyDialAddrResolverPrefersIPv4(t *testing.T) {
	res := &stubResolver{result: resolver.Result{
		IPv4: net.IPv4(1, 2, 3, 4).To4(),
		IPv6: net.ParseIP("2001:db8::1"),
	}}
	addr, err := tcpDialAddr(t, newOutboundPolicy(nil, res, false, nil), "example.com:443")
	if err != nil {
		t.Fatalf("unexpected err = %v", err)
	}
	if addr.String() != "1.2.3.4:443" {
		t.Fatalf("dial addr = %s, want 1.2.3.4:443", addr)
	}
}

func TestPolicyDialAddrResolverIPv6Only(t *testing.T) {
	res := &stubResolver{result: resolver.Result{IPv6: net.ParseIP("2001:db8::1")}}
	addr, err := tcpDialAddr(t, newOutboundPolicy(nil, res, false, nil), "example.com:443")
	if err != nil {
		t.Fatalf("unexpected err = %v", err)
	}
	if addr.String() != "[2001:db8::1]:443" {
		t.Fatalf("dial addr = %s, want [2001:db8::1]:443", addr)
	}
}

func TestPolicyDialAddrResolverFailureFailsRequest(t *testing.T) {
	inner := errors.New("boom")
	res := &stubResolver{result: resolver.Result{Err: inner}}
	_, err := tcpDialAddr(t, newOutboundPolicy(nil, res, false, nil), "example.com:443")
	var resolveErr resolver.Error
	if !errors.As(err, &resolveErr) {
		t.Fatalf("err = %v, want resolver.Error", err)
	}
	if !errors.Is(err, inner) {
		t.Fatalf("err = %v, want it to wrap %v", err, inner)
	}
}

func TestPolicyDialAddrResolverFailureACLRejectWins(t *testing.T) {
	// The ACL runs even when resolution failed, so a name rule still fires.
	res := &stubResolver{result: resolver.Result{Err: errors.New("boom")}}
	p := newOutboundPolicy(testEngine(t, "reject(suffix:example.com)\ndirect(all)\n"), res, false, nil)
	if _, err := tcpDialAddr(t, p, "blocked.example.com:443"); !errors.Is(err, errACLRejected) {
		t.Fatalf("err = %v, want errACLRejected", err)
	}
}

func TestPolicyDialAddrResolverFailureACLHijackWins(t *testing.T) {
	// A hijack rule rescues a domain the resolver could not resolve, matching
	// hysteria, where the hijack replaces the resolve result.
	res := &stubResolver{result: resolver.Result{Err: errors.New("boom")}}
	p := newOutboundPolicy(testEngine(t, "direct(example.com,*,1.1.1.1)\ndirect(all)\n"), res, false, nil)
	addr, err := tcpDialAddr(t, p, "example.com:443")
	if err != nil {
		t.Fatalf("unexpected err = %v", err)
	}
	if addr.String() != "1.1.1.1:443" {
		t.Fatalf("dial addr = %s, want 1.1.1.1:443", addr)
	}
}

func TestPolicyDialAddrACLMatchesResolvedIP(t *testing.T) {
	res := &stubResolver{result: resolver.Result{IPv4: net.IPv4(127, 0, 0, 1).To4()}}
	p := newOutboundPolicy(testEngine(t, "reject(127.0.0.1)\ndirect(all)\n"), res, false, nil)
	if _, err := tcpDialAddr(t, p, "blocked.example:443"); !errors.Is(err, errACLRejected) {
		t.Fatalf("err = %v, want the resolved IP to hit the reject rule", err)
	}
}

func TestPolicyDialAddrLiteralIPSkipsResolver(t *testing.T) {
	res := &stubResolver{result: resolver.Result{Err: errors.New("should not be called")}}
	addr, err := tcpDialAddr(t, newOutboundPolicy(nil, res, false, nil), "9.9.9.9:443")
	if err != nil {
		t.Fatalf("unexpected err = %v", err)
	}
	if addr.String() != "9.9.9.9:443" {
		t.Fatalf("dial addr = %s, want 9.9.9.9:443", addr)
	}
	if res.callCount() != 0 {
		t.Fatalf("resolver calls = %d, want 0 for an IP literal", res.callCount())
	}
}

func TestPolicyDialAddrNothingConfiguredKeepsFqdn(t *testing.T) {
	// With neither dependency there is nothing to resolve for: the dialer
	// resolves the name at connect time, as it did before the resolver existed.
	p := newOutboundPolicy(nil, nil, false, nil)
	dst := M.ParseSocksaddr("example.com:443")
	addr, err := tcpDialAddr(t, p, "example.com:443")
	if err != nil || addr != dst {
		t.Fatalf("expected (%v, nil), got (%v, %v)", dst, addr, err)
	}
}

type stubPacketConn struct {
	written []string
}

func (s *stubPacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, net.ErrClosed
}

func (s *stubPacketConn) WritePacket(b *buf.Buffer, destination M.Socksaddr) error {
	defer b.Release()
	s.written = append(s.written, destination.String())
	return nil
}

func (s *stubPacketConn) Close() error                       { return nil }
func (s *stubPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (s *stubPacketConn) SetDeadline(t time.Time) error      { return nil }
func (s *stubPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (s *stubPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func writeTestPacket(t *testing.T, c N.PacketConn, addr string) {
	t.Helper()
	b := buf.NewSize(1)
	defer b.Release()
	_ = b.WriteByte(0)
	if err := c.WritePacket(b, M.ParseSocksaddr(addr)); err != nil {
		t.Fatal(err)
	}
}

func newTestPacketConn(t *testing.T, p *outboundPolicy) (*stubPacketConn, *policyPacketConn) {
	t.Helper()
	stub := &stubPacketConn{}
	return stub, newPolicyPacketConn(context.Background(), stub, p).(*policyPacketConn)
}

func TestPolicyPacketConnRejectDrops(t *testing.T) {
	p := newOutboundPolicy(testEngine(t, "reject(all, udp/443)\nreject(10.0.0.0/8)\ndirect(all)\n"), nil, false, nil)
	stub, c := newTestPacketConn(t, p)

	writeTestPacket(t, c, "8.8.8.8:443") // rejected by proto/port
	writeTestPacket(t, c, "10.1.2.3:53") // rejected by CIDR
	writeTestPacket(t, c, "8.8.8.8:53")  // allowed
	writeTestPacket(t, c, "10.1.2.3:53") // rejected, cache hit this time
	writeTestPacket(t, c, "1.1.1.1:853") // allowed

	if len(stub.written) != 2 || stub.written[0] != "8.8.8.8:53" || stub.written[1] != "1.1.1.1:853" {
		t.Fatalf("written = %v, want [8.8.8.8:53 1.1.1.1:853]", stub.written)
	}
	if len(c.cache) != 4 {
		t.Fatalf("cache entries = %d, want 4", len(c.cache))
	}
}

func TestPolicyPacketConnHijackRewrites(t *testing.T) {
	p := newOutboundPolicy(testEngine(t, "direct(8.8.8.8, udp/53, 1.1.1.1)\ndirect(all)\n"), nil, false, nil)
	stub, c := newTestPacketConn(t, p)

	writeTestPacket(t, c, "8.8.8.8:53")
	if len(stub.written) != 1 || stub.written[0] != "1.1.1.1:53" {
		t.Fatalf("written = %v, want [1.1.1.1:53]", stub.written)
	}
}

func TestPolicyPacketConnResolvesAndCaches(t *testing.T) {
	res := &stubResolver{result: resolver.Result{IPv4: net.IPv4(1, 2, 3, 4).To4()}}
	stub, c := newTestPacketConn(t, newOutboundPolicy(nil, res, false, nil))

	writeTestPacket(t, c, "example.com:53")
	writeTestPacket(t, c, "example.com:53")

	if len(stub.written) != 2 || stub.written[0] != "1.2.3.4:53" || stub.written[1] != "1.2.3.4:53" {
		t.Fatalf("written = %v, want two 1.2.3.4:53 packets", stub.written)
	}
	if res.callCount() != 1 {
		t.Fatalf("resolver calls = %d, want 1 (decision cached per destination)", res.callCount())
	}
}

func TestPolicyPacketConnDropsOnResolveFailure(t *testing.T) {
	// A resolve failure drops the packet but keeps the stream alive: it
	// multiplexes other destinations that may resolve fine.
	res := &stubResolver{result: resolver.Result{Err: errors.New("boom")}}
	stub, c := newTestPacketConn(t, newOutboundPolicy(nil, res, false, nil))

	writeTestPacket(t, c, "example.com:53")
	if len(stub.written) != 0 {
		t.Fatalf("written = %v, want the packet dropped", stub.written)
	}
}
