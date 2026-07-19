package main

import (
	"net"
	"testing"
	"time"

	"anytls/acl"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func testEngine(t *testing.T, rules string) *acl.Engine {
	t.Helper()
	e, err := acl.NewEngineFromString(rules, &acl.FileGeoLoader{})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestACLTCPDialAddrReject(t *testing.T) {
	e := testEngine(t, "reject(10.0.0.0/8)\ndirect(all)\n")
	_, ok := aclTCPDialAddr(e, M.ParseSocksaddr("10.1.2.3:443"))
	if ok {
		t.Fatal("expected reject for 10.1.2.3")
	}
	_, ok = aclTCPDialAddr(e, M.ParseSocksaddr("11.1.2.3:443"))
	if !ok {
		t.Fatal("expected direct for 11.1.2.3")
	}
}

func TestACLTCPDialAddrHijack(t *testing.T) {
	e := testEngine(t, "direct(8.8.8.8,*,1.1.1.1)\ndirect(all)\n")
	addr, ok := aclTCPDialAddr(e, M.ParseSocksaddr("8.8.8.8:53"))
	if !ok {
		t.Fatal("expected direct")
	}
	if addr.String() != "1.1.1.1:53" {
		t.Fatalf("dial addr = %s, want 1.1.1.1:53", addr)
	}
}

func TestACLTCPDialAddrResolvesFqdn(t *testing.T) {
	e := testEngine(t, "reject(127.0.0.1)\ndirect(all)\n")
	// localhost resolves locally to 127.0.0.1, so the IP rule must apply to
	// the domain request.
	_, ok := aclTCPDialAddr(e, M.ParseSocksaddr("localhost:443"))
	if ok {
		t.Fatal("expected localhost to match the 127.0.0.1 reject rule")
	}
}

func TestACLTCPDialAddrNoRuleMatchKeepsDestination(t *testing.T) {
	e := testEngine(t, "reject(1.2.3.4)\n")
	dst := M.ParseSocksaddr("9.9.9.9:443")
	addr, ok := aclTCPDialAddr(e, dst)
	if !ok || addr != dst {
		t.Fatalf("expected (%v, true), got (%v, %v)", dst, addr, ok)
	}
}

type stubPacketConn struct {
	written []string
}

func (s *stubPacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, net.ErrClosed
}

func (s *stubPacketConn) WritePacket(b *buf.Buffer, destination M.Socksaddr) error {
	s.written = append(s.written, destination.String())
	return nil
}

func (s *stubPacketConn) Close() error                       { return nil }
func (s *stubPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (s *stubPacketConn) SetDeadline(t time.Time) error      { return nil }
func (s *stubPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (s *stubPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func writeTestPacket(t *testing.T, c *aclPacketConn, addr string) {
	t.Helper()
	b := buf.NewSize(1)
	defer b.Release()
	_ = b.WriteByte(0)
	if err := c.WritePacket(b, M.ParseSocksaddr(addr)); err != nil {
		t.Fatal(err)
	}
}

func TestACLPacketConnRejectDrops(t *testing.T) {
	e := testEngine(t, "reject(all, udp/443)\nreject(10.0.0.0/8)\ndirect(all)\n")
	stub := &stubPacketConn{}
	c := newACLPacketConn(stub, e).(*aclPacketConn)

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

func TestACLPacketConnHijackRewrites(t *testing.T) {
	e := testEngine(t, "direct(8.8.8.8, udp/53, 1.1.1.1)\ndirect(all)\n")
	stub := &stubPacketConn{}
	c := newACLPacketConn(stub, e)

	writeTestPacket(t, c.(*aclPacketConn), "8.8.8.8:53")
	if len(stub.written) != 1 || stub.written[0] != "1.1.1.1:53" {
		t.Fatalf("written = %v, want [1.1.1.1:53]", stub.written)
	}
}
