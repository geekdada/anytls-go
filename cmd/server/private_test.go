package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"anytls/acl"
	"anytls/resolver"

	M "github.com/sagernet/sing/common/metadata"
)

func TestIsPrivateAddr(t *testing.T) {
	private := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
		"100.100.100.200", "0.0.0.0", "0.1.2.3", "255.255.255.255", "224.0.0.1",
		"::1", "::", "fe80::1", "fd00:ec2::254", "ff02::1", "::ffff:127.0.0.1",
	}
	for _, s := range private {
		if !isPrivateAddr(netip.MustParseAddr(s)) {
			t.Errorf("isPrivateAddr(%s) = false, want true", s)
		}
	}
	public := []string{"1.1.1.1", "8.8.8.8", "100.128.0.1", "2001:4860:4860::8888"}
	for _, s := range public {
		if isPrivateAddr(netip.MustParseAddr(s)) {
			t.Errorf("isPrivateAddr(%s) = true, want false", s)
		}
	}
}

func TestPolicyBlocksPrivateLiteral(t *testing.T) {
	p := newOutboundPolicy(nil, nil, true, nil)
	for _, addr := range []string{"127.0.0.1:8080", "[::1]:22", "169.254.169.254:80", "10.0.0.1:443"} {
		if _, err := tcpDialAddr(t, p, addr); !errors.Is(err, errPrivateDestination) {
			t.Errorf("%s: err = %v, want errPrivateDestination", addr, err)
		}
	}
	if _, err := tcpDialAddr(t, p, "1.1.1.1:443"); err != nil {
		t.Fatalf("public literal: err = %v", err)
	}
}

func TestPolicyBlocksDomainResolvingToPrivate(t *testing.T) {
	// The domain is resolved up front and the resolved IP is what gets dialed,
	// so a name pointing at a private address cannot slip through.
	res := &stubResolver{result: resolver.Result{IPv4: net.IPv4(192, 168, 0, 1).To4()}}
	if _, err := tcpDialAddr(t, newOutboundPolicy(nil, res, true, nil), "intranet.example:80"); !errors.Is(err, errPrivateDestination) {
		t.Fatalf("err = %v, want errPrivateDestination", err)
	}
}

func TestPolicyBlocksLocalhostWithSystemResolver(t *testing.T) {
	p := newOutboundPolicy(nil, nil, true, nil)
	if _, err := tcpDialAddr(t, p, "localhost:80"); !errors.Is(err, errPrivateDestination) {
		t.Fatalf("err = %v, want errPrivateDestination", err)
	}
}

func TestPolicyPrivateFilterAllowsHijack(t *testing.T) {
	// A hijack target comes from the operator's rules, not from the client.
	p := newOutboundPolicy(testEngine(t, "direct(8.8.8.8, udp/53, 10.0.0.53)\ndirect(all)\n"), nil, true, nil)
	r, err := p.selectRoute(t.Context(), M.ParseSocksaddr("8.8.8.8:53"), acl.ProtocolUDP)
	if err != nil || r.target.String() != "10.0.0.53:53" {
		t.Fatalf("selectRoute = (%v, %v), want 10.0.0.53:53", r.target, err)
	}
}

func TestPolicyPacketConnDropsPrivate(t *testing.T) {
	stub, c := newTestPacketConn(t, newOutboundPolicy(nil, nil, true, nil))
	writeTestPacket(t, c, "192.168.1.1:53")
	writeTestPacket(t, c, "1.1.1.1:53")
	if len(stub.written) != 1 || stub.written[0] != "1.1.1.1:53" {
		t.Fatalf("written = %v, want only 1.1.1.1:53", stub.written)
	}
}

func TestClientErrorHidesDetails(t *testing.T) {
	tests := []struct {
		err  error
		want error
	}{
		{errACLRejected, errClientBlocked},
		{errPrivateDestination, errClientBlocked},
		{fmt.Errorf("wrapped: %w", resolver.Error{Err: errors.New("read udp 10.0.0.53:53: i/o timeout")}), errClientResolveFailed},
		{errors.New("dial tcp 10.9.9.9:443: connection refused"), errClientDialFailed},
	}
	for _, tt := range tests {
		if got := clientError(tt.err); got != tt.want {
			t.Errorf("clientError(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}
