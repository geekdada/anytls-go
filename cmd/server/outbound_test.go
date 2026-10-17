package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"anytls/acl"
	"anytls/outbound"
	"anytls/resolver"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// stubOutbound records TCP dials and hands out its packets conn on ListenUDP.
type stubOutbound struct {
	remote    bool
	mu        sync.Mutex
	dialed    []string
	listens   int
	listenErr error
	packets   *stubPacketConn
}

func (s *stubOutbound) RemoteResolve() bool {
	return s.remote
}

func (s *stubOutbound) DialTCP(_ context.Context, destination M.Socksaddr) (net.Conn, error) {
	s.mu.Lock()
	s.dialed = append(s.dialed, destination.String())
	s.mu.Unlock()
	return nil, errors.New("stub outbound has no dialer")
}

func (s *stubOutbound) ListenUDP(context.Context) (N.PacketConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listens++
	if s.listenErr != nil {
		return nil, s.listenErr
	}
	if s.packets == nil {
		return nil, errors.New("stub outbound has no packets conn")
	}
	return s.packets, nil
}

func testEngineWith(t *testing.T, rules string, obs map[string]outbound.Outbound) *acl.Engine[outbound.Outbound] {
	t.Helper()
	e, err := acl.NewEngineFromString(rules, obs, &acl.FileGeoLoader{})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestOutboundMapBuiltins(t *testing.T) {
	direct := &stubOutbound{}
	m := outboundMap(nil, direct)

	if len(m) != 3 {
		t.Fatalf("outboundMap keys = %v, want exactly direct, reject, default", m)
	}
	if m["direct"] != direct {
		t.Errorf("direct = %v, want the given direct outbound", m["direct"])
	}
	if m["default"] != direct {
		t.Errorf("default = %v, want direct when there are no entries", m["default"])
	}
	if _, ok := m["reject"].(outbound.Reject); !ok {
		t.Errorf("reject = %T, want outbound.Reject", m["reject"])
	}
}

func TestOutboundMapDefaultIsFirstEntry(t *testing.T) {
	warp := &stubOutbound{remote: true}
	direct := &stubOutbound{}
	m := outboundMap([]namedOutbound{{"WARP", warp}, {"other", direct}}, direct)

	if m["warp"] != warp {
		t.Errorf("warp = %v, want the WARP entry under its lowercased name", m["warp"])
	}
	if m["default"] != warp {
		t.Errorf("default = %v, want the first entry", m["default"])
	}
}

func TestOutboundMapEntryOverridesBuiltin(t *testing.T) {
	warp := &stubOutbound{remote: true}
	m := outboundMap([]namedOutbound{{"reject", warp}}, outbound.NewDirect())

	if m["reject"] != warp {
		t.Errorf("reject = %v, want the user entry", m["reject"])
	}
}

func TestPolicyRouteACLPicksNamedOutbound(t *testing.T) {
	warp := &stubOutbound{remote: true}
	direct := &stubOutbound{}
	obs := outboundMap([]namedOutbound{{"warp", warp}}, direct)
	res := &stubResolver{result: resolver.Result{IPv4: net.IPv4(1, 2, 3, 4).To4()}}
	p := newOutboundPolicy(testEngineWith(t, "warp(suffix:example.com)\ndirect(all)\n", obs), res, false, obs["default"])

	r, err := p.selectRoute(context.Background(), M.ParseSocksaddr("www.example.com:443"), acl.ProtocolTCP)
	if err != nil {
		t.Fatal(err)
	}
	if r.outbound != warp || r.target.String() != "www.example.com:443" {
		t.Fatalf("route = (%v, %s), want (warp, www.example.com:443)", r.outbound, r.target)
	}

	r, err = p.selectRoute(context.Background(), M.ParseSocksaddr("9.9.9.9:443"), acl.ProtocolTCP)
	if err != nil {
		t.Fatal(err)
	}
	if r.outbound != direct || r.target.String() != "9.9.9.9:443" {
		t.Fatalf("route = (%v, %s), want (direct, 9.9.9.9:443)", r.outbound, r.target)
	}
}

func TestPolicyRouteNoACLUsesFallback(t *testing.T) {
	warp := &stubOutbound{remote: true}
	p := newOutboundPolicy(nil, nil, false, warp)

	r, err := p.selectRoute(context.Background(), M.ParseSocksaddr("example.com:443"), acl.ProtocolTCP)
	if err != nil {
		t.Fatal(err)
	}
	if r.outbound != warp || r.target.String() != "example.com:443" {
		t.Fatalf("route = (%v, %s), want (warp, example.com:443)", r.outbound, r.target)
	}
}

func TestPolicyRouteRemoteBlocksPrivate(t *testing.T) {
	warp := &stubOutbound{remote: true}
	res := &stubResolver{result: resolver.Result{IPv4: net.IPv4(192, 168, 0, 1).To4()}}
	p := newOutboundPolicy(nil, res, true, warp)

	if _, err := p.selectRoute(context.Background(), M.ParseSocksaddr("example.com:443"), acl.ProtocolTCP); !errors.Is(err, errPrivateDestination) {
		t.Fatalf("private resolve: err = %v, want errPrivateDestination", err)
	}

	res.result = resolver.Result{IPv4: net.IPv4(1, 2, 3, 4).To4()}
	r, err := p.selectRoute(context.Background(), M.ParseSocksaddr("example.com:443"), acl.ProtocolTCP)
	if err != nil {
		t.Fatal(err)
	}
	if r.outbound != warp || r.target.String() != "example.com:443" {
		t.Fatalf("route = (%v, %s), want the original domain for remote resolving", r.outbound, r.target)
	}

	if _, err := p.selectRoute(context.Background(), M.ParseSocksaddr("10.0.0.1:443"), acl.ProtocolTCP); !errors.Is(err, errPrivateDestination) {
		t.Fatalf("private literal: err = %v, want errPrivateDestination", err)
	}
}

func TestPolicyRouteRemoteResolveFailure(t *testing.T) {
	warp := &stubOutbound{remote: true}
	res := &stubResolver{result: resolver.Result{Err: errors.New("boom")}}

	r, err := newOutboundPolicy(nil, res, false, warp).selectRoute(context.Background(), M.ParseSocksaddr("example.com:443"), acl.ProtocolTCP)
	if err != nil {
		t.Fatalf("resolve failure without the private filter: err = %v", err)
	}
	if r.outbound != warp || r.target.String() != "example.com:443" {
		t.Fatalf("route = (%v, %s), want (warp, example.com:443)", r.outbound, r.target)
	}

	_, err = newOutboundPolicy(nil, res, true, warp).selectRoute(context.Background(), M.ParseSocksaddr("example.com:443"), acl.ProtocolTCP)
	var resolveErr resolver.Error
	if !errors.As(err, &resolveErr) {
		t.Fatalf("resolve failure with the private filter: err = %v, want resolver.Error", err)
	}
}

func TestPolicyRouteHijackViaRemote(t *testing.T) {
	warp := &stubOutbound{remote: true}
	obs := outboundMap([]namedOutbound{{"warp", warp}}, outbound.NewDirect())
	res := &stubResolver{result: resolver.Result{IPv4: net.IPv4(9, 9, 9, 9).To4()}}
	p := newOutboundPolicy(testEngineWith(t, "warp(example.com,*,1.1.1.1)\n", obs), res, false, obs["default"])

	r, err := p.selectRoute(context.Background(), M.ParseSocksaddr("example.com:443"), acl.ProtocolTCP)
	if err != nil {
		t.Fatal(err)
	}
	if r.outbound != warp || r.target.String() != "1.1.1.1:443" {
		t.Fatalf("route = (%v, %s), want (warp, 1.1.1.1:443)", r.outbound, r.target)
	}
}

func TestProxyOutboundTCPDialsRouteTarget(t *testing.T) {
	stub := &stubOutbound{remote: true}
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	err := proxyOutboundTCP(context.Background(), serverConn, M.ParseSocksaddr("example.com:443"), nil, newOutboundPolicy(nil, nil, false, stub))
	if err == nil {
		t.Fatal("expected the stub dial to fail")
	}
	if len(stub.dialed) != 1 || stub.dialed[0] != "example.com:443" {
		t.Fatalf("dialed = %v, want [example.com:443]", stub.dialed)
	}
}
