package resolver

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// countingListener counts accepted connections.
type countingListener struct {
	net.Listener
	accepted atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return conn, err
}

// newTCPDNSTestServer answers every A query with 1.2.3.4 and every AAAA query
// with an empty answer, closing idle connections after idleTimeout.
func newTCPDNSTestServer(t *testing.T, idleTimeout time.Duration) (string, *countingListener) {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &countingListener{Listener: inner}
	server := &dns.Server{
		Listener:    listener,
		IdleTimeout: func() time.Duration { return idleTimeout },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			reply := new(dns.Msg)
			reply.SetReply(req)
			if q := req.Question[0]; q.Qtype == dns.TypeA {
				reply.Answer = []dns.RR{aRecord(q.Name, "1.2.3.4")}
			}
			_ = w.WriteMsg(reply)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return inner.Addr().String(), listener
}

func TestTCPResolverReusesConnections(t *testing.T) {
	addr, listener := newTCPDNSTestServer(t, time.Minute)
	r := NewTCP(addr, time.Second)

	const lookups = 10
	for range lookups {
		if got := ipString(r.Resolve(context.Background(), "example.com").IPv4); got != "1.2.3.4" {
			t.Fatalf("IPv4 = %q, want 1.2.3.4", got)
		}
	}
	// A and AAAA run in parallel, so at most two connections are needed.
	if got := listener.accepted.Load(); got > 2 {
		t.Fatalf("server accepted %d connections for %d lookups, want at most 2", got, lookups)
	}
}

func TestTCPResolverRecoversFromClosedIdleConnection(t *testing.T) {
	addr, _ := newTCPDNSTestServer(t, 50*time.Millisecond)
	r := NewTCP(addr, time.Second)

	r.Resolve(context.Background(), "example.com")
	time.Sleep(200 * time.Millisecond) // the server closes the pooled connections

	result := r.Resolve(context.Background(), "example.com")
	if got := ipString(result.IPv4); got != "1.2.3.4" || result.Err != nil {
		t.Fatalf("Resolve = (%q, %v), want 1.2.3.4 on a fresh connection", got, result.Err)
	}
}
