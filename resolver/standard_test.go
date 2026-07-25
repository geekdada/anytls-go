package resolver

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// dnsTestServer is a local DNS server recording the questions it received.
type dnsTestServer struct {
	addr string

	mu        sync.Mutex
	questions []dns.Question
}

// newDNSTestServer starts a UDP DNS server on localhost. The handler answers
// one question at a time; returning nil sends nothing, which makes the client
// time out.
func newDNSTestServer(t *testing.T, handler func(q dns.Question) []dns.RR) *dnsTestServer {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &dnsTestServer{addr: conn.LocalAddr().String()}
	server := &dns.Server{
		PacketConn: conn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			if len(req.Question) == 0 {
				return
			}
			q := req.Question[0]
			s.mu.Lock()
			s.questions = append(s.questions, q)
			s.mu.Unlock()

			answer := handler(q)
			if answer == nil {
				return // no response: let the client time out
			}
			reply := new(dns.Msg)
			reply.SetReply(req)
			reply.Answer = answer
			_ = w.WriteMsg(reply)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return s
}

func (s *dnsTestServer) names(qtype uint16) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var names []string
	for _, q := range s.questions {
		if q.Qtype == qtype {
			names = append(names, q.Name)
		}
	}
	return names
}

func (s *dnsTestServer) count(qtype uint16) int {
	return len(s.names(qtype))
}

func aRecord(name, ip string) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP(ip),
	}
}

func aaaaRecord(name, ip string) dns.RR {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: net.ParseIP(ip),
	}
}

func cnameRecord(name, target string) dns.RR {
	return &dns.CNAME{
		Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
		Target: target,
	}
}

func testUDPResolver(t *testing.T, server *dnsTestServer, timeout time.Duration) *standardResolver {
	t.Helper()
	return NewUDP(server.addr, timeout).(*standardResolver)
}

func TestStandardResolverResolve(t *testing.T) {
	server := newDNSTestServer(t, func(q dns.Question) []dns.RR {
		switch q.Qtype {
		case dns.TypeA:
			// Two records: only the first must be kept.
			return []dns.RR{aRecord(q.Name, "1.2.3.4"), aRecord(q.Name, "5.6.7.8")}
		case dns.TypeAAAA:
			return []dns.RR{aaaaRecord(q.Name, "2001:db8::1")}
		}
		return nil
	})

	result := testUDPResolver(t, server, time.Second).Resolve(context.Background(), "example.com")
	if result.Err != nil {
		t.Fatalf("Err = %v, want nil", result.Err)
	}
	if got := ipString(result.IPv4); got != "1.2.3.4" {
		t.Errorf("IPv4 = %q, want 1.2.3.4", got)
	}
	if len(result.IPv4) != net.IPv4len {
		t.Errorf("len(IPv4) = %d, want %d", len(result.IPv4), net.IPv4len)
	}
	if got := ipString(result.IPv6); got != "2001:db8::1" {
		t.Errorf("IPv6 = %q, want 2001:db8::1", got)
	}
	// A and AAAA are queried in parallel, one query each.
	if got := server.count(dns.TypeA); got != 1 {
		t.Errorf("A queries = %d, want 1", got)
	}
	if got := server.count(dns.TypeAAAA); got != 1 {
		t.Errorf("AAAA queries = %d, want 1", got)
	}
}

func TestStandardResolverResolveLiteralSkipsQuery(t *testing.T) {
	server := newDNSTestServer(t, func(dns.Question) []dns.RR {
		t.Error("resolver queried the server for an IP literal")
		return nil
	})
	result := testUDPResolver(t, server, time.Second).Resolve(context.Background(), "9.9.9.9")
	if got := ipString(result.IPv4); got != "9.9.9.9" {
		t.Errorf("IPv4 = %q, want 9.9.9.9", got)
	}
	if got := server.count(dns.TypeA); got != 0 {
		t.Errorf("A queries = %d, want 0", got)
	}
}

func TestStandardResolverResolveEmptyAnswer(t *testing.T) {
	server := newDNSTestServer(t, func(dns.Question) []dns.RR { return []dns.RR{} })
	result := testUDPResolver(t, server, time.Second).Resolve(context.Background(), "example.com")
	if !result.Empty() {
		t.Errorf("result = %+v, want empty", result)
	}
	if result.Err != nil {
		t.Errorf("Err = %v, want nil for an empty answer", result.Err)
	}
}

func TestStandardResolverSkipsCNAMEChainInPacket(t *testing.T) {
	// a -> b -> c arrives in one packet, so only c must be re-queried.
	server := newDNSTestServer(t, func(q dns.Question) []dns.RR {
		if q.Qtype != dns.TypeA {
			return []dns.RR{}
		}
		switch q.Name {
		case "a.example.":
			return []dns.RR{
				cnameRecord("a.example.", "b.example."),
				cnameRecord("b.example.", "c.example."),
			}
		case "c.example.":
			return []dns.RR{aRecord("c.example.", "1.2.3.4")}
		}
		return []dns.RR{}
	})

	r := testUDPResolver(t, server, time.Second)
	ip, err := r.lookup(context.Background(), "a.example", dns.TypeA, 0, make(map[string]struct{}))
	if err != nil {
		t.Fatalf("lookup() err = %v", err)
	}
	if ipString(ip) != "1.2.3.4" {
		t.Errorf("ip = %v, want 1.2.3.4", ip)
	}
	want := []string{"a.example.", "c.example."}
	if got := server.names(dns.TypeA); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("queries = %v, want %v", got, want)
	}
}

func TestStandardResolverAnswersWithCNAMEAndAddress(t *testing.T) {
	// CNAME first, then the address in the same packet: no second query.
	server := newDNSTestServer(t, func(q dns.Question) []dns.RR {
		if q.Qtype != dns.TypeA {
			return []dns.RR{}
		}
		return []dns.RR{
			cnameRecord(q.Name, "target.example."),
			aRecord("target.example.", "1.2.3.4"),
		}
	})

	r := testUDPResolver(t, server, time.Second)
	ip, err := r.lookup(context.Background(), "a.example", dns.TypeA, 0, make(map[string]struct{}))
	if err != nil {
		t.Fatalf("lookup() err = %v", err)
	}
	if ipString(ip) != "1.2.3.4" {
		t.Errorf("ip = %v, want 1.2.3.4", ip)
	}
	if got := server.count(dns.TypeA); got != 1 {
		t.Errorf("A queries = %d, want 1", got)
	}
}

func TestStandardResolverRejectsCNAMECycle(t *testing.T) {
	// Every question is answered with a CNAME pointing back at itself.
	server := newDNSTestServer(t, func(q dns.Question) []dns.RR {
		return []dns.RR{cnameRecord(q.Name, q.Name)}
	})

	r := testUDPResolver(t, server, time.Second)
	_, err := r.lookup(context.Background(), "loop.example", dns.TypeA, 0, make(map[string]struct{}))
	if !errors.Is(err, errCNAMEChainTooLong) {
		t.Fatalf("lookup() err = %v, want errCNAMEChainTooLong", err)
	}
	// The seen set must catch the cycle on the second visit, not the depth
	// counter 16 hops later.
	if got := server.count(dns.TypeA); got > 2 {
		t.Errorf("A queries = %d, want at most 2", got)
	}
}

func TestStandardResolverRetriesFailedLookup(t *testing.T) {
	var attempts int
	var mu sync.Mutex
	server := newDNSTestServer(t, func(q dns.Question) []dns.RR {
		if q.Qtype != dns.TypeA {
			return []dns.RR{}
		}
		mu.Lock()
		attempts++
		first := attempts == 1
		mu.Unlock()
		if first {
			return nil // drop the first attempt
		}
		return []dns.RR{aRecord(q.Name, "1.2.3.4")}
	})

	result := testUDPResolver(t, server, 200*time.Millisecond).Resolve(context.Background(), "example.com")
	if got := ipString(result.IPv4); got != "1.2.3.4" {
		t.Fatalf("IPv4 = %q, want 1.2.3.4 (the retry should succeed)", got)
	}
	if result.Err != nil {
		t.Errorf("Err = %v, want nil once the retry succeeded", result.Err)
	}
	if got := server.count(dns.TypeA); got != standardResolverRetryTimes {
		t.Errorf("A queries = %d, want %d", got, standardResolverRetryTimes)
	}
}

func TestStandardResolverErrorPrecedence(t *testing.T) {
	// A always times out, AAAA answers: the result keeps the AAAA address and
	// reports the A error.
	server := newDNSTestServer(t, func(q dns.Question) []dns.RR {
		if q.Qtype == dns.TypeAAAA {
			return []dns.RR{aaaaRecord(q.Name, "2001:db8::1")}
		}
		return nil
	})

	result := testUDPResolver(t, server, 100*time.Millisecond).Resolve(context.Background(), "example.com")
	if result.IPv4 != nil {
		t.Errorf("IPv4 = %v, want nil", result.IPv4)
	}
	if got := ipString(result.IPv6); got != "2001:db8::1" {
		t.Errorf("IPv6 = %q, want 2001:db8::1", got)
	}
	if result.Err == nil {
		t.Error("Err = nil, want the A lookup's timeout")
	}
	if result.Empty() {
		t.Error("Empty() = true, want the partial AAAA result to count")
	}
}

func TestStandardResolverContextCancel(t *testing.T) {
	server := newDNSTestServer(t, func(dns.Question) []dns.RR { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := testUDPResolver(t, server, 10*time.Second).Resolve(ctx, "example.com")
	if result.Err == nil {
		t.Error("Err = nil, want the cancelled context to abort the lookup")
	}
}

func TestStandardResolverConstructorAddrs(t *testing.T) {
	tests := []struct {
		name     string
		resolver Resolver
		wantAddr string
		wantNet  string
	}{
		{name: "udp default port", resolver: NewUDP("8.8.8.8", 0), wantAddr: "8.8.8.8:53", wantNet: ""},
		{name: "udp explicit port", resolver: NewUDP("8.8.4.4:5353", 0), wantAddr: "8.8.4.4:5353", wantNet: ""},
		{name: "tcp default port", resolver: NewTCP("8.8.8.8", 0), wantAddr: "8.8.8.8:53", wantNet: "tcp"},
		{name: "tls default port", resolver: NewTLS("1.1.1.1", 0, "", false), wantAddr: "1.1.1.1:853", wantNet: "tcp-tls"},
		{name: "tls explicit port", resolver: NewTLS("1.1.1.1:853", 0, "", false), wantAddr: "1.1.1.1:853", wantNet: "tcp-tls"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.resolver.(*standardResolver)
			if r.addr != tt.wantAddr {
				t.Errorf("addr = %q, want %q", r.addr, tt.wantAddr)
			}
			if r.client.Net != tt.wantNet {
				t.Errorf("client.Net = %q, want %q", r.client.Net, tt.wantNet)
			}
			if r.client.Timeout != resolverDefaultTimeout {
				t.Errorf("client.Timeout = %v, want %v", r.client.Timeout, resolverDefaultTimeout)
			}
		})
	}
}

func TestNewTLSConfiguresSNI(t *testing.T) {
	r := NewTLS("1.1.1.1", 5*time.Second, "cloudflare-dns.com", true).(*standardResolver)
	if r.client.TLSConfig.ServerName != "cloudflare-dns.com" {
		t.Errorf("ServerName = %q, want cloudflare-dns.com", r.client.TLSConfig.ServerName)
	}
	if !r.client.TLSConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true")
	}
	if r.client.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", r.client.Timeout)
	}
}

func TestSkipCNAMEChain(t *testing.T) {
	tests := []struct {
		name    string
		answers []dns.RR
		want    string
	}{
		{name: "empty", answers: nil, want: ""},
		{
			name:    "single",
			answers: []dns.RR{cnameRecord("a.", "b.")},
			want:    "b.",
		},
		{
			name: "chain collapses",
			answers: []dns.RR{
				cnameRecord("a.", "b."),
				cnameRecord("b.", "c."),
				cnameRecord("c.", "d."),
			},
			want: "d.",
		},
		{
			name: "unrelated cname stops the walk",
			answers: []dns.RR{
				cnameRecord("a.", "b."),
				cnameRecord("x.", "y."),
			},
			want: "b.",
		},
		{
			name:    "ignores address records",
			answers: []dns.RR{aRecord("a.", "1.2.3.4"), cnameRecord("a.", "b.")},
			want:    "b.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := skipCNAMEChain(tt.answers); got != tt.want {
				t.Errorf("skipCNAMEChain() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFirstAddress(t *testing.T) {
	tests := []struct {
		name         string
		answers      []dns.RR
		qtype        uint16
		wantIP       string
		wantHasCNAME bool
	}{
		{name: "no answers", qtype: dns.TypeA},
		{
			name:    "first a wins",
			answers: []dns.RR{aRecord("a.", "1.2.3.4"), aRecord("a.", "5.6.7.8")},
			qtype:   dns.TypeA,
			wantIP:  "1.2.3.4",
		},
		{
			name:    "aaaa for aaaa query",
			answers: []dns.RR{aaaaRecord("a.", "2001:db8::1")},
			qtype:   dns.TypeAAAA,
			wantIP:  "2001:db8::1",
		},
		{
			name:         "a ignored for aaaa query",
			answers:      []dns.RR{aRecord("a.", "1.2.3.4"), cnameRecord("a.", "b.")},
			qtype:        dns.TypeAAAA,
			wantHasCNAME: true,
		},
		{
			name:         "cname only",
			answers:      []dns.RR{cnameRecord("a.", "b.")},
			qtype:        dns.TypeA,
			wantHasCNAME: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, hasCNAME := firstAddress(tt.answers, tt.qtype)
			if got := ipString(ip); got != tt.wantIP {
				t.Errorf("ip = %q, want %q", got, tt.wantIP)
			}
			if hasCNAME != tt.wantHasCNAME {
				t.Errorf("hasCNAME = %v, want %v", hasCNAME, tt.wantHasCNAME)
			}
		})
	}
}
