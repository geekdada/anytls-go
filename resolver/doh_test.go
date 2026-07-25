package resolver

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNewHTTPSURL(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{name: "bare ip", addr: "1.1.1.1", want: "https://1.1.1.1/dns-query"},
		{name: "ip with port", addr: "1.1.1.1:443", want: "https://1.1.1.1:443/dns-query"},
		{name: "hostname", addr: "dns.google", want: "https://dns.google/dns-query"},
		{name: "full url", addr: "https://dns.google/dns-query", want: "https://dns.google/dns-query"},
		{name: "url with other path", addr: "https://doh.example/query", want: "https://doh.example/query"},
		{name: "bare ipv6", addr: "2001:db8::1", want: "https://[2001:db8::1]/dns-query"},
		{name: "bare ipv6 loopback", addr: "::1", want: "https://[::1]/dns-query"},
		{name: "bracketed ipv6", addr: "[2001:db8::1]", want: "https://[2001:db8::1]/dns-query"},
		{name: "bracketed ipv6 with port", addr: "[2001:db8::1]:443", want: "https://[2001:db8::1]:443/dns-query"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewHTTPS(tt.addr, 0, "", false).(*dohResolver)
			if r.url != tt.want {
				t.Errorf("url = %q, want %q", r.url, tt.want)
			}
			if r.client.Timeout != resolverDefaultTimeout {
				t.Errorf("Timeout = %v, want %v", r.client.Timeout, resolverDefaultTimeout)
			}
			// The URL must be usable: a bare IPv6 literal would otherwise make
			// url.Parse fail and every request with it.
			if _, err := url.Parse(r.url); err != nil {
				t.Errorf("url.Parse(%q) = %v, want it to parse", r.url, err)
			}
			if _, err := http.NewRequest(http.MethodPost, r.url, nil); err != nil {
				t.Errorf("NewRequest(%q) = %v, want no error", r.url, err)
			}
		})
	}
}

func TestBracketIPv6(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{name: "bare ipv6", addr: "2001:db8::1", want: "[2001:db8::1]"},
		{name: "loopback", addr: "::1", want: "[::1]"},
		{name: "already bracketed", addr: "[2001:db8::1]", want: "[2001:db8::1]"},
		{name: "bracketed with port", addr: "[2001:db8::1]:443", want: "[2001:db8::1]:443"},
		{name: "ipv4", addr: "1.1.1.1", want: "1.1.1.1"},
		{name: "ipv4 with port", addr: "1.1.1.1:443", want: "1.1.1.1:443"},
		{name: "v4 mapped v6", addr: "::ffff:1.1.1.1", want: "::ffff:1.1.1.1"},
		{name: "hostname", addr: "dns.google", want: "dns.google"},
		{name: "hostname with port", addr: "dns.google:443", want: "dns.google:443"},
		{name: "empty", addr: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bracketIPv6(tt.addr); got != tt.want {
				t.Errorf("bracketIPv6(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestNewHTTPSConfiguresTLS(t *testing.T) {
	r := NewHTTPS("1.1.1.1", 10*time.Second, "cloudflare-dns.com", true).(*dohResolver)
	tlsConfig := r.client.Transport.(*http.Transport).TLSClientConfig
	if tlsConfig.ServerName != "cloudflare-dns.com" {
		t.Errorf("ServerName = %q, want cloudflare-dns.com", tlsConfig.ServerName)
	}
	if !tlsConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true")
	}
	if r.client.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", r.client.Timeout)
	}
}

// dohTestServer serves DNS-over-HTTPS over plain HTTP, which is enough to
// exercise the message and header handling.
type dohTestServer struct {
	url string

	mu        sync.Mutex
	questions []dns.Question
}

// newDoHTestServer starts a test server. respond may tweak the reply or the
// HTTP framing before it is written; a nil answer means an empty answer section.
func newDoHTestServer(t *testing.T, answer func(q dns.Question) []dns.RR, tweak func(w http.ResponseWriter, reply *dns.Msg) bool) *dohTestServer {
	t.Helper()
	s := &dohTestServer{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", req.Method)
		}
		if got := req.Header.Get("Content-Type"); got != dohContentType {
			t.Errorf("request Content-Type = %q, want %q", got, dohContentType)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Error(err)
			return
		}
		var query dns.Msg
		if err := query.Unpack(body); err != nil {
			t.Errorf("unpack query: %v", err)
			return
		}
		if len(query.Question) == 0 {
			t.Error("query carried no question")
			return
		}
		q := query.Question[0]
		s.mu.Lock()
		s.questions = append(s.questions, q)
		s.mu.Unlock()

		reply := new(dns.Msg)
		reply.SetReply(&query)
		reply.Answer = answer(q)
		if tweak != nil && !tweak(w, reply) {
			return
		}
		wire, err := reply.Pack()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", dohContentType)
		_, _ = w.Write(wire)
	}))
	t.Cleanup(server.Close)
	s.url = server.URL
	return s
}

func (s *dohTestServer) count(qtype uint16) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, q := range s.questions {
		if q.Qtype == qtype {
			n++
		}
	}
	return n
}

// resolverFor points a DoH resolver at the test server's plain-HTTP URL.
func resolverFor(t *testing.T, server *dohTestServer) *dohResolver {
	t.Helper()
	r := NewHTTPS("1.1.1.1", time.Second, "", false).(*dohResolver)
	r.url = server.url
	return r
}

func TestDoHResolverResolve(t *testing.T) {
	server := newDoHTestServer(t, func(q dns.Question) []dns.RR {
		switch q.Qtype {
		case dns.TypeA:
			// Only the first record must be kept.
			return []dns.RR{aRecord(q.Name, "1.2.3.4"), aRecord(q.Name, "5.6.7.8")}
		case dns.TypeAAAA:
			return []dns.RR{aaaaRecord(q.Name, "2001:db8::1")}
		}
		return nil
	}, nil)

	result := resolverFor(t, server).Resolve(context.Background(), "example.com")
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
}

func TestDoHResolverDoesNotRetry(t *testing.T) {
	// Unlike the standard resolver, DoH makes exactly one attempt per family.
	server := newDoHTestServer(t, func(dns.Question) []dns.RR { return nil },
		func(w http.ResponseWriter, _ *dns.Msg) bool {
			w.WriteHeader(http.StatusInternalServerError)
			return false
		})

	result := resolverFor(t, server).Resolve(context.Background(), "example.com")
	if result.Err == nil {
		t.Fatal("Err = nil, want a non-200 error")
	}
	if got := server.count(dns.TypeA); got != 1 {
		t.Errorf("A requests = %d, want 1 (no retry)", got)
	}
	if got := server.count(dns.TypeAAAA); got != 1 {
		t.Errorf("AAAA requests = %d, want 1 (no retry)", got)
	}
}

func TestDoHResolverRejectsNon200(t *testing.T) {
	server := newDoHTestServer(t, func(dns.Question) []dns.RR { return nil },
		func(w http.ResponseWriter, _ *dns.Msg) bool {
			w.WriteHeader(http.StatusForbidden)
			return false
		})

	result := resolverFor(t, server).Resolve(context.Background(), "example.com")
	if result.Err == nil || !strings.Contains(result.Err.Error(), "non-200") {
		t.Errorf("Err = %v, want a non-200 error", result.Err)
	}
}

func TestDoHResolverRejectsWrongContentType(t *testing.T) {
	server := newDoHTestServer(t, func(dns.Question) []dns.RR { return nil },
		func(w http.ResponseWriter, reply *dns.Msg) bool {
			wire, err := reply.Pack()
			if err != nil {
				t.Error(err)
				return false
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write(wire)
			return false
		})

	result := resolverFor(t, server).Resolve(context.Background(), "example.com")
	if result.Err == nil || !strings.Contains(result.Err.Error(), "content-type") {
		t.Errorf("Err = %v, want a content-type error", result.Err)
	}
}

func TestDoHResolverAcceptsContentTypeParameters(t *testing.T) {
	// A server appending charset parameters is still serving DNS messages.
	server := newDoHTestServer(t, func(q dns.Question) []dns.RR {
		if q.Qtype == dns.TypeA {
			return []dns.RR{aRecord(q.Name, "1.2.3.4")}
		}
		return nil
	}, func(w http.ResponseWriter, reply *dns.Msg) bool {
		wire, err := reply.Pack()
		if err != nil {
			t.Error(err)
			return false
		}
		w.Header().Set("Content-Type", dohContentType+"; charset=utf-8")
		_, _ = w.Write(wire)
		return false
	})

	result := resolverFor(t, server).Resolve(context.Background(), "example.com")
	if got := ipString(result.IPv4); got != "1.2.3.4" {
		t.Errorf("IPv4 = %q, want 1.2.3.4 (err = %v)", got, result.Err)
	}
}

func TestDoHResolverRejectsRcode(t *testing.T) {
	server := newDoHTestServer(t, func(dns.Question) []dns.RR { return nil },
		func(w http.ResponseWriter, reply *dns.Msg) bool {
			reply.Rcode = dns.RcodeServerFailure
			return true
		})

	result := resolverFor(t, server).Resolve(context.Background(), "example.com")
	if result.Err == nil || !strings.Contains(result.Err.Error(), "SERVFAIL") {
		t.Errorf("Err = %v, want a SERVFAIL error", result.Err)
	}
}

func TestDoHResolverDoesNotFollowCNAME(t *testing.T) {
	// Parity with hysteria's tinydoh: a bare CNAME answer yields no address and
	// no error, and no second request is made.
	server := newDoHTestServer(t, func(q dns.Question) []dns.RR {
		return []dns.RR{cnameRecord(q.Name, "target.example.")}
	}, nil)

	result := resolverFor(t, server).Resolve(context.Background(), "example.com")
	if !result.Empty() {
		t.Errorf("result = %+v, want empty", result)
	}
	if result.Err != nil {
		t.Errorf("Err = %v, want nil", result.Err)
	}
	if got := server.count(dns.TypeA); got != 1 {
		t.Errorf("A requests = %d, want 1 (no CNAME chasing)", got)
	}
}

func TestDoHResolverLiteralSkipsRequest(t *testing.T) {
	server := newDoHTestServer(t, func(dns.Question) []dns.RR {
		t.Error("resolver issued a request for an IP literal")
		return nil
	}, nil)

	result := resolverFor(t, server).Resolve(context.Background(), "9.9.9.9")
	if got := ipString(result.IPv4); got != "9.9.9.9" {
		t.Errorf("IPv4 = %q, want 9.9.9.9", got)
	}
	if got := server.count(dns.TypeA); got != 0 {
		t.Errorf("A requests = %d, want 0", got)
	}
}

func TestIsDNSMessage(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{name: "exact", contentType: "application/dns-message", want: true},
		{name: "with charset", contentType: "application/dns-message; charset=utf-8", want: true},
		{name: "mixed case", contentType: "Application/DNS-Message", want: true},
		{name: "padded", contentType: " application/dns-message ", want: true},
		{name: "html", contentType: "text/html"},
		{name: "json", contentType: "application/dns-json"},
		{name: "empty", contentType: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDNSMessage(tt.contentType); got != tt.want {
				t.Errorf("isDNSMessage(%q) = %v, want %v", tt.contentType, got, tt.want)
			}
		})
	}
}
