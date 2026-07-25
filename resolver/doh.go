package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	dohContentType = "application/dns-message"
	// dohMaxResponseSize bounds the response body; 64KB covers any DNS message.
	dohMaxResponseSize = 65536
)

// dohResolver queries a DNS-over-HTTPS endpoint (RFC 8484). Unlike
// standardResolver it neither retries nor follows CNAMEs across packets,
// matching hysteria's DoH behavior.
type dohResolver struct {
	url    string
	client *http.Client
}

// NewHTTPS returns a DNS-over-HTTPS resolver. addr may be a full URL or just a
// host[:port], in which case it becomes https://<addr>/dns-query. A zero
// timeout defaults to 2s.
func NewHTTPS(addr string, timeout time.Duration, sni string, insecure bool) Resolver {
	if !strings.HasPrefix(addr, "https://") {
		addr = fmt.Sprintf("https://%s/dns-query", bracketIPv6(addr))
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: insecure,
	}
	return &dohResolver{
		url: addr,
		client: &http.Client{
			Transport: transport,
			Timeout:   timeoutOrDefault(timeout),
		},
	}
}

func (r *dohResolver) Resolve(ctx context.Context, host string) Result {
	if result, ok := tryParseIP(host); ok {
		return result
	}
	return resolveParallel(func(qtype uint16) (net.IP, error) {
		return r.lookup(ctx, host, qtype)
	})
}

func (r *dohResolver) lookup(ctx context.Context, host string, qtype uint16) (net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), qtype)
	m.RecursionDesired = true
	wire, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to build dns query for host %s: %w", host, err)
	}
	body, err := r.exchange(ctx, wire, host)
	if err != nil {
		return nil, err
	}
	var resp dns.Msg
	if err := resp.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to parse dns response for host %s: %w", host, err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns query failed with %s for host %s", dns.RcodeToString[resp.Rcode], host)
	}
	// No CNAME chasing here, mirroring hysteria: a DoH server that answers with
	// a bare CNAME simply yields no address.
	ip, _ := firstAddress(resp.Answer, qtype)
	return ip, nil
}

// exchange POSTs the wire-format query and returns the raw response body.
func (r *dohResolver) exchange(ctx context.Context, wire []byte, host string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request for host %s: %w", host, err)
	}
	req.Header.Set("Content-Type", dohContentType)
	req.Header.Set("Accept", dohContentType)

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform http request for host %s: %w", host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non-200 status-code=%d for host %s", resp.StatusCode, host)
	}
	if contentType := resp.Header.Get("Content-Type"); !isDNSMessage(contentType) {
		return nil, fmt.Errorf("unexpected content-type=%s for host %s", contentType, host)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dohMaxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read http response body for host %s: %w", host, err)
	}
	return body, nil
}

// bracketIPv6 wraps a bare IPv6 literal in brackets so it is usable as a URL
// host. Without this, "2001:db8::1" would build "https://2001:db8::1/dns-query",
// which url.Parse rejects outright ("invalid port"), failing every request. The
// plain UDP/TCP/TLS resolvers get this for free from net.JoinHostPort.
func bracketIPv6(addr string) string {
	if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
		return "[" + addr + "]"
	}
	return addr
}

// isDNSMessage checks the response media type, ignoring any parameters some
// servers append (e.g. "application/dns-message; charset=utf-8").
func isDNSMessage(contentType string) bool {
	mediaType, _, _ := strings.Cut(contentType, ";")
	return strings.EqualFold(strings.TrimSpace(mediaType), dohContentType)
}
