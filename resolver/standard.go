package resolver

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	// standardResolverRetryTimes is how many times each of the A and AAAA
	// lookups is attempted before giving up.
	standardResolverRetryTimes = 2
	// maxCNAMEDepth bounds how many CNAME hops are followed across packets.
	maxCNAMEDepth = 16
)

var errCNAMEChainTooLong = errors.New("CNAME chain too long")

// standardResolver talks to the configured DNS server over plain UDP, plain TCP
// or DNS-over-TLS, all of which miekg/dns handles through dns.Client.Net.
// TCP and TLS reuse connections through pool; UDP dials per query.
type standardResolver struct {
	addr   string
	client *dns.Client
	pool   *connPool
}

// NewUDP returns a resolver querying addr over plain UDP. A missing port
// defaults to 53, a zero timeout to 2s.
func NewUDP(addr string, timeout time.Duration) Resolver {
	return &standardResolver{
		addr:   addDefaultPort(addr),
		client: &dns.Client{Timeout: timeoutOrDefault(timeout)},
	}
}

// NewTCP returns a resolver querying addr over plain TCP. A missing port
// defaults to 53, a zero timeout to 2s.
func NewTCP(addr string, timeout time.Duration) Resolver {
	return &standardResolver{
		addr: addDefaultPort(addr),
		client: &dns.Client{
			Net:     "tcp",
			Timeout: timeoutOrDefault(timeout),
		},
		pool: newConnPool(),
	}
}

// NewTLS returns a DNS-over-TLS resolver. A missing port defaults to 853, a
// zero timeout to 2s. An empty sni leaves ServerName unset, so verification of
// an IP address literal only succeeds against a certificate with a matching IP
// SAN (or with insecure set).
func NewTLS(addr string, timeout time.Duration, sni string, insecure bool) Resolver {
	return &standardResolver{
		addr: addDefaultPortTLS(addr),
		client: &dns.Client{
			Net:     "tcp-tls",
			Timeout: timeoutOrDefault(timeout),
			TLSConfig: &tls.Config{
				ServerName:         sni,
				InsecureSkipVerify: insecure,
			},
		},
		pool: newConnPool(),
	}
}

// Resolve queries A and AAAA in parallel and keeps the first record of each.
func (r *standardResolver) Resolve(ctx context.Context, host string) Result {
	if result, ok := tryParseIP(host); ok {
		return result
	}
	return resolveParallel(func(qtype uint16) (net.IP, error) {
		return r.lookupWithRetry(ctx, host, qtype)
	})
}

func (r *standardResolver) lookupWithRetry(ctx context.Context, host string, qtype uint16) (net.IP, error) {
	var ip net.IP
	var err error
	for range standardResolverRetryTimes {
		ip, err = r.lookup(ctx, host, qtype, 0, make(map[string]struct{}))
		if err == nil {
			break
		}
	}
	return ip, err
}

// lookup issues one query, following CNAMEs across packets. depth and seen
// together bound the chain so a malicious or misconfigured server cannot make
// us loop forever.
func (r *standardResolver) lookup(ctx context.Context, host string, qtype uint16, depth int, seen map[string]struct{}) (net.IP, error) {
	if depth > maxCNAMEDepth {
		return nil, errCNAMEChainTooLong
	}
	key := strings.ToLower(dns.Fqdn(host))
	if _, ok := seen[key]; ok {
		return nil, errCNAMEChainTooLong
	}
	seen[key] = struct{}{}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), qtype)
	m.RecursionDesired = true
	resp, err := r.exchange(ctx, m)
	if err != nil {
		return nil, err
	}
	if len(resp.Answer) == 0 {
		return nil, nil
	}
	// A server may answer with both CNAME and address records in one packet.
	ip, hasCNAME := firstAddress(resp.Answer, qtype)
	if ip != nil || !hasCNAME {
		return ip, nil
	}
	return r.lookup(ctx, skipCNAMEChain(resp.Answer), qtype, depth+1, seen)
}

// firstAddress returns the first answer record matching qtype, and whether the
// answer contained a CNAME worth following instead.
func firstAddress(answers []dns.RR, qtype uint16) (net.IP, bool) {
	hasCNAME := false
	for _, answer := range answers {
		switch rr := answer.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				return rr.A.To4(), false
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				return rr.AAAA.To16(), false
			}
		case *dns.CNAME:
			hasCNAME = true
		}
	}
	return nil, hasCNAME
}

// skipCNAMEChain returns the last target of a CNAME chain delivered in a single
// packet, so a server answering
//
//	domain1.com. CNAME domain2.com.
//	domain2.com. CNAME domain3.com.
//
// makes us query domain3.com directly instead of domain2.com.
func skipCNAMEChain(answers []dns.RR) string {
	var lastCNAME string
	for _, answer := range answers {
		cname, ok := answer.(*dns.CNAME)
		if !ok {
			continue
		}
		if lastCNAME == "" || cname.Hdr.Name == lastCNAME {
			lastCNAME = cname.Target
		} else {
			return lastCNAME
		}
	}
	return lastCNAME
}
