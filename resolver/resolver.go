// Package resolver implements the server-side custom DNS resolver, mirroring
// hysteria 2's resolver block: plain UDP, plain TCP, DNS-over-TLS and
// DNS-over-HTTPS. A resolver turns a destination hostname into at most one IPv4
// and one IPv6 address, which is exactly what acl.Engine.Lookup consumes and
// what the outbound path dials.
//
// The system/default case is deliberately not implemented here: when no
// resolver is configured the server keeps resolving through net.DefaultResolver
// (and only when the ACL needs the IPs), matching hysteria, which inserts no
// resolver stage at all in that case.
package resolver

import (
	"context"
	"errors"
	"net"
	"runtime/debug"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// resolverDefaultTimeout is applied when the config leaves timeout unset.
const resolverDefaultTimeout = 2 * time.Second

var errResolverPanic = errors.New("resolver panicked")

// Result is the outcome of one lookup. It mirrors hysteria's ResolveInfo: a
// lookup may yield an error and partial results at the same time, or neither an
// error nor any address (NXDOMAIN / empty answer).
type Result struct {
	IPv4 net.IP
	IPv6 net.IP
	Err  error
}

// Empty reports whether the lookup produced no usable address.
func (r Result) Empty() bool {
	return r.IPv4 == nil && r.IPv6 == nil
}

// Resolver resolves a hostname to at most one address of each family.
// Implementations must be safe for concurrent use.
type Resolver interface {
	Resolve(ctx context.Context, host string) Result
}

// Error wraps a resolution failure so callers can tell it apart from a dial
// error. Ported from hysteria's resolveError.
type Error struct {
	Err error
}

func (e Error) Error() string {
	if e.Err == nil {
		return "resolve error"
	}
	return "resolve error: " + e.Err.Error()
}

func (e Error) Unwrap() error {
	return e.Err
}

// tryParseIP short-circuits the lookup when the host is already a literal IP.
// The IPv4 form is normalized to 4 bytes: acl's geoipMatcher binary-searches
// its table with bytes.Compare and silently mismatches a 16-byte v4-in-v6
// address.
func tryParseIP(host string) (Result, bool) {
	ip := net.ParseIP(host)
	if ip == nil {
		return Result{}, false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return Result{IPv4: ip4}, true
	}
	return Result{IPv6: ip}, true
}

// resolveParallel runs the A and AAAA lookups concurrently and assembles the
// Result. The A lookup's error takes precedence over the AAAA one, and an error
// does not discard whatever the other family returned.
func resolveParallel(lookup func(qtype uint16) (net.IP, error)) Result {
	type lookupResult struct {
		ip  net.IP
		err error
	}
	run := func(qtype uint16) <-chan lookupResult {
		ch := make(chan lookupResult, 1)
		go func() {
			var res lookupResult
			// Always send, even on panic: otherwise the receive below blocks
			// forever and takes the request with it.
			defer func() {
				if r := recover(); r != nil {
					logrus.Errorln("[BUG]", r, string(debug.Stack()))
					res = lookupResult{err: errResolverPanic}
				}
				ch <- res
			}()
			res.ip, res.err = lookup(qtype)
		}()
		return ch
	}
	ch4, ch6 := run(dns.TypeA), run(dns.TypeAAAA)
	result4, result6 := <-ch4, <-ch6

	result := Result{IPv4: result4.ip, IPv6: result6.ip}
	if result4.err != nil {
		result.Err = result4.err
	} else if result6.err != nil {
		result.Err = result6.err
	}
	return result
}

// timeoutOrDefault applies resolverDefaultTimeout when timeout is unset.
func timeoutOrDefault(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return resolverDefaultTimeout
	}
	return timeout
}

// addDefaultPort appends the plain DNS port when addr carries none.
func addDefaultPort(addr string) string {
	return addPortIfMissing(addr, "53")
}

// addDefaultPortTLS appends the DNS-over-TLS port when addr carries none.
func addDefaultPortTLS(addr string) string {
	return addPortIfMissing(addr, "853")
}

func addPortIfMissing(addr, port string) string {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, port)
	}
	return addr
}
