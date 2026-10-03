package resolver

import (
	"context"
	"errors"
	"net"

	"github.com/miekg/dns"
)

// maxIdleDNSConns bounds the idle TCP/TLS connections kept per resolver.
const maxIdleDNSConns = 8

// connPool keeps idle TCP/TLS connections to the DNS server. Without it, every
// A and AAAA query pays a fresh TCP handshake, plus a TLS handshake for DoT.
// Each in-flight query owns its connection; queries are not pipelined.
type connPool struct {
	idle chan *dns.Conn
}

func newConnPool() *connPool {
	return &connPool{idle: make(chan *dns.Conn, maxIdleDNSConns)}
}

func (p *connPool) get() *dns.Conn {
	select {
	case conn := <-p.idle:
		return conn
	default:
		return nil
	}
}

func (p *connPool) put(conn *dns.Conn) {
	select {
	case p.idle <- conn:
	default:
		conn.Close()
	}
}

// exchange sends one query. UDP uses a fresh socket. TCP and TLS take an idle
// connection first, and fall back to a new one when the server has closed the
// idle connection in the meantime.
func (r *standardResolver) exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	if r.pool == nil {
		resp, _, err := r.client.ExchangeContext(ctx, m, r.addr)
		return resp, err
	}
	if conn := r.pool.get(); conn != nil {
		resp, err := r.exchangeOn(ctx, m, conn)
		if err == nil || isTimeout(err) || ctx.Err() != nil {
			return resp, err
		}
	}
	conn, err := r.client.DialContext(ctx, r.addr)
	if err != nil {
		return nil, err
	}
	return r.exchangeOn(ctx, m, conn)
}

// exchangeOn returns conn to the pool after a clean exchange and closes it on
// any error, so a late reply to a timed-out query is never read by the next
// one.
func (r *standardResolver) exchangeOn(ctx context.Context, m *dns.Msg, conn *dns.Conn) (*dns.Msg, error) {
	resp, _, err := r.client.ExchangeWithConnContext(ctx, m, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	r.pool.put(conn)
	return resp, nil
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
