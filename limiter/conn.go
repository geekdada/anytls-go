package limiter

import (
	"context"
	"net"

	"golang.org/x/time/rate"
)

// limitedConn wraps a net.Conn and throttles it against a device's token
// buckets. Reads are limited by the down bucket (client upload) and writes by
// the up bucket (client download). Backpressure propagates naturally: a slowed
// Read stalls the session recv loop, which slows the client via TCP flow
// control, and a slowed Write stalls the outbound copy.
type limitedConn struct {
	net.Conn
	up   *rate.Limiter
	down *rate.Limiter

	ctx    context.Context
	cancel context.CancelFunc
}

// WrapConn returns c throttled by d's buckets. When both directions are
// unlimited the original conn is returned unwrapped.
func WrapConn(c net.Conn, d *Device) net.Conn {
	if d == nil || (d.up == nil && d.down == nil) {
		return c
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &limitedConn{
		Conn:   c,
		up:     d.up,
		down:   d.down,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (c *limitedConn) Read(b []byte) (int, error) {
	if c.down != nil {
		// Cap the read so a single WaitN never exceeds the bucket's burst.
		if burst := c.down.Burst(); len(b) > burst {
			b = b[:burst]
		}
	}
	n, err := c.Conn.Read(b)
	if n > 0 && c.down != nil {
		if werr := c.down.WaitN(c.ctx, n); werr != nil {
			return n, err
		}
	}
	return n, err
}

func (c *limitedConn) Write(b []byte) (int, error) {
	if c.up == nil {
		return c.Conn.Write(b)
	}
	burst := c.up.Burst()
	written := 0
	for len(b) > 0 {
		chunk := len(b)
		if chunk > burst {
			chunk = burst
		}
		if err := c.up.WaitN(c.ctx, chunk); err != nil {
			return written, err
		}
		n, err := c.Conn.Write(b[:chunk])
		written += n
		if err != nil {
			return written, err
		}
		b = b[chunk:]
	}
	return written, nil
}

func (c *limitedConn) Close() error {
	c.cancel()
	return c.Conn.Close()
}
