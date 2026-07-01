// Package limiter provides hysteria-style per-device bandwidth throttling for
// the server. A device (auth id + source IP, the same identity the stats
// package infers) gets one pair of token buckets shared by all of its pooled
// TLS sessions, mirroring how hysteria limits one QUIC connection.
package limiter

import (
	"net"
	"sync"

	"golang.org/x/time/rate"
)

// minBurst is the floor for a bucket's burst size so a single frame (header +
// payload, up to ~64 KiB) always fits and never deadlocks a WaitN call.
const minBurst = 64 * 1024

// deviceKey identifies one logical client device, inferred from its credential
// plus source IP (anytls has no on-wire device identity).
type deviceKey struct {
	auth string
	ip   string
}

// Device holds the up/down token buckets shared by one device's sessions. A nil
// limiter in either direction means that direction is unlimited.
type Device struct {
	key  deviceKey
	up   *rate.Limiter
	down *rate.Limiter
	refs int // live sessions from this device; guarded by Registry.mu
}

// Up returns the send limiter (server -> client, the client's download) or nil
// when that direction is unlimited.
func (d *Device) Up() *rate.Limiter { return d.up }

// Down returns the receive limiter (client -> server, the client's upload) or
// nil when that direction is unlimited.
func (d *Device) Down() *rate.Limiter { return d.down }

// Registry mints and reference-counts per-device buckets. upBytes/downBytes are
// the caps in bytes per second (0 = unlimited); the same caps apply to every
// device.
type Registry struct {
	upBytes   uint64
	downBytes uint64

	mu      sync.Mutex
	devices map[deviceKey]*Device
}

// NewRegistry builds a Registry from bits-per-second limits (as parsed from the
// config). It returns nil when both directions are unlimited, letting callers
// skip wrapping entirely.
func NewRegistry(upBps, downBps uint64) *Registry {
	if upBps == 0 && downBps == 0 {
		return nil
	}
	return &Registry{
		upBytes:   upBps / 8,
		downBytes: downBps / 8,
		devices:   make(map[deviceKey]*Device),
	}
}

// Acquire returns the device bucket for (authID, remoteAddr), creating it on
// first use and reference-counting it so a device's concurrent pooled sessions
// share one pair of buckets. Pair every call with Release.
func (r *Registry) Acquire(authID, remoteAddr string) *Device {
	key := deviceKey{auth: authID, ip: hostOnly(remoteAddr)}
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devices[key]
	if !ok {
		d = &Device{
			key:  key,
			up:   newLimiter(r.upBytes),
			down: newLimiter(r.downBytes),
		}
		r.devices[key] = d
	}
	d.refs++
	return d
}

// Release drops one reference to a device's buckets, freeing them once the
// device's last session disconnects. A later reconnect starts with fresh
// buckets.
func (r *Registry) Release(d *Device) {
	if d == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	d.refs--
	if d.refs <= 0 {
		delete(r.devices, d.key)
	}
}

// newLimiter builds a token bucket at bytesPerSec, or nil when unlimited. Burst
// is one second of tokens, floored at minBurst.
func newLimiter(bytesPerSec uint64) *rate.Limiter {
	if bytesPerSec == 0 {
		return nil
	}
	burst := int(bytesPerSec)
	if burst < minBurst {
		burst = minBurst
	}
	return rate.NewLimiter(rate.Limit(bytesPerSec), burst)
}

// hostOnly strips the port from an "ip:port" address, falling back to the whole
// string if it has no port.
func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
