package stats

import (
	"cmp"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Kickable is implemented by anything the stats API can disconnect — in
// practice, *proxy/session.Session. Keeping it as an interface lets stats
// avoid importing the session package (which would create an import cycle
// once the session package starts reporting traffic into the registry).
type Kickable interface {
	Close() error
}

// UserStat aggregates traffic and active sessions for one client id.
// Tx/Rx are touched on the hot path and are deliberately lock-free.
type UserStat struct {
	ID string

	Tx atomic.Int64
	Rx atomic.Int64

	mu       sync.Mutex
	sessions map[Kickable]*sessionInfo
}

type sessionInfo struct {
	remote  string
	started time.Time
}

// AddTx and AddRx satisfy the TrafficCounter contract that the session
// package's Identity field uses.
func (u *UserStat) AddTx(n int64) { u.Tx.Add(n) }
func (u *UserStat) AddRx(n int64) { u.Rx.Add(n) }

// Registry tracks per-id traffic + active sessions across the server.
type Registry struct {
	mu    sync.RWMutex
	users map[string]*UserStat
	now   func() time.Time

	streamMu sync.RWMutex
	streams  map[*StreamStats]struct{}

	deviceMu sync.Mutex
	devices  map[deviceKey]*Conn
}

func NewRegistry() *Registry {
	return &Registry{
		users:   make(map[string]*UserStat),
		now:     time.Now,
		streams: make(map[*StreamStats]struct{}),
		devices: make(map[deviceKey]*Conn),
	}
}

// deviceKey identifies one logical client device on the server. anytls has no
// device identity on the wire, so a device is inferred from its credential plus
// source IP — a single device's pooled TLS connections share a source IP and
// differ only in source port.
type deviceKey struct {
	auth string
	ip   string
}

// Conn is the per-device logical connection handle, the direct analog of a
// hysteria QUIC connection. Every pooled TLS session from the same device
// shares one Conn, so its id is the stable "connection" value in
// /dump/streams and streamSeq numbers the streams multiplexed under it
// (monotonic within the connection, like hysteria's per-connection stream ids).
type Conn struct {
	key       deviceKey
	id        uint32
	streamSeq atomic.Uint32
	refs      int // live sessions from this device; guarded by Registry.deviceMu
}

// ID is the device's connection identifier (the /dump/streams "connection").
func (c *Conn) ID() uint32 { return c.id }

// NextStreamID hands out the next monotonic stream number within this
// connection, so streams from different pooled sessions never collide.
func (c *Conn) NextStreamID() uint32 { return c.streamSeq.Add(1) }

// AcquireConn returns the logical connection for the device behind (authID,
// remoteAddr), creating it on first use and reference-counting it so concurrent
// pooled sessions from the same device share one connection id. Pair every call
// with ReleaseConn.
func (r *Registry) AcquireConn(authID, remoteAddr string) *Conn {
	key := deviceKey{auth: authID, ip: hostOnly(remoteAddr)}
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	c, ok := r.devices[key]
	if !ok {
		c = &Conn{key: key, id: r.freshConnID()}
		r.devices[key] = c
	}
	c.refs++
	return c
}

// ReleaseConn drops one reference to a device's connection, freeing it once the
// last session for that device disconnects. A later reconnect gets a fresh id,
// matching hysteria where a new connection gets a new id.
func (r *Registry) ReleaseConn(c *Conn) {
	if c == nil {
		return
	}
	r.deviceMu.Lock()
	defer r.deviceMu.Unlock()
	c.refs--
	if c.refs <= 0 {
		delete(r.devices, c.key)
	}
}

// freshConnID returns a random id unused by any live device. Random (like
// hysteria) avoids leaking the cumulative connection count; the caller holds
// deviceMu so the uniqueness check is race-free.
func (r *Registry) freshConnID() uint32 {
	for {
		id := rand.Uint32()
		inUse := false
		for _, c := range r.devices {
			if c.id == id {
				inUse = true
				break
			}
		}
		if !inUse {
			return id
		}
	}
}

// hostOnly strips the port from an "ip:port" address, falling back to the whole
// string if it has no port.
func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// TraceStream begins tracking a single stream and returns its stats record,
// which the caller installs on the stream so byte accounting flows in. authID
// is the user id, connID groups streams sharing one device connection (see
// Conn), streamID is the stream number within that connection. The record
// starts in the "connect" state.
func (r *Registry) TraceStream(authID string, connID, streamID uint32) *StreamStats {
	s := &StreamStats{
		authID:      authID,
		connID:      connID,
		streamID:    streamID,
		initialTime: r.now(),
		now:         r.now,
	}
	s.state.Store(int32(StreamStateConnecting))
	s.lastActive.Store(r.now().UnixNano())
	r.streamMu.Lock()
	r.streams[s] = struct{}{}
	r.streamMu.Unlock()
	return s
}

// UntraceStream stops tracking a stream (marking it closed first, matching
// hysteria's deferred close transition).
func (r *Registry) UntraceStream(s *StreamStats) {
	if s == nil {
		return
	}
	s.SetState(StreamStateClosed)
	r.streamMu.Lock()
	delete(r.streams, s)
	r.streamMu.Unlock()
}

// Attach records that a session belongs to id and returns the per-user stat
// counter to install on the session. The counter is stable across reconnects:
// the same id reuses the same *UserStat so Tx/Rx accumulate.
func (r *Registry) Attach(id, remote string, sess Kickable) *UserStat {
	r.mu.Lock()
	u, ok := r.users[id]
	if !ok {
		u = &UserStat{ID: id, sessions: make(map[Kickable]*sessionInfo)}
		r.users[id] = u
	}
	u.mu.Lock()
	u.sessions[sess] = &sessionInfo{remote: remote, started: r.now()}
	u.mu.Unlock()
	r.mu.Unlock()
	return u
}

// Detach removes a session from its user bucket. The UserStat itself is kept
// so traffic counters persist across reconnects.
func (r *Registry) Detach(id string, sess Kickable) {
	r.mu.RLock()
	u, ok := r.users[id]
	r.mu.RUnlock()
	if !ok {
		return
	}
	u.mu.Lock()
	delete(u.sessions, sess)
	u.mu.Unlock()
}

// TrafficEntry is the JSON shape of /traffic responses.
type TrafficEntry struct {
	Tx int64 `json:"tx"`
	Rx int64 `json:"rx"`
}

// Snapshot returns the current Tx/Rx for every known id.
func (r *Registry) Snapshot() map[string]TrafficEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]TrafficEntry, len(r.users))
	for id, u := range r.users {
		out[id] = TrafficEntry{Tx: u.Tx.Load(), Rx: u.Rx.Load()}
	}
	return out
}

// Clear resets cumulative counters and frees history for offline users,
// returning the pre-clear snapshot. It mirrors hysteria's GET
// /traffic?clear=true and is the only memory-management mechanism (there is no
// background sweeper, matching hysteria).
//
// Live sessions hold their *UserStat via Session.Identity, so entries with
// active sessions are kept and zeroed in place rather than deleted; deleting
// them would orphan the live counters and break kick. Offline entries are
// removed outright, bounding memory.
func (r *Registry) Clear() map[string]TrafficEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]TrafficEntry, len(r.users))
	for id, u := range r.users {
		u.mu.Lock()
		live := len(u.sessions)
		u.mu.Unlock()
		out[id] = TrafficEntry{Tx: u.Tx.Swap(0), Rx: u.Rx.Swap(0)}
		if live == 0 {
			delete(r.users, id)
		}
	}
	return out
}

// Online returns the number of online devices for each id that has at least one
// session connected right now. Sessions are deduplicated by source IP so a
// device's pool of TLS connections counts once — matching hysteria's /online,
// where one device keeps one (QUIC) connection. Ids with traffic history but no
// live sessions are omitted.
func (r *Registry) Online() map[string]int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]int)
	for id, u := range r.users {
		u.mu.Lock()
		ips := make(map[string]struct{}, len(u.sessions))
		for _, info := range u.sessions {
			ips[hostOnly(info.remote)] = struct{}{}
		}
		u.mu.Unlock()
		if len(ips) > 0 {
			out[id] = len(ips)
		}
	}
	return out
}

// Kick disconnects every session belonging to the supplied ids. It returns the
// number of sessions closed. Sessions are closed in their own goroutines so a
// slow Close() can't stall the caller (typically the HTTP handler).
func (r *Registry) Kick(ids []string) int {
	r.mu.RLock()
	var victims []Kickable
	for _, id := range ids {
		u, ok := r.users[id]
		if !ok {
			continue
		}
		u.mu.Lock()
		for s := range u.sessions {
			victims = append(victims, s)
		}
		u.mu.Unlock()
	}
	r.mu.RUnlock()

	for _, s := range victims {
		go s.Close()
	}
	return len(victims)
}

// DumpStreams returns one StreamEntry per live stream, sorted by
// (Auth, Connection, Stream) — identical ordering to hysteria 2.
func (r *Registry) DumpStreams() []StreamEntry {
	r.streamMu.RLock()
	entries := make([]StreamEntry, 0, len(r.streams))
	for s := range r.streams {
		entries = append(entries, s.entry())
	}
	r.streamMu.RUnlock()

	slices.SortFunc(entries, func(a, b StreamEntry) int {
		if c := cmp.Compare(a.Auth, b.Auth); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Connection, b.Connection); c != 0 {
			return c
		}
		return cmp.Compare(a.Stream, b.Stream)
	})
	return entries
}

// WriteStreamDump renders /dump/streams to w. When accept contains
// "text/plain" it emits hysteria's netstat-style table; otherwise the
// {"streams":[...]} JSON wrapper. Mirrors hysteria 2's getDumpStreams.
func (r *Registry) WriteStreamDump(w http.ResponseWriter, accept string) {
	entries := r.DumpStreams()
	if strings.Contains(accept, "text/plain") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, formatDumpStreamLine("State", "Auth", "Connection", "Stream",
			"Req-Addr", "Hooked-Req-Addr", "TX-Bytes", "RX-Bytes", "Lifetime", "Last-Active"))
		now := r.now()
		for _, e := range entries {
			fmt.Fprintln(w, e.line(now))
		}
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	wrapper := struct {
		Streams []StreamEntry `json:"streams"`
	}{entries}
	if err := json.NewEncoder(w).Encode(&wrapper); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
