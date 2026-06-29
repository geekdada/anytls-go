package stats

import (
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
}

func NewRegistry() *Registry {
	return &Registry{
		users: make(map[string]*UserStat),
		now:   time.Now,
	}
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
	r.mu.Unlock()

	u.mu.Lock()
	u.sessions[sess] = &sessionInfo{remote: remote, started: r.now()}
	u.mu.Unlock()
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

// Online returns the number of active sessions for each id that has at least
// one session connected right now. Ids with traffic history but no live
// sessions are omitted (matching hysteria's /online semantics).
func (r *Registry) Online() map[string]int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]int)
	for id, u := range r.users {
		u.mu.Lock()
		n := len(u.sessions)
		u.mu.Unlock()
		if n > 0 {
			out[id] = n
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

// SessionDump is the per-session row returned by /dump/streams.
type SessionDump struct {
	ID         string  `json:"id"`
	Remote     string  `json:"remote"`
	AgeSeconds float64 `json:"age_seconds"`
	Tx         int64   `json:"tx"`
	Rx         int64   `json:"rx"`
}

// DumpSessions returns one row per live session.
func (r *Registry) DumpSessions() []SessionDump {
	r.mu.RLock()
	defer r.mu.RUnlock()
	now := r.now()
	var out []SessionDump
	for id, u := range r.users {
		tx, rx := u.Tx.Load(), u.Rx.Load()
		u.mu.Lock()
		for _, info := range u.sessions {
			out = append(out, SessionDump{
				ID:         id,
				Remote:     info.remote,
				AgeSeconds: now.Sub(info.started).Seconds(),
				Tx:         tx,
				Rx:         rx,
			})
		}
		u.mu.Unlock()
	}
	return out
}
