package stats

import (
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// StreamState mirrors hysteria 2's per-stream lifecycle. anytls never enters
// the "hook" state (it has no request-hook/ACL layer), but the full vocabulary
// is kept so the JSON "state" field uses identical strings to hysteria.
type StreamState int32

const (
	StreamStateInitial StreamState = iota
	StreamStateHooking
	StreamStateConnecting
	StreamStateEstablished
	StreamStateClosed
)

func (s StreamState) String() string {
	switch s {
	case StreamStateInitial:
		return "init"
	case StreamStateHooking:
		return "hook"
	case StreamStateConnecting:
		return "connect"
	case StreamStateEstablished:
		return "estab"
	case StreamStateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// StreamStats is the per-stream record backing /dump/streams. Its mutable
// fields are lock-free atomics so the data path (Read/Write byte accounting and
// state transitions) never blocks on the dump path. authID/connID/streamID and
// initialTime are write-once at construction.
//
// It satisfies the session package's TrafficCounter contract (AddTx/AddRx) so a
// server Stream reports its bytes straight into the matching record.
type StreamStats struct {
	authID      string
	connID      uint32
	streamID    uint32
	initialTime time.Time
	now         func() time.Time

	state      atomic.Int32
	reqAddr    atomic.Pointer[string]
	tx         atomic.Int64
	rx         atomic.Int64
	lastActive atomic.Int64 // unix nanos
}

func (s *StreamStats) AddTx(n int64) {
	s.tx.Add(n)
	s.touch()
}

func (s *StreamStats) AddRx(n int64) {
	s.rx.Add(n)
	s.touch()
}

func (s *StreamStats) touch() { s.lastActive.Store(s.now().UnixNano()) }

// SetState records a lifecycle transition (connect/estab/closed).
func (s *StreamStats) SetState(st StreamState) { s.state.Store(int32(st)) }

// SetReqAddr records the client's requested target address.
func (s *StreamStats) SetReqAddr(addr string) { s.reqAddr.Store(&addr) }

func (s *StreamStats) entry() StreamEntry {
	reqAddr := ""
	if p := s.reqAddr.Load(); p != nil {
		reqAddr = *p
	}
	last := time.Unix(0, s.lastActive.Load())
	return StreamEntry{
		State:      StreamState(s.state.Load()).String(),
		Auth:       s.authID,
		Connection: s.connID,
		Stream:     uint64(s.streamID),
		ReqAddr:    reqAddr,
		// anytls has no request hook, so the hooked address is always empty —
		// the honest value, matching hysteria when no hook rewrites the address.
		HookedReqAddr:  "",
		Tx:             s.tx.Load(),
		Rx:             s.rx.Load(),
		InitialAt:      s.initialTime.Format(time.RFC3339Nano),
		LastActiveAt:   last.Format(time.RFC3339Nano),
		initialTime:    s.initialTime,
		lastActiveTime: last,
	}
}

// StreamEntry is one row of /dump/streams, JSON-shaped identically to
// hysteria 2's dumpStreamEntry. The trailing unexported times back the
// text/plain duration columns and are not marshaled.
type StreamEntry struct {
	State string `json:"state"`

	Auth       string `json:"auth"`
	Connection uint32 `json:"connection"`
	Stream     uint64 `json:"stream"`

	ReqAddr       string `json:"req_addr"`
	HookedReqAddr string `json:"hooked_req_addr"`

	Tx int64 `json:"tx"`
	Rx int64 `json:"rx"`

	InitialAt    string `json:"initial_at"`
	LastActiveAt string `json:"last_active_at"`

	initialTime    time.Time
	lastActiveTime time.Time
}

// line renders the text/plain (netstat-style) row, replicating hysteria 2's
// dumpStreamEntry.String() exactly — including its column layout.
func (e StreamEntry) line(now time.Time) string {
	state := strings.ToUpper(e.State)
	connection := fmt.Sprintf("%08X", e.Connection)
	stream := strconv.FormatUint(e.Stream, 10)
	reqAddr := e.ReqAddr
	if reqAddr == "" {
		reqAddr = "-"
	}
	hookedReqAddr := e.HookedReqAddr
	if hookedReqAddr == "" {
		hookedReqAddr = "-"
	}
	tx := strconv.FormatInt(e.Tx, 10)
	rx := strconv.FormatInt(e.Rx, 10)
	return formatDumpStreamLine(state, e.Auth, connection, stream, reqAddr, hookedReqAddr,
		tx, rx, roundLifetime(now.Sub(e.initialTime)).String(), roundLifetime(now.Sub(e.lastActiveTime)).String())
}

func roundLifetime(d time.Duration) time.Duration {
	if d < 10*time.Minute {
		return d.Round(time.Millisecond)
	}
	return d.Round(time.Second)
}

// formatDumpStreamLine matches hysteria 2 byte-for-byte. Note the argument
// order fed to Sprintf intentionally differs from the parameter list (a quirk
// carried over verbatim from hysteria so the output is identical): the printed
// columns are state, auth, connection, stream, tx, rx, lifetime, last-active,
// req-addr, hooked-req-addr.
func formatDumpStreamLine(state, auth, connection, stream, reqAddr, hookedReqAddr, tx, rx, lifetime, lastActive string) string {
	return fmt.Sprintf("%-8s %-12s %12s %8s %12s %12s %12s %12s %-16s %s",
		state, auth, connection, stream, tx, rx, lifetime, lastActive, reqAddr, hookedReqAddr)
}
