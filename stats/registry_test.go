package stats

import (
	"sync"
	"sync/atomic"
	"testing"
)

type fakeSession struct {
	closed atomic.Bool
}

func (f *fakeSession) Close() error {
	f.closed.Store(true)
	return nil
}

func TestRegistryAttachDetach(t *testing.T) {
	r := NewRegistry()
	s1 := &fakeSession{}
	u := r.Attach("alice", "1.2.3.4:1", s1)
	u.AddTx(100)
	u.AddRx(50)

	if got := r.Online()["alice"]; got != 1 {
		t.Fatalf("online[alice] = %d, want 1", got)
	}
	if tr := r.Snapshot()["alice"]; tr.Tx != 100 || tr.Rx != 50 {
		t.Fatalf("snapshot[alice] = %+v, want {100 50}", tr)
	}

	r.Detach("alice", s1)
	if _, ok := r.Online()["alice"]; ok {
		t.Fatal("alice should no longer be online after detach")
	}
	if tr := r.Snapshot()["alice"]; tr.Tx != 100 || tr.Rx != 50 {
		t.Fatal("traffic should survive detach for billing continuity")
	}
}

func TestRegistryConcurrentAccounting(t *testing.T) {
	r := NewRegistry()
	const goroutines = 32
	const perGoroutine = 1000

	sessions := make([]*fakeSession, goroutines)
	stats := make([]*UserStat, goroutines)
	for i := range sessions {
		sessions[i] = &fakeSession{}
		stats[i] = r.Attach("alice", "x", sessions[i])
	}

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(u *UserStat) {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				u.AddTx(1)
				u.AddRx(2)
			}
		}(stats[i])
	}
	wg.Wait()

	tr := r.Snapshot()["alice"]
	if tr.Tx != int64(goroutines*perGoroutine) {
		t.Fatalf("tx = %d, want %d", tr.Tx, goroutines*perGoroutine)
	}
	if tr.Rx != int64(2*goroutines*perGoroutine) {
		t.Fatalf("rx = %d, want %d", tr.Rx, 2*goroutines*perGoroutine)
	}
	// All sessions share source IP "x", so they count as one online device.
	if got := r.Online()["alice"]; got != 1 {
		t.Fatalf("online = %d, want 1 (pooled sessions from one source IP = one device)", got)
	}

	for _, s := range sessions {
		r.Detach("alice", s)
	}
	if _, ok := r.Online()["alice"]; ok {
		t.Fatal("expected no online sessions after full detach")
	}
}

func TestRegistryKick(t *testing.T) {
	r := NewRegistry()
	a := &fakeSession{}
	b := &fakeSession{}
	r.Attach("alice", "x", a)
	r.Attach("bob", "y", b)

	closed := r.Kick([]string{"alice", "ghost"})
	if closed != 1 {
		t.Fatalf("kick closed = %d, want 1", closed)
	}
	// Close runs in a goroutine. Wait for it.
	if !waitClosed(a) {
		t.Fatal("alice's session was not closed")
	}
	if b.closed.Load() {
		t.Fatal("bob should not have been kicked")
	}
}

func TestRegistryClear(t *testing.T) {
	r := NewRegistry()
	live := &fakeSession{}
	offline := &fakeSession{}
	r.Attach("alice", "1.1.1.1:1", live).AddTx(100)
	off := r.Attach("bob", "2.2.2.2:2", offline)
	off.AddRx(200)
	r.Detach("bob", offline) // bob has history but no live session

	snap := r.Clear()
	if snap["alice"].Tx != 100 || snap["bob"].Rx != 200 {
		t.Fatalf("clear should return pre-clear snapshot, got %#v", snap)
	}

	// alice is live: kept but zeroed.
	after := r.Snapshot()
	if _, ok := after["bob"]; ok {
		t.Fatal("offline bob should be purged after clear")
	}
	if tr, ok := after["alice"]; !ok || tr.Tx != 0 || tr.Rx != 0 {
		t.Fatalf("live alice should be kept and zeroed, got %#v ok=%v", tr, ok)
	}

	// alice's live session is still kickable (UserStat pointer intact).
	if closed := r.Kick([]string{"alice"}); closed != 1 {
		t.Fatalf("alice should still be kickable, kicked %d", closed)
	}
}

func TestRegistryDumpStreams(t *testing.T) {
	r := NewRegistry()
	aliceConn := r.AcquireConn("alice", "1.1.1.1:1")
	s1 := r.TraceStream("alice", aliceConn.ID(), aliceConn.NextStreamID())
	s1.SetReqAddr("example.com:443")
	s1.AddTx(7)
	r.TraceStream("alice", aliceConn.ID(), aliceConn.NextStreamID())
	bobConn := r.AcquireConn("bob", "2.2.2.2:2")
	r.TraceStream("bob", bobConn.ID(), bobConn.NextStreamID())

	rows := r.DumpStreams()
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}

	// Sorted by (Auth, Connection, Stream): alice/1, alice/2, bob/1.
	if rows[0].Auth != "alice" || rows[0].Stream != 1 {
		t.Fatalf("row0 = %+v, want alice stream 1", rows[0])
	}
	if rows[0].ReqAddr != "example.com:443" || rows[0].Tx != 7 {
		t.Fatalf("row0 req/tx = %q/%d", rows[0].ReqAddr, rows[0].Tx)
	}
	if rows[0].State != "connect" {
		t.Fatalf("row0 state = %q, want connect", rows[0].State)
	}
	if rows[0].HookedReqAddr != "" {
		t.Fatalf("hooked addr should always be empty, got %q", rows[0].HookedReqAddr)
	}
	if rows[2].Auth != "bob" {
		t.Fatalf("last row = %+v, want bob", rows[2])
	}

	// Closing a stream removes it and marks it closed.
	r.UntraceStream(s1)
	if rows := r.DumpStreams(); len(rows) != 2 {
		t.Fatalf("after untrace rows = %d, want 2", len(rows))
	}
}
