package auth

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingAuth holds every call until release is closed and tracks the peak
// number of concurrent calls.
type blockingAuth struct {
	release chan struct{}
	active  atomic.Int64
	peak    atomic.Int64
}

func (b *blockingAuth) Authenticate(addr, authBlob string, tx int64) (string, bool, error) {
	n := b.active.Add(1)
	for {
		peak := b.peak.Load()
		if n <= peak || b.peak.CompareAndSwap(peak, n) {
			break
		}
	}
	<-b.release
	b.active.Add(-1)
	return "id", true, nil
}

func TestLimitedAuthenticatorBoundsConcurrency(t *testing.T) {
	inner := &blockingAuth{release: make(chan struct{})}
	l := NewLimitedAuthenticator(inner, 2, time.Second)

	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Authenticate("a", "b", 0)
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(inner.release)
	wg.Wait()

	if got := inner.peak.Load(); got != 2 {
		t.Fatalf("peak concurrent backend calls = %d, want 2", got)
	}
}

func TestLimitedAuthenticatorBusyAfterWait(t *testing.T) {
	inner := &blockingAuth{release: make(chan struct{})}
	defer close(inner.release)
	l := NewLimitedAuthenticator(inner, 1, 20*time.Millisecond)

	go l.Authenticate("a", "b", 0)
	time.Sleep(10 * time.Millisecond)

	_, ok, err := l.Authenticate("a", "b", 0)
	if ok || !errors.Is(err, ErrBackendBusy) {
		t.Fatalf("got (ok=%v, err=%v), want ErrBackendBusy", ok, err)
	}
}

func TestBusyErrorIsNotCached(t *testing.T) {
	inner := &fakeAuth{err: ErrBackendBusy}
	c := NewCachingAuthenticator(inner, time.Minute, 16, time.Minute)
	c.Authenticate("a", "blob", 0)
	inner.err, inner.ok, inner.id = nil, true, "alice"
	if id, ok, _ := c.Authenticate("a", "blob", 0); !ok || id != "alice" {
		t.Fatalf("got (%q, %v), want the retry to reach the backend", id, ok)
	}
}
