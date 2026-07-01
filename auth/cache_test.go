package auth

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAuth is a programmable inner authenticator that counts calls.
type fakeAuth struct {
	calls atomic.Int64
	id    string
	ok    bool
	err   error
}

func (f *fakeAuth) Authenticate(addr, authBlob string, tx int64) (string, bool, error) {
	f.calls.Add(1)
	return f.id, f.ok, f.err
}

func TestCacheHitsBackendOnce(t *testing.T) {
	inner := &fakeAuth{id: "alice", ok: true}
	c := NewCachingAuthenticator(inner, time.Minute, 16, 0)

	for i := 0; i < 3; i++ {
		id, ok, err := c.Authenticate("addr", "blob", 0)
		if id != "alice" || !ok || err != nil {
			t.Fatalf("call %d = (%q,%v,%v)", i, id, ok, err)
		}
	}
	if got := inner.calls.Load(); got != 1 {
		t.Fatalf("backend called %d times, want 1", got)
	}
}

func TestCacheDistinctBlobsAreSeparate(t *testing.T) {
	inner := &fakeAuth{id: "x", ok: true}
	c := NewCachingAuthenticator(inner, time.Minute, 16, 0)
	c.Authenticate("a", "blob1", 0)
	c.Authenticate("a", "blob2", 0)
	if got := inner.calls.Load(); got != 2 {
		t.Fatalf("backend called %d times, want 2", got)
	}
}

func TestCacheDoesNotCacheRejects(t *testing.T) {
	// negTTL=0 disables negative caching, so rejects fall through as before.
	inner := &fakeAuth{ok: false}
	c := NewCachingAuthenticator(inner, time.Minute, 16, 0)
	for i := 0; i < 3; i++ {
		if _, ok, _ := c.Authenticate("a", "blob", 0); ok {
			t.Fatal("expected reject")
		}
	}
	if got := inner.calls.Load(); got != 3 {
		t.Fatalf("rejects should not be cached: backend called %d times, want 3", got)
	}
}

func TestCacheDoesNotCacheErrors(t *testing.T) {
	inner := &fakeAuth{ok: false, err: errors.New("backend down")}
	c := NewCachingAuthenticator(inner, time.Minute, 16, 0)
	for i := 0; i < 3; i++ {
		c.Authenticate("a", "blob", 0)
	}
	if got := inner.calls.Load(); got != 3 {
		t.Fatalf("errors should not be cached: backend called %d times, want 3", got)
	}
}

func TestCacheExpiry(t *testing.T) {
	inner := &fakeAuth{id: "alice", ok: true}
	c := NewCachingAuthenticator(inner, 30*time.Millisecond, 16, 0)
	c.Authenticate("a", "blob", 0)
	c.Authenticate("a", "blob", 0)
	if got := inner.calls.Load(); got != 1 {
		t.Fatalf("within TTL: backend called %d times, want 1", got)
	}
	time.Sleep(60 * time.Millisecond)
	c.Authenticate("a", "blob", 0)
	if got := inner.calls.Load(); got != 2 {
		t.Fatalf("after TTL: backend called %d times, want 2", got)
	}
}

func TestCacheCapacityEviction(t *testing.T) {
	inner := &fakeAuth{id: "alice", ok: true}
	c := NewCachingAuthenticator(inner, time.Minute, 2, 0)
	// Fill beyond capacity; oldest entry should be evicted.
	c.Authenticate("a", "b1", 0)
	c.Authenticate("a", "b2", 0)
	c.Authenticate("a", "b3", 0) // evicts b1
	before := inner.calls.Load()
	c.Authenticate("a", "b1", 0) // b1 was evicted -> backend hit again
	if inner.calls.Load() != before+1 {
		t.Fatal("expected evicted entry to miss the cache")
	}
}

func TestNegativeCacheHitsBackendOnce(t *testing.T) {
	inner := &fakeAuth{ok: false}
	c := NewCachingAuthenticator(inner, time.Minute, 16, time.Minute)
	for i := 0; i < 3; i++ {
		if _, ok, err := c.Authenticate("a", "blob", 0); ok || err != nil {
			t.Fatalf("call %d = (ok=%v, err=%v), want rejected", i, ok, err)
		}
	}
	if got := inner.calls.Load(); got != 1 {
		t.Fatalf("reject should be cached: backend called %d times, want 1", got)
	}
}

func TestNegativeCacheExpiry(t *testing.T) {
	inner := &fakeAuth{ok: false}
	c := NewCachingAuthenticator(inner, time.Minute, 16, 30*time.Millisecond)
	c.Authenticate("a", "blob", 0)
	c.Authenticate("a", "blob", 0)
	if got := inner.calls.Load(); got != 1 {
		t.Fatalf("within negTTL: backend called %d times, want 1", got)
	}
	time.Sleep(60 * time.Millisecond)
	c.Authenticate("a", "blob", 0)
	if got := inner.calls.Load(); got != 2 {
		t.Fatalf("after negTTL: backend called %d times, want 2", got)
	}
}

func TestNegativeCacheDoesNotCacheErrors(t *testing.T) {
	// Negative caching is enabled, but a backend error must never be cached.
	inner := &fakeAuth{ok: false, err: errors.New("backend down")}
	c := NewCachingAuthenticator(inner, time.Minute, 16, time.Minute)
	for i := 0; i < 3; i++ {
		c.Authenticate("a", "blob", 0)
	}
	if got := inner.calls.Load(); got != 3 {
		t.Fatalf("errors must never be cached: backend called %d times, want 3", got)
	}
}

func TestNegativeFloodDoesNotEvictPositives(t *testing.T) {
	// A valid credential is cached, then a flood of DISTINCT bad blobs arrives.
	// Because negatives live in a separate cache, the positive entry survives.
	inner := &fakeAuth{}
	c := NewCachingAuthenticator(inner, time.Minute, 4, time.Minute)

	inner.id, inner.ok, inner.err = "alice", true, nil
	c.Authenticate("a", "good", 0) // caches positive
	base := inner.calls.Load()

	inner.id, inner.ok, inner.err = "", false, nil
	for i := 0; i < 100; i++ {
		c.Authenticate("a", fmt.Sprintf("bad-%d", i), 0) // distinct bad blobs
	}

	inner.id, inner.ok, inner.err = "alice", true, nil
	if id, ok, _ := c.Authenticate("a", "good", 0); id != "alice" || !ok {
		t.Fatalf("good = (%q, %v), want (alice, true)", id, ok)
	}
	if got := inner.calls.Load(); got != base+100 {
		t.Fatalf("positive should have survived the flood: extra backend calls %d, want 100", got-base)
	}
}
