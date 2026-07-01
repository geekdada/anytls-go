package limiter

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestNewRegistryUnlimited(t *testing.T) {
	if r := NewRegistry(0, 0); r != nil {
		t.Fatal("both-zero limits should yield a nil registry")
	}
}

func TestAcquireSharesDeviceBuckets(t *testing.T) {
	r := NewRegistry(8000, 8000) // 1000 B/s each
	d1 := r.Acquire("user", "1.2.3.4:5000")
	d2 := r.Acquire("user", "1.2.3.4:6000") // same device, different port
	if d1 != d2 {
		t.Fatal("same auth+IP should share one Device")
	}
	d3 := r.Acquire("user", "9.9.9.9:5000") // different IP => different device
	if d3 == d1 {
		t.Fatal("different IP should be a distinct Device")
	}
	// Distinct auth => distinct device.
	if d4 := r.Acquire("other", "1.2.3.4:5000"); d4 == d1 {
		t.Fatal("different auth should be a distinct Device")
	}
}

func TestReleaseFreesOnLastRef(t *testing.T) {
	r := NewRegistry(8000, 0)
	d := r.Acquire("u", "1.1.1.1:1")
	_ = r.Acquire("u", "1.1.1.1:2") // refs = 2
	r.Release(d)
	r.mu.Lock()
	_, stillThere := r.devices[deviceKey{auth: "u", ip: "1.1.1.1"}]
	r.mu.Unlock()
	if !stillThere {
		t.Fatal("device should survive while a reference remains")
	}
	r.Release(d)
	r.mu.Lock()
	_, gone := r.devices[deviceKey{auth: "u", ip: "1.1.1.1"}]
	r.mu.Unlock()
	if gone {
		t.Fatal("device should be freed after last release")
	}
}

func TestWrapConnUnlimitedPassthrough(t *testing.T) {
	r := NewRegistry(8000, 0) // only up limited
	d := r.Acquire("u", "1.1.1.1:1")
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	// down is unlimited, so wrapping should still return a wrapper, but reads
	// must not be throttled. Verify a wrapped conn's down limiter is nil.
	wrapped := WrapConn(c1, d).(*limitedConn)
	if wrapped.down != nil {
		t.Fatal("down should be nil when unlimited")
	}
	if wrapped.up == nil {
		t.Fatal("up should be set when limited")
	}
}

func TestWrapConnBothUnlimitedReturnsOriginal(t *testing.T) {
	// A Device with both nil limiters (constructed manually) returns the conn.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if got := WrapConn(c1, &Device{}); got != c1 {
		t.Fatal("device with no limiters should return the original conn")
	}
}

func TestWriteThroughputIsThrottled(t *testing.T) {
	const bytesPerSec = 20000
	r := NewRegistry(bytesPerSec*8, 0) // up limit only
	d := r.Acquire("u", "1.1.1.1:1")

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	wrapped := WrapConn(server, d)

	// Drain the client end as fast as possible.
	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, client)
		close(done)
	}()

	// Write 60000 bytes; at 20000 B/s with a burst floor of 64 KiB the whole
	// payload fits in the initial burst, so instead assert the limiter's rate
	// is configured as expected and that a larger transfer takes time.
	payload := make([]byte, 200000) // > minBurst so throttling must kick in
	start := time.Now()
	go func() {
		wrapped.Write(payload)
		wrapped.Close()
	}()
	<-done
	elapsed := time.Since(start)

	// 200000 bytes at 20000 B/s, minus the 64 KiB burst, is roughly
	// (200000-65536)/20000 ~= 6.7s. Allow generous slack but require it to be
	// clearly throttled (well over 1s).
	if elapsed < 2*time.Second {
		t.Fatalf("expected throttling to slow the transfer, took %v", elapsed)
	}
}

func TestReadCappedToBurst(t *testing.T) {
	r := NewRegistry(0, 8000) // down limited, burst floored at minBurst
	d := r.Acquire("u", "1.1.1.1:1")
	c1, _ := net.Pipe()
	defer c1.Close()
	wrapped := WrapConn(c1, d).(*limitedConn)
	if wrapped.down.Burst() < minBurst {
		t.Fatalf("burst = %d, want >= %d", wrapped.down.Burst(), minBurst)
	}
}
