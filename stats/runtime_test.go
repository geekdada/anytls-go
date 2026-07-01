package stats

import "time"

// waitClosed polls until the fake session is closed or a short deadline passes.
// Kick closes sessions in their own goroutine, so tests must wait for it rather
// than assume synchronous close.
func waitClosed(f *fakeSession) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f.closed.Load() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return f.closed.Load()
}
