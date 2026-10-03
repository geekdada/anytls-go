package auth

import (
	"errors"
	"time"
)

// ErrBackendBusy is returned when no backend slot frees up within the wait.
var ErrBackendBusy = errors.New("auth backend busy")

// LimitedAuthenticator bounds concurrent calls into another Authenticator.
// Every handshake with an unseen credential reaches the backend, so without a
// bound an unauthenticated client can open connections faster than the
// backend answers and pile requests onto it. A call that cannot get a slot in
// time fails with ErrBackendBusy, which CachingAuthenticator does not cache.
type LimitedAuthenticator struct {
	inner Authenticator
	slots chan struct{}
	wait  time.Duration
}

// NewLimitedAuthenticator allows at most maxConcurrent calls into inner at
// once. A call waits up to wait for a free slot.
func NewLimitedAuthenticator(inner Authenticator, maxConcurrent int, wait time.Duration) *LimitedAuthenticator {
	return &LimitedAuthenticator{
		inner: inner,
		slots: make(chan struct{}, maxConcurrent),
		wait:  wait,
	}
}

func (l *LimitedAuthenticator) Authenticate(addr, authBlob string, tx int64) (string, bool, error) {
	timer := time.NewTimer(l.wait)
	defer timer.Stop()
	select {
	case l.slots <- struct{}{}:
	case <-timer.C:
		return "", false, ErrBackendBusy
	}
	defer func() { <-l.slots }()
	return l.inner.Authenticate(addr, authBlob, tx)
}
