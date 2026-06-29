package auth

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// CachingAuthenticator wraps another Authenticator and remembers successful
// authentications for a bounded time, so repeat connections from the same
// credential skip the (potentially slow) backend call.
//
// Only positive results are cached: rejects and backend errors always fall
// through to the inner authenticator, so a freshly-authorized credential is
// admitted on its next connect and a backend outage is never masked by a
// cached failure.
type CachingAuthenticator struct {
	inner Authenticator
	cache *expirable.LRU[string, string] // authBlob -> id
}

// NewCachingAuthenticator wraps inner with a TTL+capacity bounded cache.
// ttl must be > 0 and size >= 1; callers gate on ttl > 0 before wrapping.
func NewCachingAuthenticator(inner Authenticator, ttl time.Duration, size int) *CachingAuthenticator {
	return &CachingAuthenticator{
		inner: inner,
		cache: expirable.NewLRU[string, string](size, nil, ttl),
	}
}

func (c *CachingAuthenticator) Authenticate(addr, authBlob string, tx int64) (string, bool, error) {
	if id, ok := c.cache.Get(authBlob); ok {
		return id, true, nil
	}
	id, ok, err := c.inner.Authenticate(addr, authBlob, tx)
	if ok && err == nil {
		c.cache.Add(authBlob, id)
	}
	return id, ok, err
}
