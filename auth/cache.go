package auth

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// CachingAuthenticator wraps another Authenticator and remembers recent
// decisions for a bounded time, so repeat connections from the same credential
// skip the (potentially slow) backend call.
//
// It keeps two independent caches:
//   - positive (authBlob -> id): a valid credential is served from cache until
//     its TTL lapses.
//   - negative (set of authBlob): a rejected credential (ok=false, err=nil) is
//     remembered so a stale/revoked client that keeps auto-reconnecting stops
//     hammering the backend.
//
// Backend errors (err != nil) are never cached, so an outage is never masked
// and valid users aren't locked out. The two caches are separate so a flood
// of distinct bad blobs can't evict legitimate positive entries.
type CachingAuthenticator struct {
	inner Authenticator
	cache *expirable.LRU[string, string]   // authBlob -> id (positive)
	neg   *expirable.LRU[string, struct{}] // authBlob set (negative); nil when disabled
}

// NewCachingAuthenticator wraps inner with TTL+capacity bounded caches.
// ttl must be > 0 and size >= 1; callers gate on ttl > 0 before wrapping.
// negTTL <= 0 disables negative caching (rejects fall through as before).
func NewCachingAuthenticator(inner Authenticator, ttl time.Duration, size int, negTTL time.Duration) *CachingAuthenticator {
	c := &CachingAuthenticator{
		inner: inner,
		cache: expirable.NewLRU[string, string](size, nil, ttl),
	}
	// expirable.NewLRU treats a non-positive TTL as "never expire", which would
	// make a one-time rejection permanent. Only build the negative cache when a
	// positive TTL is configured, so the disabled path is a nil cache.
	if negTTL > 0 {
		c.neg = expirable.NewLRU[string, struct{}](size, nil, negTTL)
	}
	return c
}

func (c *CachingAuthenticator) Authenticate(addr, authBlob string, tx int64) (string, bool, error) {
	if id, ok := c.cache.Get(authBlob); ok {
		return id, true, nil
	}
	if c.neg != nil {
		if _, bad := c.neg.Get(authBlob); bad {
			return "", false, nil
		}
	}

	id, ok, err := c.inner.Authenticate(addr, authBlob, tx)
	switch {
	case err != nil:
		// never cache infrastructure failures
	case ok:
		c.cache.Add(authBlob, id)
	case c.neg != nil:
		c.neg.Add(authBlob, struct{}{}) // definitive rejection, remember briefly
	}
	return id, ok, err
}
