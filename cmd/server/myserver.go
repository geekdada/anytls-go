package main

import (
	"crypto/tls"

	"anytls/acl"
	"anytls/auth"
	"anytls/limiter"
	"anytls/resolver"
	"anytls/stats"
)

type myServer struct {
	tlsConfig *tls.Config
	auth      auth.Authenticator
	stats     *stats.Registry
	limits    *limiter.Registry
	policy    *outboundPolicy
}

func NewMyServer(tlsConfig *tls.Config, a auth.Authenticator, reg *stats.Registry, lim *limiter.Registry, aclEngine *acl.Engine, res resolver.Resolver, blockPrivate bool) *myServer {
	return &myServer{
		tlsConfig: tlsConfig,
		auth:      a,
		stats:     reg,
		limits:    lim,
		policy:    newOutboundPolicy(aclEngine, res, blockPrivate),
	}
}
