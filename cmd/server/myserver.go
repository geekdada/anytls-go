package main

import (
	"crypto/tls"

	"anytls/auth"
	"anytls/limiter"
	"anytls/stats"
)

type myServer struct {
	tlsConfig *tls.Config
	auth      auth.Authenticator
	stats     *stats.Registry
	limits    *limiter.Registry
}

func NewMyServer(tlsConfig *tls.Config, a auth.Authenticator, reg *stats.Registry, lim *limiter.Registry) *myServer {
	return &myServer{
		tlsConfig: tlsConfig,
		auth:      a,
		stats:     reg,
		limits:    lim,
	}
}
