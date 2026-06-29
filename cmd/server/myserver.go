package main

import (
	"crypto/tls"

	"anytls/auth"
	"anytls/stats"
)

type myServer struct {
	tlsConfig *tls.Config
	auth      auth.Authenticator
	stats     *stats.Registry
}

func NewMyServer(tlsConfig *tls.Config, a auth.Authenticator, reg *stats.Registry) *myServer {
	return &myServer{
		tlsConfig: tlsConfig,
		auth:      a,
		stats:     reg,
	}
}
