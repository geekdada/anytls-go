package main

import (
	"testing"
	"time"

	"anytls/config"
)

func TestNewResolver(t *testing.T) {
	addr := config.ResolverAddrConfig{Addr: "8.8.4.4:53", Timeout: 4 * time.Second}
	tlsBlock := config.ResolverTLSConfig{Addr: "1.1.1.1:853", Timeout: 10 * time.Second, SNI: "cloudflare-dns.com"}

	tests := []struct {
		name    string
		cfg     config.ResolverConfig
		wantNil bool
		wantErr bool
	}{
		{name: "absent", cfg: config.ResolverConfig{}, wantNil: true},
		{name: "system", cfg: config.ResolverConfig{Type: "system"}, wantNil: true},
		{name: "system uppercase", cfg: config.ResolverConfig{Type: "SYSTEM"}, wantNil: true},
		{name: "udp", cfg: config.ResolverConfig{Type: "udp", UDP: addr}},
		{name: "tcp", cfg: config.ResolverConfig{Type: "tcp", TCP: addr}},
		{name: "tls", cfg: config.ResolverConfig{Type: "tls", TLS: tlsBlock}},
		{name: "tcp-tls alias", cfg: config.ResolverConfig{Type: "tcp-tls", TLS: tlsBlock}},
		{name: "https", cfg: config.ResolverConfig{Type: "https", HTTPS: tlsBlock}},
		{name: "http alias", cfg: config.ResolverConfig{Type: "http", HTTPS: tlsBlock}},
		{name: "unknown type", cfg: config.ResolverConfig{Type: "doh"}, wantNil: true, wantErr: true},
		{name: "missing addr", cfg: config.ResolverConfig{Type: "udp"}, wantNil: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := newResolver(&tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if (res == nil) != tt.wantNil {
				t.Fatalf("resolver = %v, wantNil %v", res, tt.wantNil)
			}
		})
	}
}
