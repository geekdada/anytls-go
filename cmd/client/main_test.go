package main

import "testing"

func TestNewTLSConfig(t *testing.T) {
	tests := []struct {
		name       string
		serverAddr string
		sni        string
		insecure   bool
		wantName   string
		wantSkip   bool
	}{
		{name: "verify uses server host", serverAddr: "example.com:443", wantName: "example.com"},
		{name: "verify uses sni", serverAddr: "1.2.3.4:443", sni: "real.example.com", wantName: "real.example.com"},
		{name: "insecure without sni sends none", serverAddr: "example.com:443", insecure: true, wantName: "127.0.0.1", wantSkip: true},
		{name: "insecure keeps sni", serverAddr: "example.com:443", sni: "cdn.example.com", insecure: true, wantName: "cdn.example.com", wantSkip: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTLSConfig(tt.serverAddr, tt.sni, tt.insecure)
			if c.ServerName != tt.wantName || c.InsecureSkipVerify != tt.wantSkip {
				t.Fatalf("got (ServerName %q, InsecureSkipVerify %v), want (%q, %v)",
					c.ServerName, c.InsecureSkipVerify, tt.wantName, tt.wantSkip)
			}
		})
	}
}
