package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	body := `listen: ":9000"
password: hunter2
auth:
  type: http
  http:
    url: http://backend/auth
    insecure: true
trafficStats:
  listen: ":9999"
  secret: s3cr3t
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":9000" || c.Password != "hunter2" {
		t.Fatalf("basic fields wrong: %#v", c)
	}
	if !c.UseHTTPAuth() {
		t.Fatal("expected UseHTTPAuth")
	}
	if c.Auth.HTTP.URL != "http://backend/auth" || !c.Auth.HTTP.Insecure {
		t.Fatalf("http auth fields wrong: %#v", c.Auth)
	}
	if !c.StatsEnabled() || c.TrafficStats.Secret != "s3cr3t" {
		t.Fatalf("trafficStats wrong: %#v", c.TrafficStats)
	}
}

func TestLoadFileEmpty(t *testing.T) {
	c, err := LoadFile("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen == "" {
		t.Fatal("default listen missing")
	}
	if c.UseHTTPAuth() || c.StatsEnabled() {
		t.Fatal("defaults should not enable optional features")
	}
}

func TestLoadFileMissing(t *testing.T) {
	if _, err := LoadFile("/nonexistent/path/server.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestAuthCacheTTL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	body := `auth:
  type: http
  http:
    url: http://b/auth
    cacheTTL: 60s
    cacheSize: 100
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ttl, err := c.AuthCacheTTL()
	if err != nil {
		t.Fatal(err)
	}
	if ttl != 60_000_000_000 { // 60s in ns
		t.Fatalf("ttl = %v, want 60s", ttl)
	}
	if c.Auth.HTTP.CacheSize != 100 {
		t.Fatalf("cacheSize = %d", c.Auth.HTTP.CacheSize)
	}
}

func TestAuthCacheTTLEmptyDisabled(t *testing.T) {
	c := Default()
	ttl, err := c.AuthCacheTTL()
	if err != nil || ttl != 0 {
		t.Fatalf("empty TTL should be (0, nil), got (%v, %v)", ttl, err)
	}
}

func TestAuthCacheTTLInvalidFailsLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	body := `auth:
  type: http
  http:
    url: http://b/auth
    cacheTTL: nonsense
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected load to fail on bad cacheTTL")
	}
}
