package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestAuthCacheTTLDefault(t *testing.T) {
	c := Default()
	ttl, err := c.AuthCacheTTL()
	if err != nil || ttl != 10*time.Second {
		t.Fatalf("empty TTL should default to 10s, got (%v, %v)", ttl, err)
	}
}

func TestAuthCacheTTLZeroDisables(t *testing.T) {
	c := Default()
	c.Auth.HTTP.CacheTTL = "0"
	ttl, err := c.AuthCacheTTL()
	if err != nil || ttl != 0 {
		t.Fatalf(`cacheTTL "0" should disable, got (%v, %v)`, ttl, err)
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

func TestAuthNegativeCacheTTLExplicit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	body := `auth:
  type: http
  http:
    url: http://b/auth
    cacheTTL: 60s
    negativeCacheTTL: 5s
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	neg, err := c.AuthNegativeCacheTTL()
	if err != nil {
		t.Fatal(err)
	}
	if neg != 5*time.Second {
		t.Fatalf("negTTL = %v, want 5s", neg)
	}
}

func TestAuthNegativeCacheTTLDerivedDefault(t *testing.T) {
	c := Default()
	c.Auth.HTTP.CacheTTL = "60s"
	neg, err := c.AuthNegativeCacheTTL()
	if err != nil || neg != 60*time.Second {
		t.Fatalf("derived default = (%v, %v), want 60s", neg, err)
	}
}

func TestAuthNegativeCacheTTLDefaultWithPositiveDefault(t *testing.T) {
	c := Default() // cacheTTL unset => 10s positive
	neg, err := c.AuthNegativeCacheTTL()
	if err != nil || neg != 60*time.Second {
		t.Fatalf("derived default = (%v, %v), want 60s", neg, err)
	}
}

func TestAuthNegativeCacheTTLDisabledWhenNoPositive(t *testing.T) {
	c := Default()
	c.Auth.HTTP.CacheTTL = "0"
	neg, err := c.AuthNegativeCacheTTL()
	if err != nil || neg != 0 {
		t.Fatalf("positive caching off => neg 0, got (%v, %v)", neg, err)
	}
}

func TestAuthNegativeCacheTTLExplicitZeroDisables(t *testing.T) {
	c := Default()
	c.Auth.HTTP.CacheTTL = "60s"
	c.Auth.HTTP.NegativeCacheTTL = "0"
	neg, err := c.AuthNegativeCacheTTL()
	if err != nil || neg != 0 {
		t.Fatalf(`negativeCacheTTL "0" should disable, got (%v, %v)`, neg, err)
	}
}

func TestAuthNegativeCacheTTLInvalidFailsLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	body := `auth:
  type: http
  http:
    url: http://b/auth
    cacheTTL: 60s
    negativeCacheTTL: nonsense
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected load to fail on bad negativeCacheTTL")
	}
}

func TestLoadFileTLS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	body := `listen: ":9000"
password: hunter2
tls:
  cert: /etc/ssl/server.crt
  key: /etc/ssl/server.key
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.TLSEnabled() {
		t.Fatal("expected TLSEnabled")
	}
	if c.TLS.Cert != "/etc/ssl/server.crt" || c.TLS.Key != "/etc/ssl/server.key" {
		t.Fatalf("tls fields wrong: %#v", c.TLS)
	}
}

func TestValidateTLSPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	body := `password: x
tls:
  cert: only.crt
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected load to fail when only tls.cert is set")
	}
}

func TestValidateTLSDefaultDisabled(t *testing.T) {
	c := Default()
	if c.TLSEnabled() {
		t.Fatal("default config should not enable TLS files")
	}
	if err := c.ValidateTLS(); err != nil {
		t.Fatal(err)
	}
}

func TestParseBandwidth(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"", 0},
		{"0", 0},
		{"100", 100},
		{"100bps", 100},
		{"100 b", 100},
		{"1kbps", 1000},
		{"1kb", 1000},
		{"1k", 1000},
		{"1 mbps", 1_000_000},
		{"5mb", 5_000_000},
		{"2m", 2_000_000},
		{"1gbps", 1_000_000_000},
		{"1 GB", 1_000_000_000},
		{"1g", 1_000_000_000},
		{"1tbps", 1_000_000_000_000},
		{"1TB", 1_000_000_000_000},
		{"3 T", 3_000_000_000_000},
	}
	for _, tc := range cases {
		got, err := parseBandwidth(tc.in)
		if err != nil {
			t.Fatalf("parseBandwidth(%q) error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("parseBandwidth(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseBandwidthInvalid(t *testing.T) {
	for _, in := range []string{"abc", "10xb", "mbps", "-5", "1.5mbps"} {
		if _, err := parseBandwidth(in); err == nil {
			t.Fatalf("parseBandwidth(%q) expected error", in)
		}
	}
}

func TestBandwidthLimits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	body := `password: x
bandwidth:
  up: 100 mbps
  down: 20mbps
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	up, down, err := c.BandwidthLimits()
	if err != nil {
		t.Fatal(err)
	}
	if up != 100_000_000 || down != 20_000_000 {
		t.Fatalf("limits = (%d, %d), want (100000000, 20000000)", up, down)
	}
}

func TestBandwidthLimitsInvalidFailsLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	body := `password: x
bandwidth:
  up: nonsense
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected load to fail on bad bandwidth.up")
	}
}
