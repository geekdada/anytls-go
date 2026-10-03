package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestLoadFileAuthValidation(t *testing.T) {
	dir := t.TempDir()

	t.Run("http without url", func(t *testing.T) {
		path := filepath.Join(dir, "http-no-url.yaml")
		body := `password: hunter2
auth:
  type: http
`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFile(path); err == nil {
			t.Fatal("expected load to fail when auth.type http omits auth.http.url")
		}
	})

	t.Run("unknown auth type", func(t *testing.T) {
		path := filepath.Join(dir, "unknown-auth.yaml")
		body := `password: hunter2
auth:
  type: htpp
`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFile(path); err == nil {
			t.Fatal("expected load to fail on unrecognized auth.type")
		}
	})

	t.Run("http with url", func(t *testing.T) {
		path := filepath.Join(dir, "http-ok.yaml")
		body := `auth:
  type: http
  http:
    url: http://backend/auth
`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !c.UseHTTPAuth() {
			t.Fatal("expected UseHTTPAuth for valid http auth config")
		}
	})

	t.Run("password with password", func(t *testing.T) {
		path := filepath.Join(dir, "password-ok.yaml")
		body := `password: hunter2
auth:
  type: password
`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if c.UseHTTPAuth() {
			t.Fatal("password auth should not enable UseHTTPAuth")
		}
		if c.Password != "hunter2" {
			t.Fatalf("password = %q, want hunter2", c.Password)
		}
	})

	t.Run("empty auth block", func(t *testing.T) {
		path := filepath.Join(dir, "empty-auth.yaml")
		body := `password: hunter2
`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if c.UseHTTPAuth() {
			t.Fatal("empty auth block should not enable UseHTTPAuth")
		}
	})
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

func TestLoadFileACL(t *testing.T) {
	dir := t.TempDir()

	t.Run("inline rules", func(t *testing.T) {
		path := filepath.Join(dir, "acl-inline.yaml")
		body := `password: hunter2
acl:
  inline:
    - reject(geoip:cn)
    - direct(all)
  geoip: /data/geoip.dat
  geosite: /data/geosite.dat
  geoUpdateInterval: 24h
`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !c.ACLEnabled() {
			t.Fatal("expected ACLEnabled")
		}
		if len(c.ACL.Inline) != 2 {
			t.Fatalf("inline rules wrong: %#v", c.ACL)
		}
		iv, err := c.GeoUpdateInterval()
		if err != nil || iv != 24*time.Hour {
			t.Fatalf("geoUpdateInterval = (%v, %v), want 24h", iv, err)
		}
	})

	t.Run("file rules", func(t *testing.T) {
		path := filepath.Join(dir, "acl-file.yaml")
		body := `password: hunter2
acl:
  file: /etc/anytls/rules.acl
`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !c.ACLEnabled() || c.ACL.File != "/etc/anytls/rules.acl" {
			t.Fatalf("acl.file wrong: %#v", c.ACL)
		}
		iv, err := c.GeoUpdateInterval()
		if err != nil || iv != 0 {
			t.Fatalf("empty geoUpdateInterval should be 0, got (%v, %v)", iv, err)
		}
	})

	t.Run("file and inline conflict", func(t *testing.T) {
		path := filepath.Join(dir, "acl-both.yaml")
		body := `password: hunter2
acl:
  file: /etc/anytls/rules.acl
  inline:
    - direct(all)
`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFile(path); err == nil {
			t.Fatal("expected load to fail when both acl.file and acl.inline are set")
		}
	})

	t.Run("bad geoUpdateInterval", func(t *testing.T) {
		path := filepath.Join(dir, "acl-bad-geo.yaml")
		body := `password: hunter2
acl:
  inline:
    - direct(all)
  geoUpdateInterval: nonsense
`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFile(path); err == nil {
			t.Fatal("expected load to fail on bad geoUpdateInterval")
		}
	})

	t.Run("acl disabled by default", func(t *testing.T) {
		c := Default()
		if c.ACLEnabled() {
			t.Fatal("default config should not enable ACL")
		}
	})
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

// TestLoadFileResolver loads the resolver block exactly as documented, with
// every sub-block populated, and checks the selected one is read.
func TestLoadFileResolver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolver.yaml")
	body := `password: hunter2
resolver:
  type: udp
  tcp:
    addr: 8.8.8.8:53
    timeout: 4s
  udp:
    addr: 8.8.4.4:53
    timeout: 4s
  tls:
    addr: 1.1.1.1:853
    timeout: 10s
    sni: cloudflare-dns.com
    insecure: false
  https:
    addr: 1.1.1.1:443
    timeout: 10s
    sni: cloudflare-dns.com
    insecure: false
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.ResolverEnabled() {
		t.Fatal("expected ResolverEnabled")
	}
	if got := c.Resolver.Kind(); got != "udp" {
		t.Errorf("Kind() = %q, want udp", got)
	}
	if got := c.Resolver.Addr(); got != "8.8.4.4:53" {
		t.Errorf("Addr() = %q, want 8.8.4.4:53", got)
	}
	if c.Resolver.UDP.Timeout != 4*time.Second {
		t.Errorf("udp.timeout = %v, want 4s", c.Resolver.UDP.Timeout)
	}
	if c.Resolver.TCP.Addr != "8.8.8.8:53" || c.Resolver.TCP.Timeout != 4*time.Second {
		t.Errorf("tcp block wrong: %#v", c.Resolver.TCP)
	}
	if c.Resolver.TLS.Addr != "1.1.1.1:853" || c.Resolver.TLS.Timeout != 10*time.Second {
		t.Errorf("tls block wrong: %#v", c.Resolver.TLS)
	}
	if c.Resolver.TLS.SNI != "cloudflare-dns.com" || c.Resolver.TLS.Insecure {
		t.Errorf("tls sni/insecure wrong: %#v", c.Resolver.TLS)
	}
	if c.Resolver.HTTPS.Addr != "1.1.1.1:443" || c.Resolver.HTTPS.SNI != "cloudflare-dns.com" {
		t.Errorf("https block wrong: %#v", c.Resolver.HTTPS)
	}
}

func TestLoadFileResolverAddrPerType(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name     string
		body     string
		wantKind string
		wantAddr string
	}{
		{name: "udp", body: "resolver:\n  type: udp\n  udp:\n    addr: 8.8.4.4:53\n", wantKind: "udp", wantAddr: "8.8.4.4:53"},
		{name: "tcp", body: "resolver:\n  type: tcp\n  tcp:\n    addr: 8.8.8.8\n", wantKind: "tcp", wantAddr: "8.8.8.8"},
		{name: "tls", body: "resolver:\n  type: tls\n  tls:\n    addr: 1.1.1.1:853\n", wantKind: "tls", wantAddr: "1.1.1.1:853"},
		{name: "tcp-tls alias", body: "resolver:\n  type: tcp-tls\n  tls:\n    addr: 1.1.1.1\n", wantKind: "tcp-tls", wantAddr: "1.1.1.1"},
		{name: "https", body: "resolver:\n  type: https\n  https:\n    addr: 1.1.1.1:443\n", wantKind: "https", wantAddr: "1.1.1.1:443"},
		{name: "http alias", body: "resolver:\n  type: http\n  https:\n    addr: https://dns.google/dns-query\n", wantKind: "http", wantAddr: "https://dns.google/dns-query"},
		{name: "uppercase", body: "resolver:\n  type: UDP\n  udp:\n    addr: 8.8.4.4\n", wantKind: "udp", wantAddr: "8.8.4.4"},
		{name: "padded", body: "resolver:\n  type: \" tls \"\n  tls:\n    addr: 1.1.1.1\n", wantKind: "tls", wantAddr: "1.1.1.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".yaml")
			if err := os.WriteFile(path, []byte("password: hunter2\n"+tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := LoadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := c.Resolver.Kind(); got != tt.wantKind {
				t.Errorf("Kind() = %q, want %q", got, tt.wantKind)
			}
			if got := c.Resolver.Addr(); got != tt.wantAddr {
				t.Errorf("Addr() = %q, want %q", got, tt.wantAddr)
			}
			if !c.ResolverEnabled() {
				t.Error("expected ResolverEnabled")
			}
		})
	}
}

func TestLoadFileResolverSystemDisabled(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		body string
	}{
		{name: "absent", body: ""},
		{name: "empty type", body: "resolver:\n  type: \"\"\n"},
		{name: "system", body: "resolver:\n  type: system\n"},
		{name: "system uppercase", body: "resolver:\n  type: System\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".yaml")
			if err := os.WriteFile(path, []byte("password: hunter2\n"+tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := LoadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if c.ResolverEnabled() {
				t.Error("expected the system resolver to leave ResolverEnabled false")
			}
			if got := c.Resolver.Addr(); got != "" {
				t.Errorf("Addr() = %q, want empty", got)
			}
		})
	}
}

func TestLoadFileResolverValidation(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{name: "unknown type", body: "resolver:\n  type: doh\n", wantErr: `invalid resolver.type "doh"`},
		{name: "udp without addr", body: "resolver:\n  type: udp\n", wantErr: "resolver.udp.addr"},
		{name: "tcp without addr", body: "resolver:\n  type: tcp\n", wantErr: "resolver.tcp.addr"},
		{name: "tls without addr", body: "resolver:\n  type: tls\n", wantErr: "resolver.tls.addr"},
		{name: "https without addr", body: "resolver:\n  type: https\n", wantErr: "resolver.https.addr"},
		{name: "wrong block filled", body: "resolver:\n  type: tls\n  udp:\n    addr: 8.8.4.4:53\n", wantErr: "resolver.tls.addr"},
		{name: "negative timeout", body: "resolver:\n  type: udp\n  udp:\n    addr: 8.8.4.4:53\n    timeout: -4s\n", wantErr: "resolver.udp.timeout"},
		{name: "malformed timeout", body: "resolver:\n  type: udp\n  udp:\n    addr: 8.8.4.4:53\n    timeout: 4x\n", wantErr: "parse config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".yaml")
			if err := os.WriteFile(path, []byte("password: hunter2\n"+tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadFile(path)
			if err == nil {
				t.Fatalf("expected load to fail for %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadFileOutboundAllowPrivate(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		body string
		want bool
	}{
		{body: "password: hunter2\n", want: false},
		{body: "password: hunter2\noutbound:\n  allowPrivate: true\n", want: true},
	}
	for i, tt := range tests {
		path := filepath.Join(dir, fmt.Sprintf("outbound-%d.yaml", i))
		if err := os.WriteFile(path, []byte(tt.body), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if c.Outbound.AllowPrivate != tt.want {
			t.Errorf("case %d: AllowPrivate = %v, want %v", i, c.Outbound.AllowPrivate, tt.want)
		}
	}
}

func TestAuthMaxConcurrent(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	base := "auth:\n  type: http\n  http:\n    url: http://backend/auth\n"

	c, err := LoadFile(write("default.yaml", base))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.AuthMaxConcurrent(); got != defaultAuthMaxConcurrent {
		t.Errorf("default = %d, want %d", got, defaultAuthMaxConcurrent)
	}

	c, err = LoadFile(write("explicit.yaml", base+"    maxConcurrent: 8\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.AuthMaxConcurrent(); got != 8 {
		t.Errorf("explicit = %d, want 8", got)
	}

	if _, err := LoadFile(write("negative.yaml", base+"    maxConcurrent: -1\n")); err == nil {
		t.Error("expected a negative maxConcurrent to fail")
	}
}
