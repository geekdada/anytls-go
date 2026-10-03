package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultAuthCacheTTL         = 10 * time.Second
	defaultAuthNegativeCacheTTL = 60 * time.Second
	defaultAuthMaxConcurrent    = 64
)

type Config struct {
	Listen        string             `yaml:"listen"`
	Password      string             `yaml:"password"`
	PaddingScheme string             `yaml:"padding-scheme"`
	TLS           TLSConfig          `yaml:"tls"`
	Auth          AuthConfig         `yaml:"auth"`
	ACL           ACLConfig          `yaml:"acl"`
	Resolver      ResolverConfig     `yaml:"resolver"`
	TrafficStats  TrafficStatsConfig `yaml:"trafficStats"`
	Bandwidth     BandwidthConfig    `yaml:"bandwidth"`
	Outbound      OutboundConfig     `yaml:"outbound"`
}

// OutboundConfig controls where clients may connect through the server.
type OutboundConfig struct {
	// AllowPrivate lets clients reach loopback, private, link-local, CGNAT and
	// multicast addresses. It is off by default so a proxy user cannot reach
	// the server's own services, its LAN or a cloud metadata endpoint.
	AllowPrivate bool `yaml:"allowPrivate"`
}

// ResolverConfig mirrors hysteria 2's resolver block: it selects the DNS server
// the node uses to resolve outbound destinations. Only the sub-block matching
// Type is read. An empty or "system" Type keeps resolution on the system
// resolver, which is only consulted when the ACL needs the destination IPs.
type ResolverConfig struct {
	Type  string             `yaml:"type"`
	TCP   ResolverAddrConfig `yaml:"tcp"`
	UDP   ResolverAddrConfig `yaml:"udp"`
	TLS   ResolverTLSConfig  `yaml:"tls"`
	HTTPS ResolverTLSConfig  `yaml:"https"`
}

// ResolverAddrConfig configures the plain UDP and TCP resolvers. A missing port
// in Addr defaults to 53; a zero Timeout defaults to 2s.
type ResolverAddrConfig struct {
	Addr    string        `yaml:"addr"`
	Timeout time.Duration `yaml:"timeout"`
}

// ResolverTLSConfig configures the DNS-over-TLS and DNS-over-HTTPS resolvers. A
// missing port in Addr defaults to 853 for TLS; for HTTPS, Addr may also be a
// full URL. SNI overrides the TLS server name, which matters when Addr is an IP
// literal. Insecure skips certificate verification.
type ResolverTLSConfig struct {
	Addr     string        `yaml:"addr"`
	Timeout  time.Duration `yaml:"timeout"`
	SNI      string        `yaml:"sni"`
	Insecure bool          `yaml:"insecure"`
}

// ACLConfig mirrors hysteria 2's acl block. Exactly one of File or Inline may
// be set. GeoIP/GeoSite are optional paths to v2ray .dat files; when empty the
// files are downloaded automatically (subject to GeoUpdateInterval).
type ACLConfig struct {
	File              string   `yaml:"file"`
	Inline            []string `yaml:"inline"`
	GeoIP             string   `yaml:"geoip"`
	GeoSite           string   `yaml:"geosite"`
	GeoUpdateInterval string   `yaml:"geoUpdateInterval"`
}

// BandwidthConfig caps the per-device transfer rate, matching hysteria 2's
// bandwidth block. Up is the rate the server sends to a client (the client's
// download); Down is what the server receives (the client's upload). An empty
// value or "0" means unlimited in that direction.
type BandwidthConfig struct {
	Up   string `yaml:"up"`
	Down string `yaml:"down"`
}

type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type AuthConfig struct {
	Type string         `yaml:"type"`
	HTTP HTTPAuthConfig `yaml:"http"`
}

type HTTPAuthConfig struct {
	URL      string `yaml:"url"`
	Insecure bool   `yaml:"insecure"`
	// CacheTTL caches successful auths for this duration (e.g. "60s") so
	// reconnects skip the backend. Empty uses defaultAuthCacheTTL; "0" disables.
	CacheTTL string `yaml:"cacheTTL"`
	// CacheSize bounds the number of cached entries (default 4096 when
	// caching is enabled).
	CacheSize int `yaml:"cacheSize"`
	// NegativeCacheTTL caches rejections (ok=false) for this duration so a
	// revoked client that keeps reconnecting stops hitting the backend. Empty
	// uses defaultAuthNegativeCacheTTL; "0" disables it. Backend errors are
	// never cached.
	NegativeCacheTTL string `yaml:"negativeCacheTTL"`
	// MaxConcurrent bounds in-flight backend calls (default 64). Every
	// handshake with an unseen credential reaches the backend, so this keeps
	// unauthenticated connection floods from piling requests onto it.
	MaxConcurrent int `yaml:"maxConcurrent"`
}

type TrafficStatsConfig struct {
	Listen string `yaml:"listen"`
	Secret string `yaml:"secret"`
}

func Default() *Config {
	return &Config{
		Listen: "0.0.0.0:8443",
	}
}

// LoadFile reads YAML from path. An empty path returns Default().
func LoadFile(path string) (*Config, error) {
	if path == "" {
		return Default(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	c := Default()
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if _, err := c.AuthCacheTTL(); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	if _, err := c.AuthNegativeCacheTTL(); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	if _, _, err := c.BandwidthLimits(); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	if _, err := c.GeoUpdateInterval(); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	if err := c.ValidateACL(); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	if err := c.ValidateTLS(); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	if err := c.ValidateAuth(); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	if err := c.ValidateResolver(); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	if err := c.ValidateStats(); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	return c, nil
}

// AuthCacheTTL parses the HTTP-auth positive cache TTL. An empty value uses
// defaultAuthCacheTTL; "0" disables caching.
func (c *Config) AuthCacheTTL() (time.Duration, error) {
	s := c.Auth.HTTP.CacheTTL
	if s == "" {
		return defaultAuthCacheTTL, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid auth.http.cacheTTL %q: %w", s, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("auth.http.cacheTTL %q must not be negative", s)
	}
	return d, nil
}

// AuthNegativeCacheTTL parses the negative-result (rejection) cache TTL. When
// unset it uses defaultAuthNegativeCacheTTL while positive caching is enabled.
// Returns 0 when positive caching is off or the value is "0".
func (c *Config) AuthNegativeCacheTTL() (time.Duration, error) {
	pos, err := c.AuthCacheTTL()
	if err != nil {
		return 0, err
	}
	s := c.Auth.HTTP.NegativeCacheTTL
	if s == "" {
		if pos <= 0 {
			return 0, nil // positive caching off => negative caching off
		}
		return defaultAuthNegativeCacheTTL, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid auth.http.negativeCacheTTL %q: %w", s, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("auth.http.negativeCacheTTL %q must not be negative", s)
	}
	return d, nil
}

// UseHTTPAuth reports whether the operator has enabled external HTTP auth.
func (c *Config) UseHTTPAuth() bool {
	return c.Auth.Type == "http" && c.Auth.HTTP.URL != ""
}

// AuthMaxConcurrent returns the in-flight backend call limit, applying the
// default when unset.
func (c *Config) AuthMaxConcurrent() int {
	if c.Auth.HTTP.MaxConcurrent <= 0 {
		return defaultAuthMaxConcurrent
	}
	return c.Auth.HTTP.MaxConcurrent
}

// ValidateStats requires a secret whenever the stats API is enabled. The API
// can kick users and lists every user's destinations.
func (c *Config) ValidateStats() error {
	if c.StatsEnabled() && c.TrafficStats.Secret == "" {
		return fmt.Errorf("trafficStats.secret is required when trafficStats.listen is set")
	}
	return nil
}

// StatsEnabled reports whether the traffic-stats HTTP API should be started.
func (c *Config) StatsEnabled() bool {
	return c.TrafficStats.Listen != ""
}

// ACLEnabled reports whether ACL rules are configured. File and Inline are
// mutually exclusive.
func (c *Config) ACLEnabled() bool {
	return c.ACL.File != "" || len(c.ACL.Inline) > 0
}

// ValidateACL ensures acl.file and acl.inline are not both set.
func (c *Config) ValidateACL() error {
	if c.ACL.File != "" && len(c.ACL.Inline) > 0 {
		return fmt.Errorf("cannot set both acl.file and acl.inline")
	}
	return nil
}

// GeoUpdateInterval parses acl.geoUpdateInterval. Empty means the loader
// default (7 days).
func (c *Config) GeoUpdateInterval() (time.Duration, error) {
	s := c.ACL.GeoUpdateInterval
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid acl.geoUpdateInterval %q: %w", s, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("acl.geoUpdateInterval %q must not be negative", s)
	}
	return d, nil
}

// TLSEnabled reports whether TLS certificate files are configured.
func (c *Config) TLSEnabled() bool {
	return c.TLS.Cert != "" && c.TLS.Key != ""
}

// ValidateAuth ensures auth.type and its dependent fields are consistent.
func (c *Config) ValidateAuth() error {
	switch c.Auth.Type {
	case "", "password":
		return nil
	case "http":
		if c.Auth.HTTP.URL == "" {
			return fmt.Errorf("auth.type http requires auth.http.url")
		}
		if c.Auth.HTTP.MaxConcurrent < 0 {
			return fmt.Errorf("auth.http.maxConcurrent %d must not be negative", c.Auth.HTTP.MaxConcurrent)
		}
		return nil
	default:
		return fmt.Errorf("invalid auth.type %q", c.Auth.Type)
	}
}

// Kind returns the normalized resolver.type. Hysteria matches it
// case-insensitively and accepts the aliases "tcp-tls" and "http", so do the
// same; "" and "system" both mean the system resolver.
func (r *ResolverConfig) Kind() string {
	return strings.ToLower(strings.TrimSpace(r.Type))
}

// Enabled reports whether a custom resolver is configured. The system case is
// not a resolver instance: it stays on net.DefaultResolver.
func (r *ResolverConfig) Enabled() bool {
	switch r.Kind() {
	case "", "system":
		return false
	default:
		return true
	}
}

// Addr returns the server address of the selected sub-block, "" for the system
// case.
func (r *ResolverConfig) Addr() string {
	switch r.Kind() {
	case "udp":
		return r.UDP.Addr
	case "tcp":
		return r.TCP.Addr
	case "tls", "tcp-tls":
		return r.TLS.Addr
	case "https", "http":
		return r.HTTPS.Addr
	default:
		return ""
	}
}

// Validate ensures resolver.type is known and the sub-block it selects is
// usable. Error messages carry hysteria's field names.
func (r *ResolverConfig) Validate() error {
	var field string
	var timeout time.Duration
	switch r.Kind() {
	case "", "system":
		return nil
	case "udp":
		field, timeout = "resolver.udp", r.UDP.Timeout
	case "tcp":
		field, timeout = "resolver.tcp", r.TCP.Timeout
	case "tls", "tcp-tls":
		field, timeout = "resolver.tls", r.TLS.Timeout
	case "https", "http":
		field, timeout = "resolver.https", r.HTTPS.Timeout
	default:
		return fmt.Errorf("invalid resolver.type %q", r.Type)
	}
	if r.Addr() == "" {
		return fmt.Errorf("%s.addr: empty resolver address", field)
	}
	if timeout < 0 {
		return fmt.Errorf("%s.timeout %v must not be negative", field, timeout)
	}
	return nil
}

// ResolverEnabled reports whether a custom resolver is configured.
func (c *Config) ResolverEnabled() bool {
	return c.Resolver.Enabled()
}

// ValidateResolver validates the resolver block.
func (c *Config) ValidateResolver() error {
	return c.Resolver.Validate()
}

// ValidateTLS ensures cert and key are both set or both omitted.
func (c *Config) ValidateTLS() error {
	hasCert := c.TLS.Cert != ""
	hasKey := c.TLS.Key != ""
	if hasCert != hasKey {
		return fmt.Errorf("tls.cert and tls.key must both be set or both be omitted")
	}
	return nil
}

var bandwidthRegex = regexp.MustCompile(`^(\d+)\s*([a-zA-Z]*)$`)

// parseBandwidth converts a hysteria-style bandwidth string (e.g. "100 mbps",
// "1gbps", "500kb") into bits per second. Empty or a zero value returns 0,
// meaning unlimited. A bare integer is treated as bits per second.
func parseBandwidth(s string) (uint64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, nil
	}
	m := bandwidthRegex.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid bandwidth %q", s)
	}
	v, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid bandwidth %q: %w", s, err)
	}
	switch m[2] {
	case "", "bps", "b":
		return v, nil
	case "kbps", "kb", "k":
		return v * 1000, nil
	case "mbps", "mb", "m":
		return v * 1000 * 1000, nil
	case "gbps", "gb", "g":
		return v * 1000 * 1000 * 1000, nil
	case "tbps", "tb", "t":
		return v * 1000 * 1000 * 1000 * 1000, nil
	default:
		return 0, fmt.Errorf("unsupported bandwidth unit %q", m[2])
	}
}

// BandwidthLimits parses the configured up/down caps into bits per second.
// A returned value of 0 means that direction is unlimited.
func (c *Config) BandwidthLimits() (up, down uint64, err error) {
	up, err = parseBandwidth(c.Bandwidth.Up)
	if err != nil {
		return 0, 0, fmt.Errorf("bandwidth.up: %w", err)
	}
	down, err = parseBandwidth(c.Bandwidth.Down)
	if err != nil {
		return 0, 0, fmt.Errorf("bandwidth.down: %w", err)
	}
	return up, down, nil
}
