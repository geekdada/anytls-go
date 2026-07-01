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
)

type Config struct {
	Listen        string             `yaml:"listen"`
	Password      string             `yaml:"password"`
	PaddingScheme string             `yaml:"padding-scheme"`
	TLS           TLSConfig          `yaml:"tls"`
	Auth          AuthConfig         `yaml:"auth"`
	TrafficStats  TrafficStatsConfig `yaml:"trafficStats"`
	Bandwidth     BandwidthConfig    `yaml:"bandwidth"`
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
	if err := c.ValidateTLS(); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	if err := c.ValidateAuth(); err != nil {
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

// StatsEnabled reports whether the traffic-stats HTTP API should be started.
func (c *Config) StatsEnabled() bool {
	return c.TrafficStats.Listen != ""
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
		return nil
	default:
		return fmt.Errorf("invalid auth.type %q", c.Auth.Type)
	}
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
