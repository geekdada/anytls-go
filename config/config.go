package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen         string             `yaml:"listen"`
	Password       string             `yaml:"password"`
	PaddingScheme  string             `yaml:"padding-scheme"`
	Auth           AuthConfig         `yaml:"auth"`
	TrafficStats   TrafficStatsConfig `yaml:"trafficStats"`
}

type AuthConfig struct {
	Type string         `yaml:"type"`
	HTTP HTTPAuthConfig `yaml:"http"`
}

type HTTPAuthConfig struct {
	URL      string `yaml:"url"`
	Insecure bool   `yaml:"insecure"`
	// CacheTTL caches successful auths for this duration (e.g. "60s") so
	// reconnects skip the backend. Empty or "0" disables caching.
	CacheTTL string `yaml:"cacheTTL"`
	// CacheSize bounds the number of cached entries (default 4096 when
	// caching is enabled).
	CacheSize int `yaml:"cacheSize"`
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
	return c, nil
}

// AuthCacheTTL parses the HTTP-auth cache TTL. An empty value means caching is
// disabled (returns 0).
func (c *Config) AuthCacheTTL() (time.Duration, error) {
	s := c.Auth.HTTP.CacheTTL
	if s == "" {
		return 0, nil
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

// UseHTTPAuth reports whether the operator has enabled external HTTP auth.
func (c *Config) UseHTTPAuth() bool {
	return c.Auth.Type == "http" && c.Auth.HTTP.URL != ""
}

// StatsEnabled reports whether the traffic-stats HTTP API should be started.
func (c *Config) StatsEnabled() bool {
	return c.TrafficStats.Listen != ""
}
