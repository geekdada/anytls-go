package config

import (
	"fmt"
	"os"

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
	return c, nil
}

// UseHTTPAuth reports whether the operator has enabled external HTTP auth.
func (c *Config) UseHTTPAuth() bool {
	return c.Auth.Type == "http" && c.Auth.HTTP.URL != ""
}

// StatsEnabled reports whether the traffic-stats HTTP API should be started.
func (c *Config) StatsEnabled() bool {
	return c.TrafficStats.Listen != ""
}
