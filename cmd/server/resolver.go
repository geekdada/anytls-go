package main

import (
	"fmt"

	"anytls/config"
	"anytls/resolver"
)

// newResolver builds the resolver selected by resolver.type, mirroring
// hysteria's switch. It returns (nil, nil) for the system/absent case, where
// resolution stays on net.DefaultResolver and is only performed when the ACL
// needs the destination IPs.
func newResolver(c *config.ResolverConfig) (resolver.Resolver, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	switch c.Kind() {
	case "", "system":
		return nil, nil
	case "udp":
		return resolver.NewUDP(c.UDP.Addr, c.UDP.Timeout), nil
	case "tcp":
		return resolver.NewTCP(c.TCP.Addr, c.TCP.Timeout), nil
	case "tls", "tcp-tls":
		return resolver.NewTLS(c.TLS.Addr, c.TLS.Timeout, c.TLS.SNI, c.TLS.Insecure), nil
	case "https", "http":
		return resolver.NewHTTPS(c.HTTPS.Addr, c.HTTPS.Timeout, c.HTTPS.SNI, c.HTTPS.Insecure), nil
	default:
		return nil, fmt.Errorf("unsupported resolver.type %q", c.Type)
	}
}
