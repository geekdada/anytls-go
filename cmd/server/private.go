package main

import "net/netip"

// nonPublicPrefixes covers the ranges netip.Addr has no predicate for.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	// Shared address space (RFC 6598). Some clouds serve instance metadata
	// from it, e.g. Alibaba Cloud at 100.100.100.200.
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("255.255.255.255/32"),
}

// isPrivateAddr reports whether addr points at the server itself, its local
// network or a cloud metadata service rather than the public internet.
func isPrivateAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() ||
		addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return true
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
