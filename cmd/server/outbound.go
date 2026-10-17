package main

import (
	"strings"

	"anytls/outbound"
)

// namedOutbound pairs an outbound with its configured name.
type namedOutbound struct {
	name     string
	outbound outbound.Outbound
}

// outboundMap builds the name lookup ACL rules and the default fallback use.
// Names are lowercased because rules match them case-insensitively. The
// built-ins fill only names the user has not defined, and default is the first
// configured entry, so rules written for the built-in names keep working
// without an outbounds list.
func outboundMap(entries []namedOutbound, direct outbound.Outbound) map[string]outbound.Outbound {
	outbounds := make(map[string]outbound.Outbound, len(entries)+3)
	for _, entry := range entries {
		outbounds[strings.ToLower(entry.name)] = entry.outbound
	}
	if _, ok := outbounds["direct"]; !ok {
		outbounds["direct"] = direct
	}
	if _, ok := outbounds["reject"]; !ok {
		outbounds["reject"] = outbound.Reject{}
	}
	if _, ok := outbounds["default"]; !ok {
		if len(entries) > 0 {
			outbounds["default"] = entries[0].outbound
		} else {
			outbounds["default"] = outbounds["direct"]
		}
	}
	return outbounds
}
