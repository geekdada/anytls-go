package acl

import (
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestEngineLookup(t *testing.T) {
	rules := `
reject(all, udp/443)
reject(10.0.0.0/8)
default(8.8.8.8, udp/53, 1.1.1.1)
reject(suffix:bad.com)
direct(all)
`
	e, err := NewEngineFromString(rules, testOutbounds, &FileGeoLoader{})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		host       string
		ipv4, ipv6 net.IP
		proto      Protocol
		port       uint16
		wantAction testAction
		wantHijack net.IP
	}{
		{name: "quic blocked", host: "www.example.com", ipv4: net.ParseIP("93.184.216.34"), proto: ProtocolUDP, port: 443, wantAction: ActionReject},
		{name: "same host tcp allowed", host: "www.example.com", ipv4: net.ParseIP("93.184.216.34"), proto: ProtocolTCP, port: 443, wantAction: ActionDirect},
		{name: "cidr blocked", host: "", ipv4: net.ParseIP("10.1.2.3"), proto: ProtocolTCP, port: 80, wantAction: ActionReject},
		{name: "suffix blocked", host: "deep.bad.com", proto: ProtocolTCP, port: 443, wantAction: ActionReject},
		{name: "hijack dns", host: "", ipv4: net.ParseIP("8.8.8.8"), proto: ProtocolUDP, port: 53, wantAction: ActionDirect, wantHijack: net.ParseIP("1.1.1.1")},
		{name: "hijack rule port mismatch falls through", host: "", ipv4: net.ParseIP("8.8.8.8"), proto: ProtocolTCP, port: 53, wantAction: ActionDirect},
		{name: "catch all", host: "example.org", proto: ProtocolTCP, port: 1234, wantAction: ActionDirect},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, hijack := e.Lookup(tt.host, tt.ipv4, tt.ipv6, tt.proto, tt.port)
			if action != tt.wantAction {
				t.Errorf("Lookup() action = %v, want %v", action, tt.wantAction)
			}
			if !reflect.DeepEqual(hijack, tt.wantHijack) {
				t.Errorf("Lookup() hijack = %v, want %v", hijack, tt.wantHijack)
			}
		})
	}
}

func TestEngineNoMatchIsDirect(t *testing.T) {
	e, err := NewEngineFromString("reject(1.2.3.4)\n", testOutbounds, &FileGeoLoader{})
	if err != nil {
		t.Fatal(err)
	}
	action, hijack := e.Lookup("example.com", net.ParseIP("5.6.7.8"), nil, ProtocolTCP, 443)
	if action != ActionDirect || hijack != nil {
		t.Errorf("Lookup() = (%v, %v), want (direct, nil)", action, hijack)
	}
	action, _ = e.Lookup("", net.ParseIP("1.2.3.4"), nil, ProtocolTCP, 443)
	if action != ActionReject {
		t.Errorf("Lookup() = %v, want reject", action)
	}
}

func TestEngineLookupNoMatchUsesDefault(t *testing.T) {
	outbounds := map[string]testAction{"direct": ActionDirect, "default": "warp"}
	e, err := NewEngineFromString("direct(1.1.1.1)\n", outbounds, &FileGeoLoader{})
	if err != nil {
		t.Fatal(err)
	}
	ob, hijack := e.Lookup("example.org", nil, nil, ProtocolTCP, 443)
	if ob != "warp" || hijack != nil {
		t.Fatalf("Lookup() = (%q, %v), want (warp, nil)", ob, hijack)
	}
}

func TestNewEngineFromStringSyntaxError(t *testing.T) {
	_, err := NewEngineFromString("not a rule\n", testOutbounds, &FileGeoLoader{})
	if err == nil {
		t.Error("expected syntax error, got nil")
	}
}

func TestNewEngineFromStringRequiresDefault(t *testing.T) {
	outbounds := map[string]testAction{"direct": ActionDirect, "reject": ActionReject}
	_, err := NewEngineFromString("direct(all)\n", outbounds, &FileGeoLoader{})
	if err == nil || !strings.Contains(err.Error(), `no "default" outbound`) {
		t.Fatalf("err = %v, want a missing default error", err)
	}
}

func TestNewEngineFromStringRejectsNilDefault(t *testing.T) {
	outbounds := map[string]any{"direct": ActionDirect, "default": nil}
	_, err := NewEngineFromString("direct(all)\n", outbounds, &FileGeoLoader{})
	if err == nil || !strings.Contains(err.Error(), `no "default" outbound`) {
		t.Fatalf("err = %v, want a missing default error", err)
	}
}
