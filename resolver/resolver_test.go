package resolver

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestTryParseIP(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		wantOK   bool
		wantIPv4 string
		wantIPv6 string
	}{
		{name: "ipv4", host: "1.2.3.4", wantOK: true, wantIPv4: "1.2.3.4"},
		{name: "ipv6", host: "2001:db8::1", wantOK: true, wantIPv6: "2001:db8::1"},
		{name: "ipv6 loopback", host: "::1", wantOK: true, wantIPv6: "::1"},
		{name: "domain", host: "example.com"},
		{name: "host port", host: "1.2.3.4:53"},
		{name: "empty", host: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := tryParseIP(tt.host)
			if ok != tt.wantOK {
				t.Fatalf("tryParseIP() ok = %v, want %v", ok, tt.wantOK)
			}
			if got := ipString(result.IPv4); got != tt.wantIPv4 {
				t.Errorf("IPv4 = %q, want %q", got, tt.wantIPv4)
			}
			if got := ipString(result.IPv6); got != tt.wantIPv6 {
				t.Errorf("IPv6 = %q, want %q", got, tt.wantIPv6)
			}
			// An IPv4 literal must come back in 4-byte form: acl's geoip
			// matcher compares raw bytes and misses a v4-in-v6 address.
			if tt.wantIPv4 != "" && len(result.IPv4) != net.IPv4len {
				t.Errorf("len(IPv4) = %d, want %d", len(result.IPv4), net.IPv4len)
			}
		})
	}
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func TestResultEmpty(t *testing.T) {
	ipv4 := net.IPv4(1, 2, 3, 4).To4()
	ipv6 := net.ParseIP("2001:db8::1")
	tests := []struct {
		name   string
		result Result
		want   bool
	}{
		{name: "zero", result: Result{}, want: true},
		{name: "error only", result: Result{Err: errors.New("boom")}, want: true},
		{name: "ipv4", result: Result{IPv4: ipv4}},
		{name: "ipv6", result: Result{IPv6: ipv6}},
		{name: "both", result: Result{IPv4: ipv4, IPv6: ipv6}},
		// A partial result with an error is normal: one family failed.
		{name: "ipv4 and error", result: Result{IPv4: ipv4, Err: errors.New("boom")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.Empty(); got != tt.want {
				t.Errorf("Empty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestError(t *testing.T) {
	if got := (Error{}).Error(); got != "resolve error" {
		t.Errorf("Error() = %q, want %q", got, "resolve error")
	}
	inner := errors.New("boom")
	wrapped := Error{Err: inner}
	if got := wrapped.Error(); got != "resolve error: boom" {
		t.Errorf("Error() = %q, want %q", got, "resolve error: boom")
	}
	if !errors.Is(wrapped, inner) {
		t.Error("errors.Is() = false, want the inner error to unwrap")
	}
}

func TestAddDefaultPort(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantUDP string
		wantTLS string
	}{
		{name: "bare ipv4", addr: "8.8.8.8", wantUDP: "8.8.8.8:53", wantTLS: "8.8.8.8:853"},
		{name: "ipv4 with port", addr: "8.8.8.8:5353", wantUDP: "8.8.8.8:5353", wantTLS: "8.8.8.8:5353"},
		{name: "bare ipv6", addr: "2001:4860:4860::8888", wantUDP: "[2001:4860:4860::8888]:53", wantTLS: "[2001:4860:4860::8888]:853"},
		{name: "ipv6 with port", addr: "[2001:db8::1]:53", wantUDP: "[2001:db8::1]:53", wantTLS: "[2001:db8::1]:53"},
		{name: "hostname", addr: "dns.example.com", wantUDP: "dns.example.com:53", wantTLS: "dns.example.com:853"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := addDefaultPort(tt.addr); got != tt.wantUDP {
				t.Errorf("addDefaultPort() = %q, want %q", got, tt.wantUDP)
			}
			if got := addDefaultPortTLS(tt.addr); got != tt.wantTLS {
				t.Errorf("addDefaultPortTLS() = %q, want %q", got, tt.wantTLS)
			}
		})
	}
}

func TestTimeoutOrDefault(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{name: "zero uses default", in: 0, want: resolverDefaultTimeout},
		{name: "negative uses default", in: -time.Second, want: resolverDefaultTimeout},
		{name: "explicit", in: 4 * time.Second, want: 4 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := timeoutOrDefault(tt.in); got != tt.want {
				t.Errorf("timeoutOrDefault() = %v, want %v", got, tt.want)
			}
		})
	}
}
