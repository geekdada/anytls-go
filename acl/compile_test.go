package acl

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	"anytls/acl/v2geo"
)

var _ GeoLoader = (*testGeoLoader)(nil)

type testGeoLoader struct{}

func (l *testGeoLoader) LoadGeoIP() (map[string]*v2geo.GeoIP, error) {
	return v2geo.LoadGeoIP("v2geo/geoip.dat")
}

func (l *testGeoLoader) LoadGeoSite() (map[string]*v2geo.GeoSite, error) {
	return v2geo.LoadGeoSite("v2geo/geosite.dat")
}

func TestCompile(t *testing.T) {
	rules := []TextRule{
		{
			Outbound:      "direct",
			Address:       "1.2.3.4",
			ProtoPort:     "",
			HijackAddress: "",
		},
		{
			Outbound:      "reject",
			Address:       "8.8.8.0/24",
			ProtoPort:     "*",
			HijackAddress: "1.1.1.1",
		},
		{
			Outbound:      "reject",
			Address:       "all",
			ProtoPort:     "udp/443",
			HijackAddress: "",
		},
		{
			Outbound:      "direct",
			Address:       "2606:4700::6810:85e5",
			ProtoPort:     "tcp",
			HijackAddress: "2606:4700::6810:85e6",
		},
		{
			Outbound:      "reject",
			Address:       "2606:4700::/44",
			ProtoPort:     "*/8888",
			HijackAddress: "",
		},
		{
			Outbound:      "reject",
			Address:       "*.v2ex.com",
			ProtoPort:     "udp",
			HijackAddress: "",
		},
		{
			Outbound:      "direct",
			Address:       "crap.v2ex.com",
			ProtoPort:     "tcp/80",
			HijackAddress: "2.2.2.2",
		},
		{
			Outbound:      "default",
			Address:       "suffix:microsoft.com",
			ProtoPort:     "*/*",
			HijackAddress: "",
		},
		{
			Outbound:      "reject",
			Address:       "all",
			ProtoPort:     "tcp/6881-6889",
			HijackAddress: "",
		},
		{
			Outbound:      "direct",
			Address:       "dotpattern.test.", // trailing dot in pattern should be normalized away
			ProtoPort:     "tcp/443",
			HijackAddress: "",
		},
	}
	comp, err := Compile(rules, 100, &testGeoLoader{})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		host       HostInfo
		proto      Protocol
		port       uint16
		wantAction Action
		wantMatch  bool
		wantIP     net.IP
	}{
		{
			host:       HostInfo{IPv4: net.ParseIP("1.2.3.4")},
			proto:      ProtocolTCP,
			port:       1234,
			wantAction: ActionDirect,
			wantMatch:  true,
			wantIP:     nil,
		},
		{
			host:       HostInfo{IPv4: net.ParseIP("8.8.8.4")},
			proto:      ProtocolUDP,
			port:       5353,
			wantAction: ActionReject,
			wantMatch:  true,
			wantIP:     net.ParseIP("1.1.1.1"),
		},
		{
			host:       HostInfo{Name: "lean.delicious.com"},
			proto:      ProtocolUDP,
			port:       443,
			wantAction: ActionReject,
			wantMatch:  true,
			wantIP:     nil,
		},
		{
			host:       HostInfo{IPv6: net.ParseIP("2606:4700::6810:85e5")},
			proto:      ProtocolTCP,
			port:       80,
			wantAction: ActionDirect,
			wantMatch:  true,
			wantIP:     net.ParseIP("2606:4700::6810:85e6"),
		},
		{
			host:       HostInfo{IPv6: net.ParseIP("2606:4700:0:0:0:0:0:1")},
			proto:      ProtocolUDP,
			port:       8888,
			wantAction: ActionReject,
			wantMatch:  true,
			wantIP:     nil,
		},
		{
			host:       HostInfo{Name: "www.v2ex.com"},
			proto:      ProtocolUDP,
			port:       1234,
			wantAction: ActionReject,
			wantMatch:  true,
			wantIP:     nil,
		},
		{
			host:       HostInfo{Name: "crap.v2ex.com"},
			proto:      ProtocolTCP,
			port:       80,
			wantAction: ActionDirect,
			wantMatch:  true,
			wantIP:     net.ParseIP("2.2.2.2"),
		},
		{
			host:       HostInfo{Name: "crap.v2ex.com"},
			proto:      ProtocolTCP,
			port:       81,
			wantAction: ActionDirect,
			wantMatch:  false,
		},
		{
			host:       HostInfo{Name: "crap.v2ex.com"},
			proto:      ProtocolUDP,
			port:       80,
			wantAction: ActionReject,
			wantMatch:  true,
		},
		{
			host:       HostInfo{Name: "crap.v2ex.com"},
			proto:      ProtocolUDP,
			port:       81,
			wantAction: ActionReject,
			wantMatch:  true,
		},
		{
			host:       HostInfo{Name: "microsoft.com"},
			proto:      ProtocolTCP,
			port:       6000,
			wantAction: ActionDirect,
			wantMatch:  true,
			wantIP:     nil,
		},
		{
			host:       HostInfo{Name: "real.microsoft.com"},
			proto:      ProtocolUDP,
			port:       5353,
			wantAction: ActionDirect,
			wantMatch:  true,
			wantIP:     nil,
		},
		{
			host:       HostInfo{Name: "fakemicrosoft.com"},
			proto:      ProtocolTCP,
			port:       5000,
			wantAction: ActionDirect,
			wantMatch:  false,
			wantIP:     nil,
		},
		{
			host:       HostInfo{IPv4: net.ParseIP("223.1.1.1")},
			proto:      ProtocolTCP,
			port:       6883,
			wantAction: ActionReject, // match range port rule 6881-6889
			wantMatch:  true,
			wantIP:     nil,
		},
		{
			host:       HostInfo{Name: "crap.v2ex.com."}, // trailing dot must not bypass exact domain rule
			proto:      ProtocolTCP,
			port:       80,
			wantAction: ActionDirect,
			wantMatch:  true,
			wantIP:     net.ParseIP("2.2.2.2"),
		},
		{
			host:       HostInfo{Name: "hoho.v2ex.com."}, // trailing dot must not bypass wildcard domain rule
			proto:      ProtocolUDP,
			port:       9999,
			wantAction: ActionReject,
			wantMatch:  true,
			wantIP:     nil,
		},
		{
			host:       HostInfo{Name: "real.microsoft.com."}, // trailing dot must not bypass suffix domain rule
			proto:      ProtocolUDP,
			port:       5353,
			wantAction: ActionDirect,
			wantMatch:  true,
			wantIP:     nil,
		},
		{
			host:       HostInfo{Name: "microsoft.com..."}, // multiple trailing dots must also be normalized
			proto:      ProtocolTCP,
			port:       6000,
			wantAction: ActionDirect,
			wantMatch:  true,
			wantIP:     nil,
		},
		{
			host:       HostInfo{Name: "dotpattern.test"}, // host without dot must match rule whose pattern had a trailing dot
			proto:      ProtocolTCP,
			port:       443,
			wantAction: ActionDirect,
			wantMatch:  true,
			wantIP:     nil,
		},
	}

	for _, test := range tests {
		testName := fmt.Sprintf("%s#%s#%d", test.host, test.proto, test.port)
		t.Run(testName, func(t *testing.T) {
			gotAction, gotMatch, gotIP := comp.Match(test.host, test.proto, test.port)
			if gotAction != test.wantAction || gotMatch != test.wantMatch {
				t.Errorf("Match() = (%v, %v), want (%v, %v)", gotAction, gotMatch, test.wantAction, test.wantMatch)
			}
			if !reflect.DeepEqual(gotIP, test.wantIP) {
				t.Errorf("Match() hijack IP = %v, want %v", gotIP, test.wantIP)
			}
		})
	}
}

func TestCompileGeoRules(t *testing.T) {
	skipIfNoGeoFixtures(t)
	rules := []TextRule{
		{Outbound: "reject", Address: "geoip:JP", ProtoPort: "*/*"},
		{Outbound: "reject", Address: "geosite:4chan", ProtoPort: "*/*"},
		{Outbound: "reject", Address: "geosite:google @cn", ProtoPort: "*/*"},
	}
	comp, err := Compile(rules, 100, &testGeoLoader{})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		host       HostInfo
		proto      Protocol
		port       uint16
		wantAction Action
		wantMatch  bool
	}{
		{
			host:       HostInfo{IPv4: net.ParseIP("210.140.92.187")},
			proto:      ProtocolTCP,
			port:       25,
			wantAction: ActionReject,
			wantMatch:  true,
		},
		{
			host:       HostInfo{IPv4: net.ParseIP("175.45.176.73")},
			proto:      ProtocolTCP,
			port:       80,
			wantAction: ActionDirect,
			wantMatch:  false,
		},
		{
			host:       HostInfo{Name: "boards.4channel.org"},
			proto:      ProtocolTCP,
			port:       443,
			wantAction: ActionReject,
			wantMatch:  true,
		},
		{
			host:       HostInfo{Name: "gstatic-cn.com"},
			proto:      ProtocolUDP,
			port:       9999,
			wantAction: ActionReject,
			wantMatch:  true,
		},
		{
			host:       HostInfo{Name: "hoho.waymo.com"},
			proto:      ProtocolUDP,
			port:       9999,
			wantAction: ActionDirect,
			wantMatch:  false,
		},
	}

	for _, test := range tests {
		testName := fmt.Sprintf("%s#%s#%d", test.host, test.proto, test.port)
		t.Run(testName, func(t *testing.T) {
			gotAction, gotMatch, _ := comp.Match(test.host, test.proto, test.port)
			if gotAction != test.wantAction || gotMatch != test.wantMatch {
				t.Errorf("Match() = (%v, %v), want (%v, %v)", gotAction, gotMatch, test.wantAction, test.wantMatch)
			}
		})
	}
}

func TestCompileErrors(t *testing.T) {
	// Unknown outbound name
	_, err := Compile([]TextRule{
		{Outbound: "ob1", Address: "1.1.1.1"},
	}, 100, &testGeoLoader{})
	if err == nil {
		t.Error("expected error for unknown outbound, got nil")
	}

	// Invalid port range
	_, err = Compile([]TextRule{
		{Outbound: "reject", Address: "1.1.2.0/24", ProtoPort: "*/3-1"},
	}, 100, &testGeoLoader{})
	if err == nil {
		t.Error("expected error for invalid port range, got nil")
	}

	// Invalid hijack address
	_, err = Compile([]TextRule{
		{Outbound: "direct", Address: "1.1.1.1", HijackAddress: "not-an-ip"},
	}, 100, &testGeoLoader{})
	if err == nil {
		t.Error("expected error for invalid hijack address, got nil")
	}
}

func Test_parseGeoSiteName(t *testing.T) {
	tests := []struct {
		name  string
		s     string
		want  string
		want1 []string
	}{
		{name: "no attrs", s: "pornhub", want: "pornhub", want1: []string{}},
		{name: "one attr 1", s: "xiaomi@cn", want: "xiaomi", want1: []string{"cn"}},
		{name: "one attr 2", s: " google @jp ", want: "google", want1: []string{"jp"}},
		{name: "two attrs 1", s: "netflix@jp@kr", want: "netflix", want1: []string{"jp", "kr"}},
		{name: "two attrs 2", s: "netflix @xixi    @haha ", want: "netflix", want1: []string{"xixi", "haha"}},
		{name: "empty", s: "", want: "", want1: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := parseGeoSiteName(tt.s)
			if got != tt.want {
				t.Errorf("parseGeoSiteName(%v) name = %v, want %v", tt.s, got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("parseGeoSiteName(%v) attrs = %v, want %v", tt.s, got1, tt.want1)
			}
		})
	}
}
