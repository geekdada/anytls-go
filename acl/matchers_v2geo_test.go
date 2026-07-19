package acl

import (
	"net"
	"os"
	"testing"

	"anytls/acl/v2geo"
)

func skipIfNoGeoFixtures(t *testing.T) {
	t.Helper()
	for _, f := range []string{"v2geo/geoip.dat", "v2geo/geosite.dat"} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("fixture %s not found; copy v2ray-rules-dat files here to run", f)
		}
	}
}

func Test_geoipMatcher_Match(t *testing.T) {
	skipIfNoGeoFixtures(t)
	geoipMap, err := v2geo.LoadGeoIP("v2geo/geoip.dat")
	if err != nil {
		t.Fatal(err)
	}
	m, err := newGeoIPMatcher(geoipMap["us"])
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		host HostInfo
		want bool
	}{
		{
			name: "IPv4 match",
			host: HostInfo{
				IPv4: net.ParseIP("73.222.1.100"),
			},
			want: true,
		},
		{
			name: "IPv4 no match",
			host: HostInfo{
				IPv4: net.ParseIP("123.123.123.123"),
			},
			want: false,
		},
		{
			name: "IPv6 match",
			host: HostInfo{
				IPv6: net.ParseIP("2607:f8b0:4005:80c::2004"),
			},
			want: true,
		},
		{
			name: "IPv6 no match",
			host: HostInfo{
				IPv6: net.ParseIP("240e:947:6001::1f8"),
			},
			want: false,
		},
		{
			name: "both nil",
			host: HostInfo{
				IPv4: nil,
				IPv6: nil,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Match(tt.host); got != tt.want {
				t.Errorf("Match(%v) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func Test_geositeMatcher_Match(t *testing.T) {
	skipIfNoGeoFixtures(t)
	geositeMap, err := v2geo.LoadGeoSite("v2geo/geosite.dat")
	if err != nil {
		t.Fatal(err)
	}
	m, err := newGeositeMatcher(geositeMap["apple"], nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		attrs []string
		host  HostInfo
		want  bool
	}{
		{
			name:  "subdomain",
			attrs: nil,
			host: HostInfo{
				Name: "poop.i-book.com",
			},
			want: true,
		},
		{
			name:  "subdomain root",
			attrs: nil,
			host: HostInfo{
				Name: "applepaycash.net",
			},
			want: true,
		},
		{
			name:  "full",
			attrs: nil,
			host: HostInfo{
				Name: "courier-push-apple.com.akadns.net",
			},
			want: true,
		},
		{
			name:  "regexp",
			attrs: nil,
			host: HostInfo{
				Name: "cdn4.apple-mapkit.com",
			},
			want: true,
		},
		{
			name:  "attr match",
			attrs: []string{"cn"},
			host: HostInfo{
				Name: "bag.itunes.apple.com",
			},
			want: true,
		},
		{
			name:  "attr multi no match",
			attrs: []string{"cn", "haha"},
			host: HostInfo{
				Name: "bag.itunes.apple.com",
			},
			want: false,
		},
		{
			name:  "attr no match",
			attrs: []string{"cn"},
			host: HostInfo{
				Name: "mr-apple.com.tw",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.Attrs = tt.attrs
			if got := m.Match(tt.host); got != tt.want {
				t.Errorf("Match(%v) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}
