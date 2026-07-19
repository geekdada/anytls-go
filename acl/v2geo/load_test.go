package v2geo

import (
	"os"
	"testing"
)

func skipIfNoFixtures(t *testing.T) {
	t.Helper()
	for _, f := range []string{"geoip.dat", "geosite.dat"} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("fixture %s not found; copy v2ray-rules-dat files here to run", f)
		}
	}
}

func TestLoadGeoIP(t *testing.T) {
	skipIfNoFixtures(t)
	m, err := LoadGeoIP("geoip.dat")
	if err != nil {
		t.Fatal(err)
	}

	// Exact checks since we know the data.
	if len(m) != 252 {
		t.Fatalf("expected 252 entries, got %d", len(m))
	}
	if m["cn"].CountryCode != "CN" {
		t.Fatalf("cn country code = %q", m["cn"].CountryCode)
	}
	if m["us"].CountryCode != "US" {
		t.Fatalf("us country code = %q", m["us"].CountryCode)
	}
	if m["private"].CountryCode != "PRIVATE" {
		t.Fatalf("private country code = %q", m["private"].CountryCode)
	}
	want := &CIDR{Ip: []byte("\xc0\xa8\x00\x00"), Prefix: 16}
	found := false
	for _, c := range m["private"].Cidr {
		if string(c.Ip) == string(want.Ip) && c.Prefix == want.Prefix {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("private list missing 192.168.0.0/16")
	}
}

func TestLoadGeoSite(t *testing.T) {
	skipIfNoFixtures(t)
	m, err := LoadGeoSite("geosite.dat")
	if err != nil {
		t.Fatal(err)
	}

	// Exact checks since we know the data.
	if len(m) != 1204 {
		t.Fatalf("expected 1204 entries, got %d", len(m))
	}
	if m["netflix"].CountryCode != "NETFLIX" {
		t.Fatalf("netflix country code = %q", m["netflix"].CountryCode)
	}
	var hasFull, hasRoot bool
	for _, d := range m["netflix"].Domain {
		if d.Type == Domain_Full && d.Value == "netflix.com.edgesuite.net" {
			hasFull = true
		}
		if d.Type == Domain_RootDomain && d.Value == "fast.com" {
			hasRoot = true
		}
	}
	if !hasFull || !hasRoot {
		t.Fatal("netflix list missing expected domains")
	}
	var hasGgpht bool
	for _, d := range m["google"].Domain {
		if d.Type == Domain_RootDomain && d.Value == "ggpht.cn" {
			for _, a := range d.Attribute {
				if a.Key == "cn" {
					hasGgpht = true
				}
			}
		}
	}
	if !hasGgpht {
		t.Fatal("google list missing ggpht.cn@cn")
	}
}
