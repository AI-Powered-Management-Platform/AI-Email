package netguard

import (
	"net/netip"
	"testing"
)

func TestInternalAddressesAreBlocked(t *testing.T) {
	blocked := []string{
		"127.0.0.1",
		"127.1.2.3",
		"0.0.0.0",
		"10.0.0.5",
		"172.16.0.1",
		"172.31.255.254",
		"192.168.1.1",
		"169.254.169.254", // cloud metadata, the classic SSRF target
		"169.254.0.1",
		"100.64.0.1", // carrier-grade NAT
		"192.0.0.1",
		"224.0.0.1", // multicast
		"255.255.255.255",
		"::1",
		"fc00::1",
		"fd12:3456::1",
		"fe80::1",
		"::",
	}
	for _, in := range blocked {
		addr := netip.MustParseAddr(in)
		if !IsBlocked(addr) {
			t.Errorf("%s must be blocked", in)
		}
	}
}

func TestPublicAddressesAreAllowed(t *testing.T) {
	allowed := []string{
		"1.1.1.1",
		"8.8.8.8",
		"93.184.216.34",
		"172.32.0.1",  // just outside the private range
		"172.15.0.1",  // just below it
		"100.63.0.1",  // just below CGNAT
		"100.128.0.1", // just above CGNAT
		"2606:4700::1111",
	}
	for _, in := range allowed {
		addr := netip.MustParseAddr(in)
		if IsBlocked(addr) {
			t.Errorf("%s should be allowed", in)
		}
	}
}

func TestIPv4MappedIPv6CannotSmuggleAnInternalAddress(t *testing.T) {
	// ::ffff:127.0.0.1 is loopback wearing an IPv6 costume.
	addr := netip.MustParseAddr("::ffff:127.0.0.1")
	if !IsBlocked(addr) {
		t.Fatal("an IPv4-mapped loopback address must be blocked")
	}
	if !IsBlocked(netip.MustParseAddr("::ffff:169.254.169.254")) {
		t.Fatal("an IPv4-mapped metadata address must be blocked")
	}
}

func TestInvalidAddressIsBlocked(t *testing.T) {
	if !IsBlocked(netip.Addr{}) {
		t.Fatal("an invalid address must default to blocked")
	}
}

func TestValidateURLRejectsUnsafeDestinations(t *testing.T) {
	cases := map[string]string{
		"file scheme":      "file:///etc/passwd",
		"gopher scheme":    "gopher://example.com/",
		"no scheme":        "example.com/hook",
		"missing host":     "https://",
		"ssh port":         "https://example.com:22/hook",
		"postgres port":    "http://example.com:5432/hook",
		"literal loopback": "http://127.0.0.1/hook",
		"metadata":         "http://169.254.169.254/latest/meta-data/",
		"localhost name":   "http://localhost:80/hook",
		"private literal":  "https://10.1.2.3/hook",
	}
	for name, raw := range cases {
		if _, err := ValidateURL(raw); err == nil {
			t.Errorf("%s: %q should have been rejected", name, raw)
		}
	}
}

func TestValidateURLAcceptsNormalWebhooks(t *testing.T) {
	for _, raw := range []string{
		"https://example.com/hooks/email",
		"https://example.com:443/hooks",
		"http://example.org:80/h",
		"https://sub.domain.example.co.uk/path?x=1",
	} {
		if _, err := ValidateURL(raw); err != nil {
			t.Errorf("%q should be allowed: %v", raw, err)
		}
	}
}
