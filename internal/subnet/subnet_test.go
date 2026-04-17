package subnet

import (
	"net"
	"testing"
)

func TestKeySameIPv4Slash24MapsToSameKey(t *testing.T) {
	keyA := Key("192.168.1.10", 24, 56)
	keyB := Key("192.168.1.250", 24, 56)

	if keyA != "192.168.1.0/24" {
		t.Fatalf("expected keyA to be 192.168.1.0/24, got %q", keyA)
	}
	if keyA != keyB {
		t.Fatalf("expected same /24 to map to same key, got %q and %q", keyA, keyB)
	}
}

func TestKeyDifferentIPv4Slash24MapsToDifferentKeys(t *testing.T) {
	keyA := Key("192.168.1.10", 24, 56)
	keyB := Key("192.168.2.10", 24, 56)

	if keyA == keyB {
		t.Fatalf("expected different /24 to map to different keys, got %q", keyA)
	}
}

func TestKeyIPv6Slash56(t *testing.T) {
	key := Key("2001:db8:abcd:1234::1", 24, 56)
	if key != "2001:db8:abcd:1200::/56" {
		t.Fatalf("expected IPv6 /56 key, got %q", key)
	}
}

func TestKeyMalformedIPReturnsEmpty(t *testing.T) {
	if got := Key("not-an-ip", 24, 56); got != "" {
		t.Fatalf("expected empty key for malformed IP, got %q", got)
	}
	if got := DefaultKey("bad-ip"); got != "" {
		t.Fatalf("expected empty key for malformed IP in default key, got %q", got)
	}
}

func TestIsIPv4(t *testing.T) {
	if !IsIPv4("10.1.2.3") {
		t.Fatalf("expected IPv4 address to return true")
	}
	if IsIPv4("2001:db8::1") {
		t.Fatalf("expected IPv6 address to return false")
	}
	if IsIPv4("invalid") {
		t.Fatalf("expected invalid input to return false")
	}
}

func TestKeyAndMaskSubnetAdditionalBranches(t *testing.T) {
	t.Run("invalid mask values return empty", func(t *testing.T) {
		if got := Key("192.168.1.10", -1, 56); got != "" {
			t.Fatalf("expected empty key for negative ipv4 bits, got %q", got)
		}
		if got := Key("2001:db8::1", 24, 129); got != "" {
			t.Fatalf("expected empty key for out-of-range ipv6 bits, got %q", got)
		}
	})

	t.Run("empty net.IP in maskSubnet returns empty", func(t *testing.T) {
		if got := maskSubnet(net.IP{}, 24); got != "" {
			t.Fatalf("expected empty key for zero-length ip, got %q", got)
		}
	})

	t.Run("zero and two-digit masks exercise itoa branches", func(t *testing.T) {
		if got := Key("192.168.1.10", 0, 56); got != "0.0.0.0/0" {
			t.Fatalf("expected /0 masked key, got %q", got)
		}
		if got := Key("10.11.12.13", 10, 56); got != "10.0.0.0/10" {
			t.Fatalf("expected /10 masked key, got %q", got)
		}
	})

	t.Run("ipv4 bits above 32 are rejected", func(t *testing.T) {
		if got := Key("10.1.2.3", 40, 56); got != "" {
			t.Fatalf("expected empty key for ipv4 bits above 32, got %q", got)
		}
	})
}
