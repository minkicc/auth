package plugins

import (
	"net"
	"net/netip"
	"testing"
)

func TestRequireRemoteIPAllowedBlocksPrivateAndLoopback(t *testing.T) {
	blocked := []string{
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"169.254.1.1",
		"::1",
		"fc00::1",
		"fe80::1",
	}
	for _, raw := range blocked {
		ip := net.ParseIP(raw)
		if ip == nil {
			t.Fatalf("failed to parse test ip %s", raw)
		}
		if err := requireRemoteIPAllowed("example.test", ip, false); err == nil {
			t.Fatalf("expected %s to be blocked", raw)
		}
	}
}

func TestRequireRemoteIPAllowedCanAllowPrivateNetworks(t *testing.T) {
	if err := requireRemoteIPAllowed("localhost", net.ParseIP("127.0.0.1"), true); err != nil {
		t.Fatalf("expected private network override to allow loopback: %v", err)
	}
}

func TestIsBlockedRemoteAddressAllowsPublicAddress(t *testing.T) {
	addr := netip.MustParseAddr("8.8.8.8")
	if isBlockedRemoteAddress(addr) {
		t.Fatalf("expected public address to be allowed")
	}
}
