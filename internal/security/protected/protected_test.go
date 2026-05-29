package protected_test

import (
	"testing"

	"github.com/jm/security-automation-go/internal/security/protected"
)

func TestIsProtected_RFC1918(t *testing.T) {
	s := protected.New()
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"169.254.1.1", true},
		{"100.64.0.1", true},
		// Not protected
		{"1.2.3.4", false},
		{"8.8.8.8", false},
		{"203.0.113.1", false},
	}
	for _, tc := range cases {
		got := s.IsProtected(tc.ip)
		if got != tc.want {
			t.Errorf("IsProtected(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestIsProtected_CloudflareRanges(t *testing.T) {
	s := protected.New()
	cfIPs := []string{
		"173.245.48.1",
		"103.21.244.1",
		"104.16.0.1",
		"104.24.0.1",
		"172.64.0.1",
		"162.158.0.1",
	}
	for _, ip := range cfIPs {
		if !s.IsProtected(ip) {
			t.Errorf("expected CF IP %s to be protected", ip)
		}
	}
}

func TestIsProtected_InvalidIP(t *testing.T) {
	s := protected.New()
	if s.IsProtected("not-an-ip") {
		t.Error("invalid IP should not be protected")
	}
	if s.IsProtected("") {
		t.Error("empty IP should not be protected")
	}
}

func TestIsProtected_NilShield(t *testing.T) {
	var s *protected.Shield
	if s.IsProtected("10.0.0.1") {
		t.Error("nil shield should return false")
	}
}

func TestNetworkCount(t *testing.T) {
	s := protected.New()
	// Must have at least the static CIDRs (34) plus whatever interfaces exist
	if s.NetworkCount() < 34 {
		t.Errorf("expected at least 34 protected networks, got %d", s.NetworkCount())
	}
}

func TestNewWithExtraRanges(t *testing.T) {
	s := protected.NewWithExtraRanges([]string{"203.0.113.0/24"})
	if !s.IsProtected("203.0.113.42") {
		t.Error("extra range should be protected")
	}
	if s.IsProtected("203.0.114.1") {
		t.Error("IP outside extra range should not be protected")
	}
}
