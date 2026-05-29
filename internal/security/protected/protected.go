// Package protected implements Python's anti-self-ban protection (is_protected()).
//
// A Shield is populated at startup with:
//  1. A static list of RFC1918, loopback, link-local, CGNAT, and all
//     Cloudflare IP ranges — mirroring Python's _PROTECTED_CIDRS_STATIC.
//  2. The host's own IPs auto-detected via `ip -j addr` (with fallback to
//     socket.getaddrinfo equiv). Mirroring Python's _build_protected_networks().
//
// IsProtected returns true for any IP that falls inside a protected network,
// blocking self-ban of the server, management ranges, VPNs, and CF relays.
package protected

import (
	"context"
	"encoding/json"
	"net"
	"os/exec"
	"time"
)

// staticCIDRs mirrors Python's _PROTECTED_CIDRS_STATIC exactly.
var staticCIDRs = []string{
	// RFC1918 private ranges
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	// Loopback
	"127.0.0.0/8",
	"::1/128",
	// Link-local
	"169.254.0.0/16",
	"fe80::/10",
	// CGNAT (shared address space)
	"100.64.0.0/10",
	// Cloudflare IP ranges (https://www.cloudflare.com/ips/)
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	// Cloudflare IPv6
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

// ipAddrRunner abstracts `ip -j addr` execution for testability.
type ipAddrRunner interface {
	run(ctx context.Context) ([]byte, error)
}

type realRunner struct{}

func (r *realRunner) run(ctx context.Context) ([]byte, error) {
	opCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return exec.CommandContext(opCtx, "ip", "-j", "addr").Output()
}

// Shield holds the set of protected networks. Build once at startup, reuse across cycles.
type Shield struct {
	networks []net.IPNet
}

// New creates a Shield with static + auto-detected host networks.
// If auto-detection fails, a warning is logged but the static ranges still apply.
func New() *Shield {
	return newWithRunner(context.Background(), &realRunner{})
}

// NewWithExtraRanges creates a Shield with additional CIDR strings (e.g., management ranges).
func NewWithExtraRanges(extras []string) *Shield {
	s := New()
	for _, cidr := range extras {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			s.networks = append(s.networks, *n)
		}
	}
	return s
}

func newWithRunner(ctx context.Context, runner ipAddrRunner) *Shield {
	s := &Shield{}
	// 1. Static CIDRs
	for _, cidr := range staticCIDRs {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			s.networks = append(s.networks, *n)
		}
	}
	// 2. Auto-detect own IPs via `ip -j addr` (mirrors Python's subprocess approach)
	s.addOwnIPs(ctx, runner)
	return s
}

// ipJAddrEntry is one element of `ip -j addr` output.
type ipJAddrEntry struct {
	AddrInfo []struct {
		Local string `json:"local"`
	} `json:"addr_info"`
}

// addOwnIPs parses `ip -j addr` and adds each interface address as a host route.
// Falls back to net.InterfaceAddrs on failure, matching Python's fallback to socket.getaddrinfo.
func (s *Shield) addOwnIPs(ctx context.Context, runner ipAddrRunner) {
	raw, err := runner.run(ctx)
	if err == nil {
		var ifaces []ipJAddrEntry
		if json.Unmarshal(raw, &ifaces) == nil {
			for _, iface := range ifaces {
				for _, ai := range iface.AddrInfo {
					if ai.Local == "" {
						continue
					}
					if ip := net.ParseIP(ai.Local); ip != nil {
						// Represent as host route (/32 or /128)
						bits := 32
						if ip.To4() == nil {
							bits = 128
						}
						s.networks = append(s.networks, net.IPNet{
							IP:   ip,
							Mask: net.CIDRMask(bits, bits),
						})
					}
				}
			}
			return
		}
	}
	// Fallback: net.InterfaceAddrs (mirrors Python's socket.getaddrinfo fallback)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPNet:
			s.networks = append(s.networks, *v)
		case *net.IPAddr:
			bits := 32
			if v.IP.To4() == nil {
				bits = 128
			}
			s.networks = append(s.networks, net.IPNet{
				IP:   v.IP,
				Mask: net.CIDRMask(bits, bits),
			})
		}
	}
}

// IsProtected returns true if ip falls inside any protected network.
// Mirrors Python's is_protected().
func (s *Shield) IsProtected(ipStr string) bool {
	if s == nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, network := range s.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// NetworkCount returns the total number of protected networks (static + dynamic).
func (s *Shield) NetworkCount() int {
	if s == nil {
		return 0
	}
	return len(s.networks)
}
