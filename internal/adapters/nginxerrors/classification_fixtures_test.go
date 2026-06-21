package nginxerrors

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/security/classifier"
)

// These fixtures characterize how representative real-world HTTP error
// requests flow from Normalize through the existing (unmodified) classifier,
// confirming the nginxerrors wiring carries URI/UA fields correctly. They do
// not exercise classifier internals beyond what Normalize hands it.
func TestNormalizeAndClassifyFixtures(t *testing.T) {
	ts := time.Now().UTC()

	cases := []struct {
		name      string
		uri       string
		status    int
		userAgent string
		wantType  string
	}{
		{name: "404 sensitive wordpress path", uri: "/wp-login.php", status: 404, userAgent: "Mozilla/5.0", wantType: "wordpress_probe"},
		{name: "403 xss payload in query", uri: "/search?q=<script>alert(1)</script>", status: 403, userAgent: "Mozilla/5.0", wantType: "exploit_attempt"},
		{name: "404 simple bot scanner UA", uri: "/robots.txt", status: 404, userAgent: "sqlmap/1.6", wantType: "suspicious_probe"},
		{name: "404 legit crawler UA stays benign", uri: "/robots.txt", status: 404, userAgent: "Mozilla/5.0 (compatible; Googlebot/2.1)", wantType: "benign_probe"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := netip.MustParseAddr("203.0.113.10")
			event, err := Normalize(RawEvent{
				IP:        ip,
				Timestamp: ts,
				Method:    "GET",
				URI:       tc.uri,
				Status:    tc.status,
				UserAgent: tc.userAgent,
			})
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}
			got := classifier.Classify(event)
			if got.AbuseType != tc.wantType {
				t.Fatalf("classify(%q, ua=%q) abuse_type = %q, want %q (evidence=%v)", tc.uri, tc.userAgent, got.AbuseType, tc.wantType, got.Evidence)
			}
		})
	}
}

func TestNormalizeAndClassify5xxServerError(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.20")
	event, err := Normalize(RawEvent{
		IP:        ip,
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URI:       "/checkout",
		Status:    502,
		UserAgent: "Mozilla/5.0",
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	got := classifier.Classify(event)
	if got.AbuseType == "" {
		t.Fatal("expected a non-empty abuse_type classification for a 5xx event")
	}
	if event.RuleName != "http_502" {
		t.Fatalf("expected rule name to encode status, got %q", event.RuleName)
	}
}
