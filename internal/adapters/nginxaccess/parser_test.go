package nginxaccess

import (
	"net/netip"
	"testing"
	"time"
)

func TestParseLineCombinedFormat(t *testing.T) {
	line := `82.65.145.189 - - [25/May/2026:12:45:47 +0200] "GET / HTTP/2.0" 200 2988 "-" "Mozilla/5.0 Chrome/146" cs_reason=-`
	e, ok := ParseLine(line)
	if !ok {
		t.Fatal("expected ParseLine to return ok")
	}
	if e.IP.String() != "82.65.145.189" {
		t.Errorf("IP: got %s", e.IP)
	}
	if e.Status != 200 {
		t.Errorf("Status: got %d", e.Status)
	}
	if e.Method != "GET" {
		t.Errorf("Method: got %s", e.Method)
	}
	if e.URI != "/" {
		t.Errorf("URI: got %s", e.URI)
	}
	want := time.Date(2026, 5, 25, 12, 45, 47, 0, time.FixedZone("", 2*3600))
	if !e.Time.Equal(want) {
		t.Errorf("Time: got %v, want %v", e.Time, want)
	}
}

func TestParseLineCaptchaLine(t *testing.T) {
	line := `2a06:98c0:3600::103 - - [30/May/2026:23:12:16 +0200] "GET /robots.txt HTTP/2.0" 403 150 "-" "-" cs_reason=captcha`
	e, ok := ParseLine(line)
	if !ok {
		t.Fatal("expected ParseLine to return ok")
	}
	if e.Status != 403 {
		t.Errorf("Status: got %d, want 403", e.Status)
	}
	if e.CSReason != "captcha" {
		t.Errorf("CSReason: got %q, want %q", e.CSReason, "captcha")
	}
}

func TestFilter4xx5xx(t *testing.T) {
	entries := []Entry{
		{Status: 200},
		{Status: 301},
		{Status: 403},
		{Status: 404},
		{Status: 500},
		{Status: 503},
	}
	filtered := Filter4xx5xx(entries)
	if len(filtered) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(filtered))
	}
	for _, e := range filtered {
		if e.Status < 400 || e.Status >= 600 {
			t.Errorf("unexpected status %d", e.Status)
		}
	}
}

func TestGroupByIP(t *testing.T) {
	entries := []Entry{
		{IP: mustIP("1.2.3.4"), Status: 403, Method: "GET", URI: "/a"},
		{IP: mustIP("1.2.3.4"), Status: 403, Method: "POST", URI: "/b"},
		{IP: mustIP("1.2.3.4"), Status: 404, Method: "GET", URI: "/c"},
		{IP: mustIP("5.6.7.8"), Status: 403, Method: "GET", URI: "/d"},
	}
	groups := GroupByIP(entries)
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}
	// Highest count first
	if groups[0].Count != 2 {
		t.Errorf("first group count: got %d, want 2", groups[0].Count)
	}
	if groups[0].IP.String() != "1.2.3.4" || groups[0].Status != 403 {
		t.Errorf("first group: got %s %d", groups[0].IP, groups[0].Status)
	}
}

func mustIP(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}

func TestParseLineInvalidSkipped(t *testing.T) {
	cases := []string{
		"",
		"# comment",
		"not a log line",
		"256.256.256.256 - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 0 \"-\" \"-\"",
	}
	for _, line := range cases {
		if _, ok := ParseLine(line); ok {
			t.Errorf("expected ParseLine to return !ok for %q", line)
		}
	}
}
