package ui

import (
	"context"
	"strings"
	"testing"
)

func TestIncidentPage_RendersIP(t *testing.T) {
	view := IncidentView{
		IP:            "1.2.3.4",
		TimelineURL:   "/timeline?q=1.2.3.4",
		EvidenceURL:   "/evidence?q=1.2.3.4",
		ForensicURL:   "/forensic?q=1.2.3.4",
		CorrelatedURL: "/timeline/correlated?ip=1.2.3.4",
		AbuseIPDBURL:  "https://www.abuseipdb.com/check/1.2.3.4",
		VirusTotalURL: "https://www.virustotal.com/gui/ip-address/1.2.3.4",
	}
	var buf strings.Builder
	if err := IncidentPage(view).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()
	for _, want := range []string{
		"1.2.3.4", "AbuseIPDB", "VirusTotal", "By IP group", "Focus Incident",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("incident page missing %q", want)
		}
	}
}

func TestIncidentPage_NoMutationButtons(t *testing.T) {
	view := IncidentView{
		IP:            "1.2.3.4",
		AbuseIPDBURL:  "https://www.abuseipdb.com/check/1.2.3.4",
		VirusTotalURL: "https://www.virustotal.com/gui/ip-address/1.2.3.4",
	}
	var buf strings.Builder
	_ = IncidentPage(view).Render(context.Background(), &buf)
	body := buf.String()
	for _, banned := range []string{">Ban<", ">Report<", ">Suppress<", "formaction=\"/ban"} {
		if strings.Contains(body, banned) {
			t.Errorf("incident page must not contain mutation action %q", banned)
		}
	}
}

func TestIncidentPage_ShowsNote(t *testing.T) {
	view := IncidentView{
		IP:            "1.2.3.4",
		HasNote:       true,
		NoteContent:   "suspicious scanning behavior",
		NoteUpdatedAt: "2026-06-25T10:00:00Z",
		AbuseIPDBURL:  "x",
		VirusTotalURL: "x",
	}
	var buf strings.Builder
	_ = IncidentPage(view).Render(context.Background(), &buf)
	body := buf.String()
	if !strings.Contains(body, "suspicious scanning behavior") {
		t.Error("incident page should display note content")
	}
	if !strings.Contains(body, "2026-06-25") {
		t.Error("incident page should display note timestamp")
	}
}
