package ui

import (
	"strings"
	"testing"
)

func TestV2InvestigatePivotLinks(t *testing.T) {
	view := ForensicView{IP: "1.2.3.4"}
	out := renderV2InvestigateIP(view, nil, "", "", "")

	wantLinks := []string{
		`/v2/timeline?q=1.2.3.4`,
		`/v2/cloudflare`,
		`/v2/notes`,
		`/notes?type=ip`,
		"Pivot to",
	}
	for _, want := range wantLinks {
		if !strings.Contains(out, want) {
			t.Errorf("renderV2InvestigateIP missing %q in output", want)
		}
	}
}
