package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

func TestRenderV2NotesPageEmpty(t *testing.T) {
	got := renderV2NotesPage(nil, "test-token")

	for _, want := range []string{
		"No notes.",
		"Notes can tag IPs, ASNs, domains, or evidence IDs. Use the quick-create form →",
		`<select class="v2-field" name="type"`,
		`<option value="ip">IP address</option>`,
		`<option value="asn">ASN</option>`,
		`<option value="domain">Domain</option>`,
		`<option value="other">Other</option>`,
		"Ctrl+K to search existing notes",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("empty state missing %q", want)
		}
	}

	// Hardcoded hidden type input must not appear
	if strings.Contains(got, `type="hidden" name="type" value="ip"`) {
		t.Error("empty state must not contain hardcoded hidden type input")
	}
}

func TestRenderV2NotesPageWithNotes(t *testing.T) {
	now := time.Now()
	notes := make([]sqlite.Note, 10)
	for i := range notes {
		notes[i] = sqlite.Note{
			ID:          int64(i + 1),
			EntityType:  "ip",
			EntityValue: "10.0.0." + string(rune('0'+i)),
			Content:     "test note",
			CreatedAt:   now,
			UpdatedAt:   now,
		}
	}

	got := renderV2NotesPage(notes, "test-token")

	// "View all N notes" link must appear when notes > 6
	if !strings.Contains(got, "View all 10 notes") {
		t.Error("expected 'View all 10 notes' link when more than 6 notes exist")
	}

	// Type select must be present
	if !strings.Contains(got, `<select class="v2-field" name="type"`) {
		t.Error("type select input not found in rendered output")
	}

	// Note count pill in header
	if !strings.Contains(got, "10 notes") {
		t.Error("expected '10 notes' pill in card header")
	}

	// Keyboard shortcut hint below Save button
	if !strings.Contains(got, "Ctrl+K to search existing notes") {
		t.Error("expected keyboard shortcut hint below Save button")
	}
}
