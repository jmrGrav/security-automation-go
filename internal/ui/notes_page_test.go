package ui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

func TestNotesPageRendersEmpty(t *testing.T) {
	var buf strings.Builder
	if err := NotesPage(nil).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), "No notes") {
		t.Error("empty notes page should show empty state")
	}
}

func TestNotesPageRendersNotes(t *testing.T) {
	notes := []sqlite.Note{
		{EntityType: "ip", EntityValue: "1.2.3.4", Content: "test note", UpdatedAt: time.Now()},
	}
	var buf strings.Builder
	if err := NotesPage(notes).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()
	for _, want := range []string{"1.2.3.4", "test note", "ip"} {
		if !strings.Contains(body, want) {
			t.Errorf("notes page missing %q", want)
		}
	}
}

func TestV2NotesPageEmptyStateIsOperational(t *testing.T) {
	out := renderV2NotesPage(nil)
	for _, want := range []string{
		"Operator Notes",
		"Recent notes",
		"Search",
		"Filters",
		"Quick create",
		"Entities recently annotated",
		"No notes",
		"Open Focus Incident",
		"Browse Timeline",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("v2 notes empty state missing %q: %s", want, out)
		}
	}
	if strings.Contains(out, "Pinned notes") {
		t.Fatal("v2 notes page must not contain removed 'Pinned notes' section")
	}
}

func TestV2NotesPageRendersNotesAsInvestigationLinks(t *testing.T) {
	notes := []sqlite.Note{
		{EntityType: "ip", EntityValue: "1.2.3.4", Content: "scanner", UpdatedAt: time.Date(2026, 6, 25, 10, 0, 0, 0, time.UTC)},
	}

	out := renderV2NotesPage(notes)
	for _, want := range []string{
		"scanner",
		"1.2.3.4",
		"/v2/incident?ip=1.2.3.4",
		"/v2/timeline?q=1.2.3.4",
		"/v2/investigate?q=1.2.3.4",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("v2 notes page missing %q: %s", want, out)
		}
	}
}
