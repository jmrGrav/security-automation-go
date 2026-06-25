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
