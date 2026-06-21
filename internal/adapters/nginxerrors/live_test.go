package nginxerrors

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func writeAccessLog(t *testing.T, dir, name string, lines []string) {
	t.Helper()
	path := filepath.Join(dir, name)
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func combinedLine(ip, ts, method, uri string, status int) string {
	return ip + ` - - [` + ts + `] "` + method + ` ` + uri + ` HTTP/1.1" ` + strconv.Itoa(status) + ` 123 "-" "test-agent"`
}

func TestListErrorsSinceFiltersByStatusAndTime(t *testing.T) {
	dir := t.TempDir()
	writeAccessLog(t, dir, "access.log", []string{
		combinedLine("1.2.3.4", "13/Jun/2026:10:00:00 +0000", "GET", "/ok", 200),
		combinedLine("1.2.3.4", "13/Jun/2026:10:00:01 +0000", "GET", "/missing", 404),
		combinedLine("5.6.7.8", "13/Jun/2026:10:05:00 +0000", "GET", "/late", 500),
	})

	src := NewLiveSource(dir)
	since := time.Date(2026, 6, 13, 9, 0, 0, 0, time.UTC)
	events, err := src.ListErrorsSince(context.Background(), since)
	if err != nil {
		t.Fatalf("ListErrorsSince: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 error events (200 excluded), got %d: %+v", len(events), events)
	}

	cutoff := time.Date(2026, 6, 13, 10, 0, 30, 0, time.UTC)
	later, err := src.ListErrorsSince(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("ListErrorsSince: %v", err)
	}
	if len(later) != 1 || later[0].IP.String() != "5.6.7.8" {
		t.Fatalf("expected only the post-cutoff event, got %+v", later)
	}
}

func TestListErrorsSinceMissingDirIsFailOpen(t *testing.T) {
	src := NewLiveSource(filepath.Join(t.TempDir(), "does-not-exist"))
	events, err := src.ListErrorsSince(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("expected fail-open nil error, got %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no events, got %d", len(events))
	}
}
