package wafref

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// LiveSource tails waf_refs.jsonl, an append-only file the Lua WAF bundle
// writes to (and never renames/truncates, unlike events.jsonl). Tracking a
// byte offset — rather than the rename-based consumption openrestyevent
// uses — lets the file keep growing for as long as a human might want to
// look up a ref later, without fighting the Lua writer for the file.
type LiveSource struct {
	RefsFile string

	mu     sync.Mutex
	offset int64
}

func NewLiveSource(refsFile string) *LiveSource {
	return &LiveSource{RefsFile: refsFile}
}

// Offset returns the number of bytes of RefsFile already consumed.
// Callers can persist this across restarts to avoid re-processing the
// entire file (and re-recording duplicate evidence rows) on every start.
func (s *LiveSource) Offset() int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.offset
}

// SetOffset restores a previously persisted byte offset, e.g. on startup.
func (s *LiveSource) SetOffset(offset int64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offset = offset
}

type luaRefEntry struct {
	Ref      string `json:"ref"`
	TS       string `json:"ts"`
	ClientIP string `json:"client_ip"`
	Host     string `json:"host"`
	Method   string `json:"method"`
	URI      string `json:"uri"`
	Reason   string `json:"reason"`
}

func (s *LiveSource) Read(ctx context.Context) ([]RawEvent, error) {
	_ = ctx
	if s == nil || strings.TrimSpace(s.RefsFile) == "" {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.RefsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// File was truncated or rotated underneath us; restart from the top
	// rather than erroring, since this is best-effort correlation data.
	if info.Size() < s.offset {
		s.offset = 0
	}
	if _, err := f.Seek(s.offset, io.SeekStart); err != nil {
		return nil, err
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	// Only consume up to the last newline. A partial trailing line means the
	// Lua writer's append is still in flight (or was cut short) — leave it
	// for the next tick rather than risk parsing a half-written entry.
	lastNL := strings.LastIndexByte(string(buf), '\n')
	if lastNL < 0 {
		return nil, nil
	}
	complete := buf[:lastNL+1]
	s.offset += int64(len(complete))

	events := make([]RawEvent, 0)
	for _, line := range strings.Split(strings.TrimRight(string(complete), "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry luaRefEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if strings.TrimSpace(entry.Ref) == "" || strings.TrimSpace(entry.ClientIP) == "" {
			continue
		}
		ts, ok := parseLuaTimestamp(entry.TS)
		if !ok {
			ts = time.Now().UTC()
		}
		events = append(events, RawEvent{
			Ref:       entry.Ref,
			Timestamp: ts,
			IP:        entry.ClientIP,
			Host:      entry.Host,
			Method:    entry.Method,
			URI:       entry.URI,
			Reason:    entry.Reason,
		})
	}
	return events, nil
}

// parseLuaTimestamp parses the "!%Y-%m-%dT%H:%M:%SZ" timestamp written by
// waf_refs.lua's os.date call, which is RFC3339 without sub-second precision.
func parseLuaTimestamp(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	ts, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return ts.UTC(), true
}
