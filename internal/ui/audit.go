package ui

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/security/audit"
)

type AuditSink interface {
	audit.AuditSink
}

type AuditReader interface {
	audit.AuditReader
}

func (s *Server) auditRecord(action string, fields map[string]string) {
	if s == nil || s.audit == nil {
		return
	}
	s.audit.Record(action, fields)
}

type BufferAuditSink struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	entries []audit.AuditEntry
}

func NewBufferAuditSink() *BufferAuditSink {
	return &BufferAuditSink{}
}

func (s *BufferAuditSink) Record(action string, fields map[string]string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sanitized := sanitizeAuditFields(fields)
	entry := auditEntryFromFields(action, sanitized)
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	s.entries = append(s.entries, entry)
	s.buf.WriteString(action)
	for _, k := range sortedKeys(sanitized) {
		v := sanitized[k]
		s.buf.WriteByte(' ')
		s.buf.WriteString(k)
		s.buf.WriteByte('=')
		s.buf.WriteString(v)
	}
	s.buf.WriteByte('\n')
}

func (s *BufferAuditSink) String() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *BufferAuditSink) Entries() []audit.AuditEntry {
	entries, _ := s.EntriesContext(context.Background())
	return entries
}

func (s *BufferAuditSink) EntriesContext(ctx context.Context) ([]audit.AuditEntry, error) {
	if s == nil {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]audit.AuditEntry, len(s.entries))
	copy(out, s.entries)
	return out, nil
}

type FileAuditSink struct {
	mu   sync.Mutex
	path string
}

func NewFileAuditSink(path string) (*FileAuditSink, error) {
	if path == "" {
		return nil, fmt.Errorf("audit file path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		return nil, fmt.Errorf("initialize audit file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("chmod audit file: %w", err)
	}
	return &FileAuditSink{path: path}, nil
}

func (s *FileAuditSink) Record(action string, fields map[string]string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	sanitized := sanitizeAuditFields(fields)
	keys := sortedKeys(sanitized)

	parts := []string{time.Now().UTC().Format(time.RFC3339Nano), action}
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, sanitized[k]))
	}

	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(strings.Join(parts, " ") + "\n")
	_ = f.Chmod(0o600)
}

func (s *FileAuditSink) Entries() []audit.AuditEntry {
	entries, _ := s.EntriesContext(context.Background())
	return entries
}

func (s *FileAuditSink) EntriesContext(ctx context.Context) ([]audit.AuditEntry, error) {
	if s == nil {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	entries := make([]audit.AuditEntry, 0)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		entry := audit.AuditEntry{Timestamp: fields[0], Action: fields[1]}
		for _, field := range fields[2:] {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			switch key {
			case "actor", "session", "actor_session":
				entry.ActorSession = value
			case "source":
				entry.Source = value
				if entry.ActorSession == "" {
					entry.ActorSession = value
				}
			case "remote_ip", "ip":
				entry.RemoteIP = value
			case "target":
				entry.Target = value
			case "provider", "subject_id":
				if entry.Target == "" {
					entry.Target = value
				}
			case "result":
				entry.Result = value
			case "reason":
				if entry.Result == "" {
					entry.Result = value
				}
			case "error":
				entry.Error = value
			case "correlation_id", "correlation":
				entry.Correlation = value
			case "event_id":
				entry.EventID = value
			}
		}
		if entry.ActorSession == "" {
			entry.ActorSession = entry.Source
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

type noopAuditSink struct{}

func (noopAuditSink) Record(action string, fields map[string]string) {}

func auditEntryFromFields(action string, fields map[string]string) audit.AuditEntry {
	entry := audit.AuditEntry{Action: action}
	for key, value := range fields {
		value = strings.TrimSpace(value)
		switch key {
		case "timestamp":
			entry.Timestamp = value
		case "actor", "session", "actor_session":
			entry.ActorSession = value
		case "source":
			entry.Source = value
			if entry.ActorSession == "" {
				entry.ActorSession = value
			}
		case "remote_ip", "ip":
			entry.RemoteIP = value
		case "target":
			entry.Target = value
		case "provider", "subject_id":
			if entry.Target == "" {
				entry.Target = value
			}
		case "result":
			entry.Result = value
		case "reason":
			if entry.Result == "" {
				entry.Result = value
			}
		case "error":
			entry.Error = value
		case "correlation_id", "correlation":
			entry.Correlation = value
		case "event_id":
			entry.EventID = value
		}
	}
	if entry.ActorSession == "" {
		entry.ActorSession = entry.Source
	}
	return entry
}

func filterAuditEntries(entries []audit.AuditEntry, query string) []audit.AuditEntry {
	query = strings.TrimSpace(strings.ToLower(query))
	if query == "" {
		return entries
	}
	out := make([]audit.AuditEntry, 0, len(entries))
	for _, entry := range entries {
		fields := []string{
			entry.Timestamp,
			entry.Action,
			entry.ActorSession,
			entry.Source,
			entry.RemoteIP,
			entry.Target,
			entry.Result,
			entry.Error,
			entry.Correlation,
			entry.EventID,
		}
		matched := false
		for _, field := range fields {
			if strings.Contains(strings.ToLower(field), query) {
				matched = true
				break
			}
		}
		if matched {
			out = append(out, entry)
		}
	}
	return out
}

func sanitizeAuditFields(fields map[string]string) map[string]string {
	if len(fields) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(fields))
	for key, value := range fields {
		redacted := redactAuditValue(key, value)
		if redacted == nil {
			out[key] = ""
			continue
		}
		if s, ok := redacted.(string); ok {
			out[key] = strings.TrimSpace(s)
			continue
		}
		out[key] = fmt.Sprint(redacted)
	}
	return out
}

func isSensitiveAuditField(key string) bool {
	return isSensitiveAuditKey(key)
}

func redactValue(value string) string {
	if value == "" {
		return "missing"
	}
	if len(value) <= 8 {
		return "****"
	}
	return fmt.Sprintf("%s...%s", value[:4], value[len(value)-4:])
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
