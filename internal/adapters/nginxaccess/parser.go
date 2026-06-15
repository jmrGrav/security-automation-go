package nginxaccess

import (
	"bufio"
	"compress/gzip"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Entry is a single parsed nginx combined-format access log line.
type Entry struct {
	IP        netip.Addr
	Time      time.Time
	Method    string
	URI       string
	Proto     string
	Status    int
	Size      int64
	Referer   string
	UserAgent string
	CSReason  string
}

// GroupKey identifies a unique (IP, status) pair.
type GroupKey struct {
	IP     netip.Addr
	Status int
}

// Group aggregates access log entries for one IP+status combination.
type Group struct {
	IP        netip.Addr
	Status    int
	Count     int
	Method    string
	LastURI   string
	UserAgent string
	FirstSeen time.Time
	LastSeen  time.Time
}

// ParseLine parses one nginx combined-format log line.
// Returns false if the line does not match the expected format.
func ParseLine(line string) (Entry, bool) {
	// Format: IP - - [DD/Mon/YYYY:HH:MM:SS +ZONE] "METHOD URI PROTO" STATUS SIZE "REFERER" "UA" [optional fields]
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Entry{}, false
	}

	parts := strings.SplitN(line, " ", 9)
	if len(parts) < 9 {
		return Entry{}, false
	}

	ip, err := netip.ParseAddr(parts[0])
	if err != nil {
		return Entry{}, false
	}

	// parts[3] = "[DD/Mon/YYYY:HH:MM:SS" (brackets split across parts[3..4])
	tsRaw := strings.TrimPrefix(parts[3], "[")
	if len(parts) > 4 {
		tsRaw += " " + strings.TrimSuffix(parts[4], "]")
	}
	ts, _ := time.Parse("02/Jan/2006:15:04:05 -0700", tsRaw)

	// parts[5] = "\"METHOD" parts[6] = "URI" parts[7] = "PROTO\""
	method := strings.TrimPrefix(parts[5], "\"")
	uri := parts[6]
	proto := strings.TrimSuffix(parts[7], "\"")

	// parts[8] is "STATUS SIZE ... rest"
	tail := strings.SplitN(strings.TrimSpace(parts[8]), " ", 3)
	if len(tail) < 2 {
		return Entry{}, false
	}
	status, err := strconv.Atoi(tail[0])
	if err != nil {
		return Entry{}, false
	}
	rest := ""
	if len(tail) >= 3 {
		rest = tail[2]
	}

	referer, ua, csReason := parseRestFields(rest)

	return Entry{
		IP:        ip,
		Time:      ts,
		Method:    method,
		URI:       uri,
		Proto:     proto,
		Status:    status,
		Referer:   referer,
		UserAgent: ua,
		CSReason:  csReason,
	}, true
}

func parseRestFields(rest string) (referer, ua, csReason string) {
	rest = strings.TrimSpace(rest)
	if rest == "" || rest == "-" {
		return "", "", ""
	}

	// Referer is the first quoted field
	if strings.HasPrefix(rest, "\"") {
		end := strings.Index(rest[1:], "\"")
		if end >= 0 {
			referer = rest[1 : end+1]
			rest = strings.TrimSpace(rest[end+2:])
		}
	}

	// UA is the next quoted field
	if strings.HasPrefix(rest, "\"") {
		end := strings.Index(rest[1:], "\"")
		if end >= 0 {
			ua = rest[1 : end+1]
			rest = strings.TrimSpace(rest[end+2:])
		}
	}

	// Remaining fields: cs_reason=VALUE etc.
	for _, field := range strings.Fields(rest) {
		if strings.HasPrefix(field, "cs_reason=") {
			csReason = strings.TrimPrefix(field, "cs_reason=")
		}
	}
	return referer, ua, csReason
}

// ReadFile parses all entries from a single log file (plain or gzip).
// Returns an empty slice on any read error (fail-open).
func ReadFile(path string) []Entry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil
		}
		defer gz.Close()
		r = gz
	}

	var entries []Entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 512*1024), 512*1024)
	for sc.Scan() {
		if e, ok := ParseLine(sc.Text()); ok {
			entries = append(entries, e)
		}
	}
	return entries
}

// ReadDir reads all *.access.log and *.access.log.1 files in the directory,
// returning parsed entries sorted by time (oldest first).
// Fail-open: missing or unreadable files are silently skipped.
func ReadDir(logDir string) []Entry {
	if logDir == "" {
		return nil
	}
	patterns := []string{
		filepath.Join(logDir, "*.access.log"),
		filepath.Join(logDir, "*.access.log.1"),
		filepath.Join(logDir, "access.log"),
		filepath.Join(logDir, "access.log.1"),
	}
	seen := map[string]bool{}
	var paths []string
	for _, pat := range patterns {
		matches, _ := filepath.Glob(pat)
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				paths = append(paths, m)
			}
		}
	}

	var entries []Entry
	for _, p := range paths {
		entries = append(entries, ReadFile(p)...)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Time.Before(entries[j].Time)
	})
	return entries
}

// Filter4xx5xx returns only entries with 4xx or 5xx status codes.
func Filter4xx5xx(entries []Entry) []Entry {
	out := make([]Entry, 0, len(entries)/4)
	for _, e := range entries {
		if e.Status >= 400 && e.Status < 600 {
			out = append(out, e)
		}
	}
	return out
}

// GroupByIP aggregates entries by (IP, status), returning groups sorted by count descending.
func GroupByIP(entries []Entry) []Group {
	m := map[GroupKey]*Group{}
	for _, e := range entries {
		k := GroupKey{IP: e.IP, Status: e.Status}
		g, ok := m[k]
		if !ok {
			g = &Group{
				IP:        e.IP,
				Status:    e.Status,
				Method:    e.Method,
				LastURI:   e.URI,
				UserAgent: e.UserAgent,
				FirstSeen: e.Time,
				LastSeen:  e.Time,
			}
			m[k] = g
		}
		g.Count++
		if e.Time.After(g.LastSeen) {
			g.LastSeen = e.Time
			g.LastURI = e.URI
			g.Method = e.Method
			g.UserAgent = e.UserAgent
		}
		if !e.Time.IsZero() && (g.FirstSeen.IsZero() || e.Time.Before(g.FirstSeen)) {
			g.FirstSeen = e.Time
		}
	}
	groups := make([]Group, 0, len(m))
	for _, g := range m {
		groups = append(groups, *g)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		return groups[i].IP.Compare(groups[j].IP) < 0
	})
	return groups
}
