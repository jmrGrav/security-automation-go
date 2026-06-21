package crowdsecevent

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

var accessLogRequestPattern = regexp.MustCompile(`"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)`)

type LiveSource struct {
	DecisionsLog string
	NginxLogDir  string
	Lookback     time.Duration

	mu       sync.Mutex
	seenIDs  map[string]struct{}
	seenLine map[string]struct{}
}

func NewLiveSource(decisionsLog string, nginxLogDir string, lookback time.Duration) *LiveSource {
	if lookback <= 0 {
		lookback = 24 * time.Hour
	}
	return &LiveSource{
		DecisionsLog: decisionsLog,
		NginxLogDir:  nginxLogDir,
		Lookback:     lookback,
		seenIDs:      make(map[string]struct{}),
		seenLine:     make(map[string]struct{}),
	}
}

type decisionEnvelope struct {
	DT string `json:"dt"`
	CS struct {
		EventType string     `json:"event_type"`
		Origin    string     `json:"origin"`
		Action    string     `json:"action"`
		Type      string     `json:"type"`
		Scenario  string     `json:"scenario"`
		IP        string     `json:"ip"`
		ID        any        `json:"id"`
		WAF       *wafDetail `json:"waf"`
	} `json:"cs"`
}

// wafDetail mirrors poller.wafDetail — the optional Coraza/OWASP-CRS
// rule-level detail attached to "alert" records in decisions.log.
type wafDetail struct {
	RuleID       string `json:"rule_id,omitempty"`
	Message      string `json:"message,omitempty"`
	Category     string `json:"category,omitempty"`
	URI          string `json:"uri,omitempty"`
	MatchedZones string `json:"matched_zones,omitempty"`
	Data         string `json:"data,omitempty"`
	TargetFQDN   string `json:"target_fqdn,omitempty"`
}

func (s *LiveSource) Read(ctx context.Context) ([]RawEvent, error) {
	_ = ctx
	if strings.TrimSpace(s.DecisionsLog) == "" {
		return nil, nil
	}
	f, err := os.Open(s.DecisionsLog)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	cutoff := time.Now().UTC().Add(-s.Lookback)
	events := make([]RawEvent, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var env decisionEnvelope
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			continue
		}
		rawID := strings.TrimSpace(stringify(env.CS.ID))
		if !s.acceptDecision(env.CS.EventType, strings.ToLower(strings.TrimSpace(env.CS.Origin)), env.CS.Action, env.CS.Type, env.CS.Scenario) {
			continue
		}
		ts, ok := parseISOTime(env.DT)
		if !ok || ts.Before(cutoff) {
			continue
		}
		ip := strings.TrimSpace(env.CS.IP)
		if _, err := netip.ParseAddr(ip); err != nil {
			continue
		}
		if !s.markSeen(rawID, line) {
			continue
		}

		uris := s.lookupURIs(ip, 5)
		ruleID := rawID
		ruleName := env.CS.Scenario
		hostname := ""
		if env.CS.WAF != nil {
			if env.CS.WAF.URI != "" {
				uris = append([]string{env.CS.WAF.URI}, uris...)
			}
			if env.CS.WAF.RuleID != "" {
				ruleID = env.CS.WAF.RuleID
			}
			if env.CS.WAF.Message != "" {
				ruleName = env.CS.WAF.Message
			}
			hostname = env.CS.WAF.TargetFQDN
		}

		// Alerts with no attached CrowdSec decision are detections only —
		// the Lua AppSec fusion check already blocked the request in-band,
		// but no ban exists. Mark them evidence-only so the Service never
		// reports them upstream. Real ban decisions (eventType=="decision")
		// and confirmed bans (alert with a decision attached) keep the
		// existing "block" action and full reporting path.
		eventAction := "block"
		if env.CS.EventType == "alert" && strings.ToLower(strings.TrimSpace(env.CS.Action)) != "banned" {
			eventAction = "detected"
		}

		events = append(events, RawEvent{
			IP:        ip,
			Hostname:  hostname,
			URIs:      uris,
			Action:    eventAction,
			RuleID:    ruleID,
			RuleName:  ruleName,
			Timestamp: ts,
			Hits:      max(1, len(uris)),
			WindowSec: int(s.Lookback.Seconds()),
		})
	}
	return events, scanner.Err()
}

func (s *LiveSource) acceptDecision(eventType, origin, action, decisionType, scenario string) bool {
	switch eventType {
	case "alert":
		// Accept both confirmed bans and detection-only alerts (e.g. a
		// single Coraza/CRS match that triggered an in-request block but
		// has no CrowdSec decision yet). Detection-only alerts are tagged
		// "detected" above and routed through the evidence-only path by
		// the Service — they are never reported upstream from here.
	case "decision":
		if decisionType != "ban" {
			return false
		}
		// Accept local agent decisions, manual cscli bans, and CAPI community blocklist.
		// origin is already lowercased by the caller.
		switch origin {
		case "crowdsec", "cscli", "capi":
		default:
			return false
		}
	default:
		return false
	}
	scenario = strings.ToLower(strings.TrimSpace(scenario))
	return !strings.Contains(scenario, "cloudflare-waf") && !strings.HasPrefix(scenario, "recidivist-escalation")
}

func (s *LiveSource) markSeen(id string, line string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != "" {
		if _, ok := s.seenIDs[id]; ok {
			return false
		}
		s.seenIDs[id] = struct{}{}
		return true
	}
	if _, ok := s.seenLine[line]; ok {
		return false
	}
	s.seenLine[line] = struct{}{}
	return true
}

func (s *LiveSource) lookupURIs(ip string, maxURIs int) []string {
	if strings.TrimSpace(s.NginxLogDir) == "" {
		return nil
	}
	entries, err := filepath.Glob(filepath.Join(s.NginxLogDir, "*.log"))
	if err != nil {
		return nil
	}
	uris := make([]string, 0, maxURIs)
	seen := make(map[string]struct{}, maxURIs)
	for _, file := range entries {
		name := filepath.Base(file)
		if strings.Contains(name, "error") || strings.Contains(name, "csp") {
			continue
		}
		buf, err := readFileTail(file, 2*1024*1024)
		if err != nil {
			continue
		}
		lines := strings.Split(string(buf), "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			line := lines[i]
			if !strings.Contains(line, ip) {
				continue
			}
			match := accessLogRequestPattern.FindStringSubmatch(line)
			if len(match) < 2 {
				continue
			}
			uri := strings.TrimSpace(match[1])
			if uri == "" {
				continue
			}
			if _, ok := seen[uri]; ok {
				continue
			}
			seen[uri] = struct{}{}
			uris = append(uris, uri)
			if len(uris) >= maxURIs {
				return uris
			}
		}
	}
	slices.Sort(uris)
	return uris
}

func readFileTail(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	size, err := f.Seek(0, 2)
	if err != nil {
		return nil, err
	}
	start := size - maxBytes
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, 0); err != nil {
		return nil, err
	}
	return ioReadAll(f)
}

func parseISOTime(raw string) (time.Time, bool) {
	ts, err := time.Parse(time.RFC3339, strings.ReplaceAll(strings.TrimSpace(raw), "Z", "+00:00"))
	if err != nil {
		return time.Time{}, false
	}
	return ts.UTC(), true
}

func stringify(v any) string {
	switch vv := v.(type) {
	case string:
		return vv
	case float64:
		return strconv.FormatFloat(vv, 'f', -1, 64)
	default:
		raw, _ := json.Marshal(v)
		return strings.Trim(string(raw), `"`)
	}
}

func ioReadAll(f *os.File) ([]byte, error) {
	return io.ReadAll(f)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
