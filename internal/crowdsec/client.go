package crowdsec

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/crowdsec/models"
	"github.com/jm/security-automation-go/internal/crowdsec/source"
)

// localOrigins is the set of CrowdSec origins synced to Cloudflare.
// Mirrors Python's LOCAL_ORIGINS = {"crowdsec", "cscli"}.
var localOrigins = map[string]bool{
	"crowdsec": true,
	"cscli":    true,
}

// lookbackDefault is the window used by ListRecentBans.
// Mirrors Python's LOOKBACK_HOURS = 48.
const lookbackDefault = 48 * time.Hour

// ActiveBanSource is the interface used by app.CrowdSecSyncApp.
type ActiveBanSource interface {
	ListActiveBans(ctx context.Context) ([]string, error)
	ListRecentBans(ctx context.Context) ([]models.RecentBan, error)
}

// AllowlistManager is the interface used by app.AllowlistSyncApp.
type AllowlistManager interface {
	ListAllowlist(ctx context.Context, name string) ([]models.AllowlistEntry, error)
	AddAllowlistEntry(ctx context.Context, name string, entry models.AllowlistEntry) error
}

// DecisionManager is the interface for applying CrowdSec decisions via cscli.
type DecisionManager interface {
	AddIPDecision(ctx context.Context, ip, duration, reason string) error
	AddRangeDecision(ctx context.Context, cidr, duration, reason string) error
}

// cscliRunner is an injectable subprocess runner for allowlist and decision commands.
// Separate from source.CommandRunner to avoid a package dependency cycle.
type cscliRunner interface {
	run(ctx context.Context, bin string, args ...string) ([]byte, error)
}

type realCscliRunner struct{ timeout time.Duration }

func (r *realCscliRunner) run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	opCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	cmd := exec.CommandContext(opCtx, bin, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("cscli %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// Client implements ActiveBanSource, AllowlistManager, and DecisionManager.
type Client struct {
	src        source.DecisionSource
	decLogPath string
	lookback   time.Duration
	cscliBin   string
	runner     cscliRunner
}

// NewClient creates a Client using cscli as the decision source (production default).
func NewClient() *Client {
	return newClient("cscli", 15*time.Second, "/var/log/crowdsec/decisions.log")
}

// NewClientFromConfig creates a Client from explicit config fields.
// binPath="" → "cscli"; timeout=0 → 15s; decLogPath="" → system default.
func NewClientFromConfig(binPath, decLogPath string, timeout time.Duration) *Client {
	if binPath == "" {
		binPath = "cscli"
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	if decLogPath == "" {
		decLogPath = "/var/log/crowdsec/decisions.log"
	}
	return newClient(binPath, timeout, decLogPath)
}

// NewClientWithSource creates a Client with an injected DecisionSource.
// Used for testing and replay scenarios.
func NewClientWithSource(src source.DecisionSource, decLogPath string) *Client {
	return &Client{
		src:        src,
		decLogPath: decLogPath,
		lookback:   lookbackDefault,
		cscliBin:   "cscli",
		runner:     &realCscliRunner{timeout: 15 * time.Second},
	}
}

func newClient(binPath string, timeout time.Duration, decLogPath string) *Client {
	return &Client{
		src:        source.NewCSCLISource(binPath, timeout),
		decLogPath: decLogPath,
		lookback:   lookbackDefault,
		cscliBin:   binPath,
		runner:     &realCscliRunner{timeout: timeout},
	}
}

// ListActiveBans returns IPs currently banned by CrowdSec (local origins only).
//
// Mirrors Python's get_active_bans():
//   - Fetches all decisions via cscli decisions list -o json (no --origin, bug #4470)
//   - Filters: origin in {"crowdsec","cscli"}, type=="ban", scope.lower()=="ip"
//   - Returns nil slice on source failure (callers should treat nil as skip-this-cycle)
func (c *Client) ListActiveBans(ctx context.Context) ([]string, error) {
	alerts, err := c.src.ListAlerts(ctx)
	if err != nil {
		return nil, fmt.Errorf("crowdsec.Client.ListActiveBans: %w", err)
	}
	return source.FilterActiveBanIPs(alerts), nil
}

// decisionLogLine is the JSON structure of each line in decisions.log.
type decisionLogLine struct {
	DT string `json:"dt"`
	CS struct {
		EventType string `json:"event_type"`
		Origin    string `json:"origin"`
		Type      string `json:"type"`
		Scenario  string `json:"scenario"`
		IP        string `json:"ip"`
		ID        int64  `json:"id"`
		Action    string `json:"action"`
	} `json:"cs"`
}

// ListRecentBans reads decisions.log and returns bans within the lookback window.
//
// Mirrors Python's get_recent_local_bans(hours=LOOKBACK_HOURS=48):
//   - event_type "alert": action=="banned", skip cloudflare-waf + recidivist scenarios
//   - event_type "decision": origin in LOCAL_ORIGINS, type=="ban", same scenario filters
//   - Applies cutoff; validates IP with net.ParseIP
func (c *Client) ListRecentBans(ctx context.Context) ([]models.RecentBan, error) {
	lookback := c.lookback
	if lookback == 0 {
		lookback = lookbackDefault
	}
	cutoff := time.Now().UTC().Add(-lookback)

	f, err := os.Open(c.decLogPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("crowdsec.Client.ListRecentBans: open %s: %w", c.decLogPath, err)
	}
	defer f.Close()

	var bans []models.RecentBan
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry decisionLogLine
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		cs := entry.CS
		switch cs.EventType {
		case "alert":
			if cs.Action != "banned" {
				continue
			}
			if strings.Contains(cs.Scenario, "cloudflare-waf") ||
				strings.HasPrefix(cs.Scenario, "recidivist-escalation") {
				continue
			}
		case "decision":
			if !localOrigins[strings.ToLower(cs.Origin)] {
				continue
			}
			if cs.Type != "ban" {
				continue
			}
			if strings.HasPrefix(cs.Scenario, "cloudflare-waf") ||
				strings.HasPrefix(cs.Scenario, "recidivist-escalation") {
				continue
			}
		default:
			continue
		}

		dt, err := parseISO(entry.DT)
		if err != nil || dt.Before(cutoff) {
			continue
		}
		if net.ParseIP(cs.IP) == nil {
			continue
		}

		origin := cs.Origin
		if origin == "" {
			origin = "crowdsec"
		}
		bans = append(bans, models.RecentBan{
			IP:       cs.IP,
			Scenario: cs.Scenario,
			Origin:   strings.ToLower(origin),
			When:     dt,
			ID:       fmt.Sprintf("%d", cs.ID),
		})
	}
	if err := scanner.Err(); err != nil {
		return bans, fmt.Errorf("crowdsec.Client.ListRecentBans: scan: %w", err)
	}
	return bans, nil
}

// ListAllowlist returns entries in a named CrowdSec allowlist.
// Mirrors Python's get_crowdsec_allowlist(): cscli allowlists inspect <name> -o json.
func (c *Client) ListAllowlist(ctx context.Context, name string) ([]models.AllowlistEntry, error) {
	out, err := c.runner.run(ctx, c.cscliBin, "allowlists", "inspect", name, "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("crowdsec.Client.ListAllowlist: %w", err)
	}
	var parsed struct {
		Items []struct {
			Value   string `json:"value"`
			Comment string `json:"comment"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("crowdsec.Client.ListAllowlist: parse: %w", err)
	}
	entries := make([]models.AllowlistEntry, 0, len(parsed.Items))
	for _, item := range parsed.Items {
		if item.Value != "" {
			entries = append(entries, models.AllowlistEntry{Value: item.Value, Comment: item.Comment})
		}
	}
	return entries, nil
}

// AddAllowlistEntry adds an entry to a named CrowdSec allowlist.
// Mirrors Python's: cscli allowlists add <name> <value> --comment <comment>.
func (c *Client) AddAllowlistEntry(ctx context.Context, name string, entry models.AllowlistEntry) error {
	args := []string{"allowlists", "add", name, entry.Value}
	if entry.Comment != "" {
		args = append(args, "--comment", entry.Comment)
	}
	_, err := c.runner.run(ctx, c.cscliBin, args...)
	if err != nil {
		return fmt.Errorf("crowdsec.Client.AddAllowlistEntry: %w", err)
	}
	return nil
}

// AddIPDecision adds an IP ban via cscli.
// Mirrors Python's escalate_ban(): cscli decisions add --ip <ip> --duration <d> --type ban --reason <r>.
func (c *Client) AddIPDecision(ctx context.Context, ip, duration, reason string) error {
	_, err := c.runner.run(ctx, c.cscliBin,
		"decisions", "add", "--ip", ip,
		"--duration", duration, "--type", "ban", "--reason", reason,
	)
	if err != nil {
		return fmt.Errorf("crowdsec.Client.AddIPDecision: %w", err)
	}
	return nil
}

// AddRangeDecision adds a CIDR range ban via cscli.
// Mirrors Python's: cscli decisions add --range <cidr> ...
func (c *Client) AddRangeDecision(ctx context.Context, cidr, duration, reason string) error {
	_, err := c.runner.run(ctx, c.cscliBin,
		"decisions", "add", "--range", cidr,
		"--duration", duration, "--type", "ban", "--reason", reason,
	)
	if err != nil {
		return fmt.Errorf("crowdsec.Client.AddRangeDecision: %w", err)
	}
	return nil
}

// parseISO parses an ISO 8601 timestamp, handling "Z" → "+00:00".
// Mirrors Python's _parse_dt(): dt_str.replace("Z", "+00:00").
func parseISO(s string) (time.Time, error) {
	s = strings.ReplaceAll(s, "Z", "+00:00")
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s)
	}
	return t, err
}
