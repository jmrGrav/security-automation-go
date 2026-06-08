// Package poller polls the CrowdSec LAPI and cscli for decisions and alerts,
// writing newline-delimited JSON records to decisions.log for Vector/BetterStack.
// It is the Go replacement for crowdsec-poller.py.
package poller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sync/atomic"
	"time"
)

// Config holds all tunables for the poller.
type Config struct {
	// LAPIURL is the base URL of the CrowdSec LAPI, e.g. "http://127.0.0.1:8080".
	LAPIURL string
	// LAPIKey is the X-Api-Key used to authenticate against the LAPI.
	LAPIKey string
	// Interval between poll cycles. Default 30s.
	Interval time.Duration
	// Enabled gates the poller; when false, Run returns immediately.
	Enabled bool
	// LogPath is the file written for Vector/BetterStack. Default /var/log/crowdsec/decisions.log.
	LogPath string
	// CscliBin is the path to the cscli binary. Default "cscli".
	CscliBin string
	// Timeout for the LAPI HTTP request and cscli invocation. Default 15s.
	Timeout time.Duration
}

func (c *Config) setDefaults() {
	if c.LAPIURL == "" {
		c.LAPIURL = "http://127.0.0.1:8080"
	}
	if c.Interval <= 0 {
		c.Interval = 30 * time.Second
	}
	if c.LogPath == "" {
		c.LogPath = "/var/log/crowdsec/decisions.log"
	}
	if c.CscliBin == "" {
		c.CscliBin = "cscli"
	}
	if c.Timeout <= 0 {
		c.Timeout = 15 * time.Second
	}
}

// Metrics are runtime counters exposed on the Poller.
type Metrics struct {
	PollSuccessTotal   atomic.Int64
	PollErrorTotal     atomic.Int64
	DecisionsWritten   atomic.Int64
	LastSuccessUnixSec atomic.Int64
	LastErrorUnixSec   atomic.Int64
}

// Poller polls CrowdSec and writes decisions.log.
type Poller struct {
	cfg     Config
	logger  *slog.Logger
	lapi    *lapiClient
	writer  *logWriter
	host    string
	Metrics Metrics

	seenDecisions map[int64]struct{}
	seenAlerts    map[int64]struct{}
}

// New creates a Poller. Returns nil if cfg.Enabled is false.
// The LAPI key must be set in cfg.LAPIKey (from CredentialStore) before calling New.
// Run() returns an error immediately if the key is absent (fail-closed).
func New(cfg Config, logger *slog.Logger) *Poller {
	if !cfg.Enabled {
		return nil
	}
	cfg.setDefaults()
	host, _ := os.Hostname()
	return &Poller{
		cfg:           cfg,
		logger:        logger,
		lapi:          newLAPIClient(cfg.LAPIURL, cfg.LAPIKey, cfg.Timeout),
		writer:        newLogWriter(cfg.LogPath),
		host:          host,
		seenDecisions: make(map[int64]struct{}),
		seenAlerts:    make(map[int64]struct{}),
	}
}

// Run starts the poll loop and blocks until ctx is cancelled.
// Returns an error immediately if the LAPI key is absent (fail-closed).
func (p *Poller) Run(ctx context.Context) error {
	if p.cfg.LAPIKey == "" {
		return errors.New("crowdsec lapi key is not configured — set it via the UI Settings panel or first-run wizard")
	}
	p.logger.InfoContext(ctx, "crowdsec poller starting",
		"interval", p.cfg.Interval,
		"lapi_url", p.cfg.LAPIURL,
		"log_path", p.cfg.LogPath,
	)

	if err := p.preload(ctx); err != nil {
		p.logger.WarnContext(ctx, "poller preload failed — starting clean", "error", err)
	}

	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			p.tick(ctx)
		}
	}
}

// preload reads the existing log to rebuild in-memory seen-ID sets,
// preventing a flood of duplicate records after a restart.
func (p *Poller) preload(ctx context.Context) error {
	decIDs, alertIDs, err := loadSeenIDs(p.cfg.LogPath)
	if err != nil {
		return err
	}
	p.seenDecisions = decIDs
	p.seenAlerts = alertIDs
	p.logger.InfoContext(ctx, "poller preloaded seen IDs",
		"decisions", len(p.seenDecisions),
		"alerts", len(p.seenAlerts),
	)
	return nil
}

func (p *Poller) tick(ctx context.Context) {
	nd, na, err := p.poll(ctx)
	if err != nil {
		p.Metrics.PollErrorTotal.Add(1)
		p.Metrics.LastErrorUnixSec.Store(time.Now().Unix())
		p.logger.WarnContext(ctx, "poller tick error", "error", err)
		return
	}
	p.Metrics.PollSuccessTotal.Add(1)
	p.Metrics.LastSuccessUnixSec.Store(time.Now().Unix())
	if nd > 0 || na > 0 {
		p.logger.InfoContext(ctx, "poller tick",
			"new_decisions", nd,
			"new_alerts", na,
		)
	}
}

func (p *Poller) poll(ctx context.Context) (nd, na int, err error) {
	nd, errD := p.processDecisions(ctx)
	na, errA := p.processAlerts(ctx)

	if errD != nil && errA != nil {
		return 0, 0, fmt.Errorf("decisions: %w; alerts: %v", errD, errA)
	}
	if errD != nil {
		return 0, na, fmt.Errorf("decisions: %w", errD)
	}
	if errA != nil {
		return nd, 0, fmt.Errorf("alerts: %w", errA)
	}
	return nd, na, nil
}

func (p *Poller) processDecisions(ctx context.Context) (int, error) {
	decisions, err := p.lapi.fetchDecisions(ctx)
	if err != nil {
		return 0, err
	}

	now := nowISO()
	count := 0
	for _, d := range decisions {
		if _, seen := p.seenDecisions[d.ID]; seen {
			continue
		}
		p.seenDecisions[d.ID] = struct{}{}

		ip := d.Value
		if ip == "" {
			ip = "unknown"
		}

		if err := p.writer.write(DecisionRecord{
			DT:       now,
			Host:     p.host,
			Platform: "CrowdSec",
			CS: decisionFields{
				EventType: "decision",
				ID:        d.ID,
				IP:        ip,
				Type:      orDefault(d.Type, "unknown"),
				Scenario:  orDefault(d.Scenario, "unknown"),
				Duration:  orDefault(d.Duration, "unknown"),
				Origin:    orDefault(d.Origin, "unknown"),
				Scope:     orDefault(d.Scope, "unknown"),
				Simulated: d.Simulated,
			},
		}); err != nil {
			return count, fmt.Errorf("write decision %d: %w", d.ID, err)
		}
		p.Metrics.DecisionsWritten.Add(1)
		count++
	}
	return count, nil
}

func (p *Poller) processAlerts(ctx context.Context) (int, error) {
	cscliCtx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()

	//nolint:gosec // bin path comes from trusted config, not user input
	cmd := exec.CommandContext(cscliCtx, p.cfg.CscliBin, "alerts", "list", "--output", "json")
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("cscli alerts list: %w", err)
	}

	alerts, err := parseAlerts(out)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, a := range alerts {
		if _, seen := p.seenAlerts[a.ID]; seen {
			continue
		}
		p.seenAlerts[a.ID] = struct{}{}

		ip := a.Source.IP
		if ip == "" {
			ip = "unknown"
		}
		// Fallback: enrich from events[].meta when source.ip is absent (appsec).
		if ip == "unknown" {
			if v := a.metaLookup("source_ip"); v != "" {
				ip = v
			}
		}

		dt := a.CreatedAt
		if dt == "" {
			dt = nowISO()
		}

		action := "detected"
		if a.hasDecision() {
			action = "banned"
		}

		if err := p.writer.write(DecisionRecord{
			DT:       dt,
			Host:     p.host,
			Platform: "CrowdSec",
			CS: decisionFields{
				EventType:   "alert",
				ID:          a.ID,
				IP:          ip,
				Scenario:    orDefault(a.Scenario, "unknown"),
				Action:      action,
				HasDecision: a.hasDecision(),
			},
		}); err != nil {
			return count, fmt.Errorf("write alert %d: %w", a.ID, err)
		}
		p.Metrics.DecisionsWritten.Add(1)
		count++
	}
	return count, nil
}

func nowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
