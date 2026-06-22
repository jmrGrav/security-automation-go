package nginxerrors

import (
	"context"
	"net/netip"
	"sort"
	"time"

	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/services/autoban"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

// DefaultMinBurst is the minimum number of error-status hits from one IP
// within a single ProcessSince window before it is even worth recording as
// evidence. A single stray 404 is noise, not signal; this is the
// anti-noise/aggregation gate the HTTP error intelligence mission calls for.
// It is intentionally conservative — Task #8 makes this operator-configurable.
const DefaultMinBurst = 3

type Source interface {
	ListErrorsSince(ctx context.Context, since time.Time) ([]RawEvent, error)
}

// BanEvaluator is the subset of autoban.Evaluator used to authorize a ban for
// a pre-aggregated burst. Satisfied by *autoban.Evaluator.
type BanEvaluator interface {
	EvaluateExternalBurst(ip, reason string) autoban.BanDecision
	Log(decision autoban.BanDecision)
	RecordBan(ip string)
	// RecordBanWithDuration marks ip as banned in the dedup guard using ttl
	// as the dedup window instead of the fixed legacy TTL. Satisfied by
	// *autoban.Evaluator.
	RecordBanWithDuration(ip string, ttl time.Duration)
}

// banDurationLookup is satisfied by a BanExecutor that can report the actual
// duration applied to a specific IP's most recent ban (e.g. *cfBanExecutor
// in cmd/cf-sync, via banlifecycle). It is a small additive interface —
// banExec is type-asserted against it rather than widening
// autoban.BanExecutor itself — so existing BanExecutor implementations
// (including test fakes) keep compiling unchanged.
type banDurationLookup interface {
	LastBanDuration(ctx context.Context, ip string) (time.Duration, bool)
}

// Service aggregates raw nginx error log lines into per-IP bursts and
// records them as Evidence/Timeline only. An HTTP error burst by itself is
// never a ban decision — it has no WAF rule, no CrowdSec score, just an
// elevated error rate. It must never reach AbuseIPDB/Spamhaus or feed
// auto-ban from this path alone, unless an operator has explicitly opted
// into enforcement via SetEnforcement (config: http_error_intel.enforce_mode).
type Service struct {
	source    Source
	reporting *reporting.Service
	minBurst  int

	enforce      bool
	banThreshold int
	banEval      BanEvaluator
	banExec      autoban.BanExecutor
}

func NewService(source Source, reportingService *reporting.Service) *Service {
	return &Service{source: source, reporting: reportingService, minBurst: DefaultMinBurst}
}

// SetMinBurst overrides DefaultMinBurst. A value <= 0 leaves the default in place.
func (s *Service) SetMinBurst(minBurst int) {
	if s != nil && minBurst > 0 {
		s.minBurst = minBurst
	}
}

// SetEnforcement opts the service into auto-ban escalation for bursts whose
// count reaches banThreshold. eval and exec are still subject to every
// existing autoban safety guard (protected IP, dedup, public-IP-only, and
// Cloudflare shadow mode via eval's LiveMode) — this only decides whether
// nginxerrors bursts are offered to that evaluator at all. A nil eval or a
// banThreshold <= 1 leaves the service evidence-only (no-op).
func (s *Service) SetEnforcement(eval BanEvaluator, exec autoban.BanExecutor, banThreshold int) {
	if s == nil || eval == nil || banThreshold <= 1 {
		return
	}
	s.banEval = eval
	s.banExec = exec
	s.banThreshold = banThreshold
	s.enforce = true
}

// recordBanAfterExecute marks ip as banned in s.banEval's dedup guard using
// the real ban duration that was just applied, when s.banExec exposes one
// via banDurationLookup. Falls back to the fixed legacy TTL (RecordBan) when
// the executor doesn't support the lookup or the lookup fails — this can
// only make the dedup guard hold longer than (never shorter than) the real
// ban, which is the safe direction.
func (s *Service) recordBanAfterExecute(ctx context.Context, ip string) {
	if lookup, ok := s.banExec.(banDurationLookup); ok {
		if d, found := lookup.LastBanDuration(ctx, ip); found && d > 0 {
			s.banEval.RecordBanWithDuration(ip, d)
			return
		}
	}
	s.banEval.RecordBan(ip)
}

type burstKey struct {
	ip     string
	status int
}

type burst struct {
	ip        string
	status    int
	count     int
	method    string
	lastURI   string
	userAgent string
	firstSeen time.Time
	lastSeen  time.Time
}

type ProcessingReport struct {
	Fetched       int
	Bursts        int
	BelowMinBurst int
	Classified    int
	Reported      int
	Suppressed    int
	Banned        int
	HighWatermark time.Time
}

// ProcessSince fetches error entries strictly after since, aggregates them
// into per-IP+status bursts, and records each burst meeting minBurst as
// evidence. Callers should persist the returned HighWatermark and pass it
// back as since on the next call — without overlap — so the same burst is
// never re-recorded as a duplicate evidence row.
func (s *Service) ProcessSince(ctx context.Context, since time.Time) (ProcessingReport, error) {
	var report ProcessingReport
	if s == nil || s.source == nil || s.reporting == nil {
		return report, nil
	}

	raw, err := s.source.ListErrorsSince(ctx, since)
	if err != nil {
		return report, err
	}
	report.Fetched = len(raw)

	bursts := map[burstKey]*burst{}
	for _, e := range raw {
		if e.Timestamp.After(report.HighWatermark) {
			report.HighWatermark = e.Timestamp.UTC()
		}
		k := burstKey{ip: e.IP.String(), status: e.Status}
		b, ok := bursts[k]
		if !ok {
			b = &burst{ip: k.ip, status: k.status, firstSeen: e.Timestamp, lastSeen: e.Timestamp}
			bursts[k] = b
		}
		b.count++
		if !e.Timestamp.Before(b.lastSeen) {
			b.lastSeen = e.Timestamp
			b.lastURI = e.URI
			b.method = e.Method
			b.userAgent = e.UserAgent
		}
		if e.Timestamp.Before(b.firstSeen) {
			b.firstSeen = e.Timestamp
		}
	}

	keys := make([]burstKey, 0, len(bursts))
	for k := range bursts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ip != keys[j].ip {
			return keys[i].ip < keys[j].ip
		}
		return keys[i].status < keys[j].status
	})

	for _, k := range keys {
		b := bursts[k]
		if b.count < s.minBurst {
			report.BelowMinBurst++
			continue
		}
		report.Bursts++

		ip, err := netip.ParseAddr(b.ip)
		if err != nil {
			continue
		}
		windowSec := int(b.lastSeen.Sub(b.firstSeen).Seconds())
		normalized, err := Normalize(RawEvent{
			IP:        ip,
			Timestamp: b.lastSeen,
			Method:    b.method,
			URI:       b.lastURI,
			Status:    b.status,
			UserAgent: b.userAgent,
		})
		if err != nil {
			continue
		}
		normalized.Hits = b.count
		normalized.WindowSec = windowSec

		result, err := s.reporting.Process(ctx, reporting.Request{
			Source:       abuseformat.SourceNginxError,
			Event:        normalized,
			EvidenceOnly: true,
		})
		if err != nil {
			return report, err
		}
		report.Classified++
		if result.Reported {
			report.Reported++
		}
		if result.Suppressed {
			report.Suppressed++
		}

		if s.enforce && b.count >= s.banThreshold {
			decision := s.banEval.EvaluateExternalBurst(b.ip, "http_error_burst")
			s.banEval.Log(decision)
			if decision.ShouldBan && !decision.Shadow && s.banExec != nil {
				if err := s.banExec.ExecuteBan(ctx, decision); err == nil {
					s.recordBanAfterExecute(ctx, b.ip)
					report.Banned++
				}
			}
		}
	}

	return report, nil
}
