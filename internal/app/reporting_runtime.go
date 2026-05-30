package app

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/abuseipdb"
	cloudflareevent "github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	crowdsecevent "github.com/jm/security-automation-go/internal/adapters/crowdsecevent"
	openrestyevent "github.com/jm/security-automation-go/internal/adapters/openrestyevent"
	"github.com/jm/security-automation-go/internal/betterstack"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

// cloudflareWAFOverlap is the backward-look window applied to each WAF query
// to avoid gaps at restart. Mirrors cmd/cf-sync cloudflareReplayOverlap.
const cloudflareWAFOverlap = 10 * time.Minute

// wafCursorStore is the minimal interface for WAF cursor persistence.
// sqlite.CursorStore satisfies this.
type wafCursorStore interface {
	Load(ctx context.Context, name string) (time.Time, bool, error)
	Save(ctx context.Context, name string, value time.Time) error
}

type wafReportingRuntime struct {
	service          *reporting.Service
	db               *sqlite.DB
	crowdsecSource   *crowdsecevent.LiveSource
	openrestySource  *openrestyevent.LiveSource
	crowdsecService  *crowdsecevent.Service
	openrestyService *openrestyevent.Service
	outboxWorker     *reporting.OutboxWorker
	// cursorStore is non-nil when SQLite is available; used by startWAFReplay.
	cursorStore *sqlite.CursorStore
	// wg tracks the WAF replay goroutine so close() can wait before closing db.
	wg sync.WaitGroup
}

func newWAFReportingRuntime(ctx context.Context, logger *slog.Logger, cfg *config.Config, abuse *abuseipdb.Client, better betterstack.IngestClient) *wafReportingRuntime {
	if abuse == nil {
		return nil
	}

	telemetry := sinks.NewMulti(sinks.NewPrometheus())
	if better != nil {
		telemetry = sinks.NewMulti(sinks.NewPrometheus(), sinks.NewBetterStack(better))
	}

	service := reporting.New(abuse.Executor, telemetry, trust.DefaultRegistry(), 15*time.Minute)
	if db, err := sqlite.New(cfg.StateDir); err == nil {
		stores := sqlite.NewReportingStores(db)
		stores.Configure(service)
		return &wafReportingRuntime{
			service:          service,
			db:               db,
			crowdsecSource:   crowdsecevent.NewLiveSource(cfg.CrowdSec.DecisionsLog, cfg.CrowdSec.NginxLogDir, 24*time.Hour),
			openrestySource:  openrestyevent.NewLiveSource(cfg.OpenResty.EventsFile),
			crowdsecService:  crowdsecevent.NewService(service),
			openrestyService: openrestyevent.NewService(service),
			outboxWorker:     reporting.NewOutboxWorker(stores.Outbox, abuse.Executor, stores.Dedup, stores.Evidence, telemetry, reporting.OutboxWorkerConfig{Limit: 25, RetryBackoff: 5 * time.Minute}),
			cursorStore:      sqlite.NewCursorStore(db),
		}
	} else {
		logger.WarnContext(ctx, "failed to initialize sqlite dedup store", "error", err)
	}

	return &wafReportingRuntime{
		service:          service,
		crowdsecSource:   crowdsecevent.NewLiveSource(cfg.CrowdSec.DecisionsLog, cfg.CrowdSec.NginxLogDir, 24*time.Hour),
		openrestySource:  openrestyevent.NewLiveSource(cfg.OpenResty.EventsFile),
		crowdsecService:  crowdsecevent.NewService(service),
		openrestyService: openrestyevent.NewService(service),
	}
}

// startWAFReplay launches the Cloudflare WAF replay goroutine.
// wafSvc processes WAF events and reports to AbuseIPDB via r.service.
// The goroutine is context-bound and tracked via wg so close() can safely
// wait before closing the SQLite db (preventing use-after-close on cursor saves).
func (r *wafReportingRuntime) startWAFReplay(ctx context.Context, logger *slog.Logger, wafSvc *cloudflareevent.Service, cursor wafCursorStore, zoneID string, interval time.Duration) {
	if r == nil || wafSvc == nil || cursor == nil {
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		// Initial cursor: interval-ago, or persisted value if available.
		since := time.Now().UTC().Add(-interval)
		if persisted, ok, err := cursor.Load(ctx, "cloudflare_waf_since"); err == nil && ok {
			since = persisted.UTC()
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Apply overlap window to avoid gaps at restarts.
			querySince := since
			if cloudflareWAFOverlap > 0 && !since.IsZero() {
				querySince = since.Add(-cloudflareWAFOverlap)
			}

			report, err := wafSvc.ProcessSince(ctx, zoneID, querySince)
			if err != nil {
				logger.Warn("cloudflare waf replay failed (non-fatal)", "error", err)
			} else if report.Fetched > 0 {
				logger.Info("cloudflare waf replay processed",
					"fetched", report.Fetched,
					"classified", report.Classified,
					"reported", report.Reported,
					"suppressed", report.Suppressed,
				)
				next := report.HighWatermark
				if !next.After(since) {
					next = time.Now().UTC()
				}
				since = next.UTC()
				if saveErr := cursor.Save(ctx, "cloudflare_waf_since", since); saveErr != nil {
					logger.Warn("cloudflare waf replay cursor save failed", "error", saveErr)
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// close waits for the WAF replay goroutine then closes SQLite.
// Must be called after the context is cancelled so the goroutine can exit.
func (r *wafReportingRuntime) close() {
	if r == nil {
		return
	}
	r.wg.Wait()
	if r.db != nil {
		_ = r.db.Close()
	}
}

func (r *wafReportingRuntime) processOutbox(ctx context.Context, logger *slog.Logger) {
	if r == nil || r.outboxWorker == nil {
		return
	}
	if _, err := r.outboxWorker.ProcessOnce(ctx); err != nil {
		logger.WarnContext(ctx, "abuseipdb report outbox retry failed", "error", err)
	}
}

func (r *wafReportingRuntime) processCrowdSec(ctx context.Context, logger *slog.Logger) {
	if r == nil || r.service == nil || r.crowdsecSource == nil || r.crowdsecService == nil {
		return
	}
	events, err := r.crowdsecSource.Read(ctx)
	if err != nil {
		logger.WarnContext(ctx, "crowdsec live source failed", "error", err)
		return
	}
	for _, event := range events {
		if _, err := r.crowdsecService.Process(ctx, event); err != nil {
			logger.WarnContext(ctx, "crowdsec event processing failed", "ip", event.IP, "rule_id", event.RuleID, "error", err)
		}
	}
}

func (r *wafReportingRuntime) processOpenResty(ctx context.Context, logger *slog.Logger) {
	if r == nil || r.service == nil || r.openrestySource == nil || r.openrestyService == nil {
		return
	}
	events, err := r.openrestySource.Read(ctx)
	if err != nil {
		logger.WarnContext(ctx, "openresty live source failed", "error", err)
		return
	}
	for _, event := range events {
		if _, err := r.openrestyService.Process(ctx, event); err != nil {
			logger.WarnContext(ctx, "openresty event processing failed", "ip", event.IP, "rule_id", event.RuleID, "error", err)
		}
	}
}
