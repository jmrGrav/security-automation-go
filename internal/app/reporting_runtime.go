package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/jm/security-automation-go/internal/abuseipdb"
	crowdsecevent "github.com/jm/security-automation-go/internal/adapters/crowdsecevent"
	openrestyevent "github.com/jm/security-automation-go/internal/adapters/openrestyevent"
	"github.com/jm/security-automation-go/internal/betterstack"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

type wafReportingRuntime struct {
	service          *reporting.Service
	db               *sqlite.DB
	crowdsecSource   *crowdsecevent.LiveSource
	openrestySource  *openrestyevent.LiveSource
	crowdsecService  *crowdsecevent.Service
	openrestyService *openrestyevent.Service
	outboxWorker     *reporting.OutboxWorker
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

func (r *wafReportingRuntime) close() {
	if r != nil && r.db != nil {
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
