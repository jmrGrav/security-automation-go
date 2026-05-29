package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	"github.com/jm/security-automation-go/internal/api/auth"
	"github.com/jm/security-automation-go/internal/api/server"
	"github.com/jm/security-automation-go/internal/observability/handlers"
	"github.com/jm/security-automation-go/internal/orchestrator/pipeline"
	"github.com/jm/security-automation-go/internal/policy/admission"
	"github.com/jm/security-automation-go/internal/policy/bundles/activation"
	"github.com/jm/security-automation-go/internal/policy/bundles/registry"
	"github.com/jm/security-automation-go/internal/policy/federation"
	"github.com/jm/security-automation-go/internal/policy/replay/recorder"
	"github.com/jm/security-automation-go/internal/runtime/drift/memory"
	"github.com/jm/security-automation-go/internal/runtime/engine"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
	"github.com/jm/security-automation-go/internal/runtime/quarantine"
	"github.com/jm/security-automation-go/internal/runtime/scheduler/pool"
	"github.com/jm/security-automation-go/internal/runtime/status"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

const cloudflareReplayOverlap = 10 * time.Minute

type cursorStateStore interface {
	Load(ctx context.Context, name string) (time.Time, bool, error)
	Save(ctx context.Context, name string, value time.Time) error
}

func newAuthenticator() *auth.Authenticator {
	authTokens := map[string]auth.Identity{
		"admin-token": {
			OperatorID: "admin",
			Scopes: []auth.Scope{
				auth.ScopeRuntimeRead,
				auth.ScopeRuntimeExecute,
				auth.ScopeRuntimeRollback,
				auth.ScopeQuarantineManage,
				auth.ScopeAuditRead,
			},
		},
	}
	return auth.NewAuthenticator(authTokens)
}

func startAPIServer(logger *slog.Logger, collector *status.Collector, j journal.JournalStore, qStore *quarantine.Store, orch *pipeline.Orchestrator, p *pool.Pool, sm *engine.StateMachine, dm *memory.Store, rec *recorder.Recorder, br *registry.Registry, am *activation.Manager, fr *federation.Resolver, adm *admission.Controller, evidence reporting.EvidenceStore, ownershipLineage *ownership.LineageQueryService, metricsAddr string) *http.Server {
	apiSrv := server.New(
		logger,
		collector,
		j,
		qStore,
		orch.GetOwnershipResolver(),
		orch.GetGovernor(),
		p,
		sm,
		dm,
		rec,
		br,
		am,
		fr,
		adm,
		evidence,
		ownershipLineage,
		newAuthenticator(),
	)

	mux := http.NewServeMux()
	mux.Handle("/metrics", handlers.NewMetricsHandler())
	mux.Handle("/api/v1/", apiSrv.Handler())
	mux.Handle("/api/v2/", apiSrv.Handler())
	mux.Handle("/api/v3/", apiSrv.Handler())
	mux.Handle("/statusz", handlers.StatuszHandler(collector))
	mux.HandleFunc("/healthz", handlers.HealthzHandler)
	mux.HandleFunc("/readyz", handlers.ReadyzHandler)

	srv := &http.Server{
		Addr:    metricsAddr,
		Handler: mux,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server failed", "error", err)
		}
	}()
	return srv
}

func newDaemonContext(ctx context.Context, logger *slog.Logger, srv *http.Server) (context.Context, context.CancelFunc) {
	childCtx, cancel := context.WithCancel(ctx)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.Info("received signal, shutting down", "signal", sig)

		shutdownCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		_ = srv.Shutdown(shutdownCtx)

		cancel()
	}()

	return childCtx, cancel
}

func startWAFReplayPoller(ctx context.Context, logger *slog.Logger, interval time.Duration, zoneID string, wafReplay *cloudflareevent.Service, cursorStore cursorStateStore) {
	if wafReplay == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		since := loadWAFReplayCursor(ctx, logger, cursorStore, interval)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			since = runWAFReplayIteration(ctx, logger, zoneID, wafReplay, cursorStore, since, time.Now().UTC())

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func runWAFReplayIteration(ctx context.Context, logger *slog.Logger, zoneID string, wafReplay *cloudflareevent.Service, cursorStore cursorStateStore, since time.Time, now time.Time) time.Time {
	querySince := replayQuerySince(since, cloudflareReplayOverlap)
	report, err := wafReplay.ProcessSince(ctx, zoneID, querySince)
	if err != nil {
		logger.Warn("cloudflare waf replay failed", "error", err)
		return since
	}
	if report.Fetched > 0 {
		logger.Info("cloudflare waf replay processed",
			"fetched", report.Fetched,
			"classified", report.Classified,
			"reported", report.Reported,
			"suppressed", report.Suppressed,
		)
	}
	nextCursor := nextWAFReplayCursor(report, since, now)
	if cursorStore != nil {
		if err := cursorStore.Save(ctx, "cloudflare_waf_since", nextCursor); err != nil {
			logger.Warn("cloudflare waf replay cursor save failed", "error", err)
			return since
		}
	}
	return nextCursor
}

func loadWAFReplayCursor(ctx context.Context, logger *slog.Logger, cursorStore cursorStateStore, interval time.Duration) time.Time {
	since := time.Now().UTC().Add(-interval)
	if cursorStore == nil {
		return since
	}
	persisted, ok, err := cursorStore.Load(ctx, "cloudflare_waf_since")
	if err != nil {
		logger.Warn("cloudflare waf replay cursor load failed", "error", err)
		return since
	}
	if ok {
		return persisted.UTC()
	}
	return since
}

func replayQuerySince(since time.Time, overlap time.Duration) time.Time {
	if since.IsZero() {
		return since
	}
	if overlap <= 0 {
		return since.UTC()
	}
	return since.UTC().Add(-overlap)
}

func nextWAFReplayCursor(report cloudflareevent.ProcessingReport, previous time.Time, now time.Time) time.Time {
	if report.HighWatermark.After(previous) {
		return report.HighWatermark.UTC()
	}
	if now.After(previous) {
		return now.UTC()
	}
	return previous.UTC()
}
