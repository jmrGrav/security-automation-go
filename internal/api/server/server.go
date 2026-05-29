package server

import (
	"log/slog"
	"net/http"

	"github.com/jm/security-automation-go/internal/api/auth"
	"github.com/jm/security-automation-go/internal/api/handlers"
	v2 "github.com/jm/security-automation-go/internal/api/handlers/v2"
	v3 "github.com/jm/security-automation-go/internal/api/handlers/v3"
	"github.com/jm/security-automation-go/internal/api/middleware"
	"github.com/jm/security-automation-go/internal/policy/admission"
	"github.com/jm/security-automation-go/internal/policy/bundles/activation"
	"github.com/jm/security-automation-go/internal/policy/bundles/registry"
	"github.com/jm/security-automation-go/internal/policy/federation"
	"github.com/jm/security-automation-go/internal/policy/replay/recorder"
	driftmemory "github.com/jm/security-automation-go/internal/runtime/drift/memory"
	"github.com/jm/security-automation-go/internal/runtime/engine"
	"github.com/jm/security-automation-go/internal/runtime/governor"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
	"github.com/jm/security-automation-go/internal/runtime/quarantine"
	"github.com/jm/security-automation-go/internal/runtime/scheduler/pool"
	"github.com/jm/security-automation-go/internal/runtime/status"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

type Server struct {
	mux    *http.ServeMux
	logger *slog.Logger
}

func New(
	logger *slog.Logger,
	collector *status.Collector,
	j journal.JournalStore,
	qStore *quarantine.Store,
	or *ownership.Resolver,
	g *governor.ResourceGovernor,
	p *pool.Pool,
	sm *engine.StateMachine,
	dm *driftmemory.Store,
	rec *recorder.Recorder,
	reg *registry.Registry,
	act *activation.Manager,
	fed *federation.Resolver,
	adm *admission.Controller,
	evidence reporting.EvidenceStore,
	ownershipLineage *ownership.LineageQueryService,
	authenticator *auth.Authenticator,
) *Server {
	mux := http.NewServeMux()

	// API v1
	h1 := handlers.NewBaseHandler(collector, j, qStore)
	v1Mux := http.NewServeMux()
	v1Mux.HandleFunc("GET /status", h1.GetStatus)
	v1Mux.HandleFunc("GET /audit/events", h1.GetAuditEvents)
	v1Mux.HandleFunc("POST /reconcile/run", h1.TriggerReconcile)
	v1Mux.HandleFunc("POST /quarantine/release", h1.ReleaseQuarantine)

	// API v2
	h2 := v2.NewV2Handler(or, g, p, sm, dm, rec, reg, act)
	v2Mux := http.NewServeMux()
	v2Mux.HandleFunc("GET /ownership/claims", h2.GetOwnershipClaims)
	v2Mux.HandleFunc("GET /governor/budgets", h2.GetGovernorStatus)
	v2Mux.HandleFunc("GET /workers", h2.GetWorkersStatus)
	v2Mux.HandleFunc("GET /drift/memory", h2.GetDriftMemory)
	v2Mux.HandleFunc("GET /policy/evidence", h2.GetPolicyEvidence)
	v2Mux.HandleFunc("GET /policy/bundles", h2.GetPolicyBundles)
	v2Mux.HandleFunc("POST /runtime/pause", h2.RuntimePause)
	v2Mux.HandleFunc("POST /runtime/resume", h2.RuntimeResume)

	// API v3
	h3 := v3.NewV3Handler(adm, evidence, ownershipLineage)
	v3Mux := http.NewServeMux()
	v3Mux.HandleFunc("GET /policy/explain", h3.GetExplainDecision)
	v3Mux.HandleFunc("GET /security/evidence", h3.GetSecurityEvidence)
	v3Mux.HandleFunc("GET /security/evidence/{evidence_id}", h3.GetSecurityEvidence)
	v3Mux.HandleFunc("GET /security/evidence/{evidence_id}/explain", h3.GetExplainSecurityEvidence)
	v3Mux.HandleFunc("GET /security/ownership/lineage", h3.GetOwnershipLineage)
	v3Mux.HandleFunc("GET /security/ownership/lineage/page", h3.GetOwnershipLineagePage)
	v3Mux.HandleFunc("GET /security/ownership/lineage/{event_id}", h3.GetOwnershipLineage)
	v3Mux.HandleFunc("GET /security/ownership/lineage/{event_id}/explain", h3.GetExplainOwnershipLineage)

	// Chain middlewares
	v1Handler := middleware.Auth(authenticator)(v1Mux)
	v1Handler = middleware.Tracing(v1Handler)
	v1Handler = middleware.Logging(logger)(v1Handler)
	v1Handler = middleware.Recovery(logger)(v1Handler)

	v2Handler := middleware.Auth(authenticator)(v2Mux)
	v2Handler = middleware.Tracing(v2Handler)
	v2Handler = middleware.Logging(logger)(v2Handler)
	v2Handler = middleware.Recovery(logger)(v2Handler)

	v3Handler := middleware.Auth(authenticator)(v3Mux)
	v3Handler = middleware.Tracing(v3Handler)
	v3Handler = middleware.Logging(logger)(v3Handler)
	v3Handler = middleware.Recovery(logger)(v3Handler)

	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", v1Handler))
	mux.Handle("/api/v2/", http.StripPrefix("/api/v2", v2Handler))
	mux.Handle("/api/v3/", http.StripPrefix("/api/v3", v3Handler))

	return &Server{
		mux:    mux,
		logger: logger,
	}
}

func (s *Server) Handler() http.Handler {
	return s.mux
}
