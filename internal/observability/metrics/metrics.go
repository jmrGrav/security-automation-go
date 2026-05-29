package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Registry is a dedicated Prometheus registry for cf-sync.
var Registry = prometheus.NewRegistry()

var (
	// Counters
	ReconciliationRunsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "reconciliation_runs_total",
		Help: "Total number of reconciliation runs started.",
	})
	ReconciliationFailuresTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "reconciliation_failures_total",
		Help: "Total number of reconciliation runs that failed.",
	})
	MutationOperationsTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
		Name: "mutation_operations_total",
		Help: "Total number of mutation operations planned.",
	}, []string{"type"}) // type: create, update, delete
	MutationFailuresTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
		Name: "mutation_failures_total",
		Help: "Total number of mutation operations that failed.",
	}, []string{"type"})
	BreakerOpenTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "breaker_open_total",
		Help: "Total number of times the circuit breaker opened.",
	})
	QuarantineEventsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "quarantine_events_total",
		Help: "Total number of items moved to quarantine.",
	})
	ReplayFailuresTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "replay_failures_total",
		Help: "Total number of offline replay failures.",
	})
	AbuseIPDBReportsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_reports_total",
		Help: "Total number of successful AbuseIPDB reports.",
	})
	AbuseIPDBFailuresTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_failures_total",
		Help: "Total number of failed AbuseIPDB reports.",
	})
	AbuseIPDBReportsSentTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_reports_sent_total",
		Help: "Total number of AbuseIPDB reports emitted after all reporting guards.",
	})
	AbuseIPDBReportsSuppressedRecentTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_reports_suppressed_recent_total",
		Help: "Total number of AbuseIPDB reports suppressed because the IP was already reported within 24 hours.",
	})
	AbuseIPDBReportDedupStoreErrorsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_report_dedup_store_errors_total",
		Help: "Total number of durable dedup store errors while evaluating or marking AbuseIPDB reports.",
	})
	AbuseIPDBRateLimitTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_rate_limit_total",
		Help: "Total number of AbuseIPDB 429 rate limit errors.",
	})
	AbuseIPDBPreBanChecksTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_preban_checks_total",
		Help: "Total number of AbuseIPDB pre-ban check evaluations.",
	})
	AbuseIPDBPreBanAllowedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_preban_allowed_total",
		Help: "Total number of AbuseIPDB pre-ban checks that allowed propagation.",
	})
	AbuseIPDBPreBanSuppressedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_preban_suppressed_total",
		Help: "Total number of AbuseIPDB pre-ban checks that suppressed propagation.",
	})
	AbuseIPDBPreBanFalsePositiveSuspectedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_preban_false_positive_suspected_total",
		Help: "Total number of pre-ban checks that marked a probable false positive.",
	})
	AbuseIPDBPreBanAPIErrorsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_preban_api_errors_total",
		Help: "Total number of API errors during AbuseIPDB pre-ban checks.",
	})
	CloudflareEventsReplayedLocalTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "cloudflare_events_replayed_local_total",
		Help: "Total number of Cloudflare events replayed through the local classifier.",
	})
	CloudflareEventsClassifiedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "cloudflare_events_classified_total",
		Help: "Total number of Cloudflare events classified locally.",
	})
	CloudflareEventsReportedAbuseIPDBTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "cloudflare_events_reported_abuseipdb_total",
		Help: "Total number of Cloudflare replay events reported to AbuseIPDB.",
	})
	CloudflareEventsSuppressedLowConfidenceTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "cloudflare_events_suppressed_low_confidence_total",
		Help: "Total number of Cloudflare replay events suppressed due to low confidence.",
	})
	AbuseIPDBCategoryMappingTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
		Name: "abuseipdb_category_mapping_total",
		Help: "Total number of category mappings emitted by local classification.",
	}, []string{"category"})
	AbuseIPDBReportSourceTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
		Name: "abuseipdb_report_source_total",
		Help: "Total number of AbuseIPDB reports by source.",
	}, []string{"source"})
	AbuseIPDBCommentGeneratedTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
		Name: "abuseipdb_comment_generated_total",
		Help: "Total number of canonical AbuseIPDB comments generated by source.",
	}, []string{"source"})
	AbuseIPDBCommentTruncatedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_comment_truncated_total",
		Help: "Total number of AbuseIPDB comments truncated to fit the canonical limit.",
	})
	AbuseIPDBCommentMissingFieldsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_comment_missing_fields_total",
		Help: "Total number of AbuseIPDB comments generated with missing canonical fields.",
	})
	SecurityBenignProbeTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "security_benign_probe_total",
		Help: "Total number of events classified as benign probes.",
	})
	SecurityFalsePositiveSuppressedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "security_false_positive_suppressed_total",
		Help: "Total number of events suppressed as false positives or low-signal detections.",
	})
	SecuritySoftMitigationTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "security_soft_mitigation_total",
		Help: "Total number of events escalated only to soft mitigation.",
	})
	SecurityProgressiveEscalationTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "security_progressive_escalation_total",
		Help: "Total number of events escalated through progressive enforcement.",
	})
	SecurityHardBanAllowedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "security_hard_ban_allowed_total",
		Help: "Total number of events allowed to progress to a propagable hard ban.",
	})
	SecurityLowSignalSuppressedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "security_low_signal_suppressed_total",
		Help: "Total number of low-signal detections suppressed before propagation/reporting.",
	})
	DependencyResolutionFailuresTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "dependency_resolution_failures_total",
		Help: "Total number of failures during resource graph resolution.",
	})
	SnapshotGraphCyclesTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "snapshot_graph_cycles_total",
		Help: "Total number of cyclic dependencies detected in resource graph.",
	})
	OrphanResourceTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "orphan_resource_total",
		Help: "Total number of resources detected without a valid parent reference.",
	})

	// Histograms
	DiscoveryDurationSeconds = promauto.With(Registry).NewHistogram(prometheus.HistogramOpts{
		Name:    "discovery_duration_seconds",
		Help:    "Time spent fetching resources from Cloudflare.",
		Buckets: prometheus.DefBuckets,
	})
	PlanningDurationSeconds = promauto.With(Registry).NewHistogram(prometheus.HistogramOpts{
		Name:    "planning_duration_seconds",
		Help:    "Time spent calculating reconciliation plans.",
		Buckets: prometheus.DefBuckets,
	})
	ExecutionDurationSeconds = promauto.With(Registry).NewHistogram(prometheus.HistogramOpts{
		Name:    "execution_duration_seconds",
		Help:    "Total time spent executing mutation batches.",
		Buckets: prometheus.DefBuckets,
	})
	CSCLIExecutionDurationSeconds = promauto.With(Registry).NewHistogram(prometheus.HistogramOpts{
		Name:    "cscli_execution_duration_seconds",
		Help:    "Time spent executing individual cscli commands.",
		Buckets: prometheus.DefBuckets,
	})
	AbuseIPDBExecutionDurationSeconds = promauto.With(Registry).NewHistogram(prometheus.HistogramOpts{
		Name:    "abuseipdb_execution_duration_seconds",
		Help:    "Time spent sending reports to AbuseIPDB.",
		Buckets: prometheus.DefBuckets,
	})
	AbuseIPDBPreBanScore = promauto.With(Registry).NewHistogram(prometheus.HistogramOpts{
		Name:    "abuseipdb_preban_score",
		Help:    "Observed AbuseIPDB score during pre-ban checks.",
		Buckets: prometheus.LinearBuckets(0, 10, 11),
	})
	AbuseIPDBReportAgeSeconds = promauto.With(Registry).NewHistogram(prometheus.HistogramOpts{
		Name:    "abuseipdb_report_age_seconds",
		Help:    "Age in seconds since the last successful AbuseIPDB report for the same IP.",
		Buckets: prometheus.ExponentialBuckets(60, 4, 9),
	})
	CloudflareLocalReplayConfidenceScore = promauto.With(Registry).NewHistogram(prometheus.HistogramOpts{
		Name:    "cloudflare_local_replay_confidence_score",
		Help:    "Confidence score produced by local replay classification of Cloudflare events.",
		Buckets: prometheus.LinearBuckets(0, 0.1, 11),
	})
	SecurityRiskScore = promauto.With(Registry).NewHistogram(prometheus.HistogramOpts{
		Name:    "security_risk_score",
		Help:    "Calculated security risk score for normalized events.",
		Buckets: prometheus.LinearBuckets(0, 2, 16),
	})

	// Gauges
	BreakerState = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "breaker_state",
		Help: "Current state of the circuit breaker (0=closed, 1=open, 2=half-open).",
	})
	DaemonHealth = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "daemon_health",
		Help: "Current health status of the daemon (1=healthy, 0=unhealthy).",
	})
	SnapshotObjectsTotal = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "snapshot_objects_total",
		Help: "Total number of objects in the last successful snapshot.",
	})
	SnapshotResourceTotal = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "snapshot_resource_total",
		Help: "Total number of unique resource types in the last snapshot graph.",
	})
	RulesetObjectsTotal = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "ruleset_objects_total",
		Help: "Total number of ruleset objects in the last snapshot.",
	})
	RulesetPhaseConflictsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "ruleset_phase_conflicts_total",
		Help: "Total number of phase precedence conflicts detected.",
	})
	RulesetPrecedenceDriftTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "ruleset_precedence_drift_total",
		Help: "Total number of rules with precedence drift detected.",
	})
	OrphanRulesTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "orphan_rules_total",
		Help: "Total number of rules without a valid ruleset container.",
	})
	PendingQuarantineObjects = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "pending_quarantine_objects",
		Help: "Number of objects currently in quarantine.",
	})

	// Scheduler & Coordination
	SchedulerRunsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "scheduler_runs_total",
		Help: "Total number of scheduled reconciliation loops.",
	})
	SchedulerRetriesTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "scheduler_retries_total",
		Help: "Total number of autonomous retries.",
	})
	SchedulerCooldownsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "scheduler_cooldowns_total",
		Help: "Total number of cooldown periods started.",
	})
	SchedulerOscillationsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "scheduler_oscillations_total",
		Help: "Total number of resource oscillations detected.",
	})
	SchedulerPaused = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "scheduler_paused",
		Help: "Whether the scheduler is currently paused (1=paused, 0=running).",
	})
	SchedulerCooldownActive = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "scheduler_cooldown_active",
		Help: "Whether a cooldown is currently active.",
	})
)
