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
	AbuseIPDBOutboxPendingTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_outbox_pending_total",
		Help: "Total number of AbuseIPDB outbox items observed in pending state.",
	})
	AbuseIPDBOutboxFailedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_outbox_failed_total",
		Help: "Total number of AbuseIPDB outbox items observed in failed state.",
	})
	AbuseIPDBOutboxReportedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_outbox_reported_total",
		Help: "Total number of AbuseIPDB outbox items observed in reported state.",
	})
	AbuseIPDBReportsSuppressedRecentTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_reports_suppressed_recent_total",
		Help: "Total number of AbuseIPDB reports suppressed because the IP was already reported within 24 hours.",
	})
	AbuseIPDBReportDedupStoreErrorsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_report_dedup_store_errors_total",
		Help: "Total number of durable dedup store errors while evaluating or marking AbuseIPDB reports.",
	})
	EvidenceWriteFailuresTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "evidence_write_failures_total",
		Help: "Total number of failures while writing forensic evidence.",
	})
	TelemetryPublishFailuresTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "telemetry_publish_failures_total",
		Help: "Total number of non-blocking telemetry publish failures.",
	})
	AbuseIPDBRateLimitTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "abuseipdb_rate_limit_total",
		Help: "Total number of AbuseIPDB 429 rate limit errors.",
	})
	ProviderQuotaRemainingPercent = promauto.With(Registry).NewGaugeVec(prometheus.GaugeOpts{
		Name: "provider_quota_remaining_percent",
		Help: "Remaining quota percentage observed per provider.",
	}, []string{"provider"})
	ProviderQuotaState = promauto.With(Registry).NewGaugeVec(prometheus.GaugeOpts{
		Name: "provider_quota_state",
		Help: "Observed quota state per provider encoded as 0=NORMAL, 1=WARNING, 2=THROTTLED, 3=EXHAUSTED, 4=UNKNOWN.",
	}, []string{"provider"})
	ProviderQuotaRefreshFailuresTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
		Name: "provider_quota_refresh_failures_total",
		Help: "Total number of failed quota refresh attempts per provider.",
	}, []string{"provider"})
	ProviderAutoThrottleTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
		Name: "provider_auto_throttle_total",
		Help: "Total number of times a provider was automatically throttled due to low quota.",
	}, []string{"provider"})
	ProviderAutoDisableTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
		Name: "provider_auto_disable_total",
		Help: "Total number of times a provider was automatically disabled due to exhausted quota.",
	}, []string{"provider"})
	ProviderAutoReenableTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
		Name: "provider_auto_reenable_total",
		Help: "Total number of times a provider was automatically re-enabled after quota recovery.",
	}, []string{"provider"})
	AIExplainRequestsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "ai_explain_requests_total",
		Help: "Total number of AI explain requests received by the gateway.",
	})
	AIExplainFailuresTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "ai_explain_failures_total",
		Help: "Total number of failed AI explain requests.",
	})
	AIExplainCachePrunedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "ai_explain_cache_pruned_total",
		Help: "Total number of expired or evicted AI explain cache entries removed.",
	})
	AIExplainCacheEntries = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "ai_explain_cache_entries",
		Help: "Current number of AI explain cache entries in memory.",
	})
	AIProviderSelectedTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
		Name: "ai_provider_selected_total",
		Help: "Total number of selected AI providers.",
	}, []string{"provider"})
	AIProviderSkippedTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
		Name: "ai_provider_skipped_total",
		Help: "Total number of AI providers skipped during routing or fallback.",
	}, []string{"provider"})
	AIProviderRateLimitedTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
		Name: "ai_provider_rate_limited_total",
		Help: "Total number of AI provider calls rate limited or put into cooldown.",
	}, []string{"provider"})
	AIProviderTokensUsedTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
		Name: "ai_provider_tokens_used_total",
		Help: "Total number of AI tokens observed per provider.",
	}, []string{"provider"})
	AIProviderQuotaRemainingPercent = promauto.With(Registry).NewGaugeVec(prometheus.GaugeOpts{
		Name: "ai_provider_quota_remaining_percent",
		Help: "Observed remaining quota percentage per AI provider.",
	}, []string{"provider"})
	AIProviderQuotaState = promauto.With(Registry).NewGaugeVec(prometheus.GaugeOpts{
		Name: "ai_provider_quota_state",
		Help: "Observed quota state per AI provider encoded as 0=NORMAL, 1=WARNING, 2=THROTTLED, 3=EXHAUSTED, 4=UNKNOWN, 5=COOLDOWN, 6=DISABLED.",
	}, []string{"provider"})
	AIExplainCacheHitsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "ai_explain_cache_hits_total",
		Help: "Total number of cached AI explain responses.",
	})
	AIExplainLatencySeconds = promauto.With(Registry).NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ai_explain_latency_seconds",
		Help:    "Latency of AI explain calls by provider.",
		Buckets: prometheus.DefBuckets,
	}, []string{"provider"})
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
	CloudflareWAFMalformedEventsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "cloudflare_waf_malformed_events_total",
		Help: "Total number of malformed Cloudflare WAF events observed during replay.",
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
	RuntimeRecoveryDivergencesTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "runtime_recovery_divergences_total",
		Help: "Total number of recovery runs that detected runtime state divergence.",
	})
	RuntimeOwnershipInvariantViolationsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "runtime_ownership_invariant_violations_total",
		Help: "Total number of recovery runs that detected ownership invariant violations.",
	})
	CloudflareReplayCursorLoadFailuresTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "cloudflare_replay_cursor_load_failures_total",
		Help: "Total number of failures while loading the Cloudflare replay cursor.",
	})
	CloudflareReplayCursorSaveFailuresTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "cloudflare_replay_cursor_save_failures_total",
		Help: "Total number of failures while saving the Cloudflare replay cursor.",
	})
	SQLiteDegradedModeTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "sqlite_degraded_mode_total",
		Help: "Total number of times SQLite was placed into read-only degraded mode.",
	})
	SQLiteQuarantineCreatedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "sqlite_quarantine_created_total",
		Help: "Total number of SQLite quarantine artifacts created after corruption detection.",
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
	SchedulerQueueDepth = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "scheduler_queue_depth",
		Help: "Current number of queued scheduler work items.",
	})
	SchedulerQueueDroppedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "scheduler_queue_dropped_total",
		Help: "Total number of scheduler work items dropped by queue backpressure.",
	})
	SchedulerQueueCoalescedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "scheduler_queue_coalesced_total",
		Help: "Total number of scheduler work items coalesced into an existing queue entry.",
	})
	UISessionEntries = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "ui_session_entries",
		Help: "Current number of UI sessions tracked in memory.",
	})
	UISessionsPrunedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "ui_sessions_pruned_total",
		Help: "Total number of UI sessions pruned from memory.",
	})
	ReportingEvidencePrunedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "reporting_evidence_pruned_total",
		Help: "Total number of reporting evidence rows pruned by retention cleanup.",
	})
	ReportOutboxPrunedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "report_outbox_pruned_total",
		Help: "Total number of report outbox rows pruned by retention cleanup.",
	})
	ReportingDecisionGateEntries = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "reporting_decision_gate_entries",
		Help: "Current number of IP lock entries tracked by the reporting decision gate.",
	})
	ReportingDecisionGatePrunedTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "reporting_decision_gate_pruned_total",
		Help: "Total number of decision gate IP lock entries pruned.",
	})
	EventArchiveHotEntries = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "event_archive_hot_entries",
		Help: "Current number of raw archive events kept hot in the active table after checkpoint-aware compaction.",
	})
	EventArchiveWarmEntries = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "event_archive_warm_entries",
		Help: "Current number of raw archive events eligible for checkpoint-aware purge.",
	})
	EventArchiveColdEntries = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "event_archive_cold_entries",
		Help: "Current number of raw archive rows removed by checkpoint-aware compaction in the latest run.",
	})
	EventArchiveReplaySafeEntries = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "event_archive_replay_safe_entries",
		Help: "Current number of raw archive entries still safe for deterministic replay after compaction.",
	})
	EventArchivePurgeCandidates = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "event_archive_purge_candidates",
		Help: "Current number of raw archive rows eligible for purge at the active checkpoint boundary.",
	})
	EventArchiveCompactionsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "event_archive_compactions_total",
		Help: "Total number of checkpoint-aware raw archive compactions performed.",
	})
	EventArchiveRotationsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "event_archive_rotations_total",
		Help: "Total number of raw archive rotations performed while compacting checkpoint-covered history.",
	})
	EventArchiveStorageBytes = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
		Name: "event_archive_storage_bytes",
		Help: "Current SQLite storage footprint for the raw event archive and sidecar WAL/SHM files.",
	})
	SpamhausSubmitTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "spamhaus_submit_total",
		Help: "Total number of successful Spamhaus Submit API submissions.",
	})
	SpamhausSubmitFailuresTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "spamhaus_submit_failures_total",
		Help: "Total number of failed Spamhaus Submit API submissions.",
	})
	SpamhausSubmitDedupTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
		Name: "spamhaus_submit_dedup_total",
		Help: "Total number of Spamhaus submissions skipped by the 24h per-IP dedup.",
	})
)
