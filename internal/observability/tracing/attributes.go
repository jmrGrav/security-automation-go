package tracing

import (
	"go.opentelemetry.io/otel/attribute"
)

// Standard attributes for cf-sync traces.
const (
	AttrRunID            = attribute.Key("cf_sync.run_id")
	AttrPlanID           = attribute.Key("cf_sync.plan_id")
	AttrBatchID          = attribute.Key("cf_sync.batch_id")
	AttrOpID             = attribute.Key("cf_sync.op_id")
	AttrSnapshotChecksum = attribute.Key("cf_sync.snapshot_checksum")
	AttrResourceKind     = attribute.Key("cf_sync.resource_kind")
	AttrResourceSIK      = attribute.Key("cf_sync.resource_sik")
	AttrReplayMode       = attribute.Key("cf_sync.replay_mode")
	AttrSuccess          = attribute.Key("cf_sync.success")
	AttrOperationType    = attribute.Key("cf_sync.operation_type")
	AttrDriftDetected    = attribute.Key("cf_sync.drift_detected")
	AttrObjectCount      = attribute.Key("cf_sync.object_count")
	AttrZoneScope        = attribute.Key("cf_sync.zone_scope")
)

// Cloudflare specific attributes
const (
	AttrCFEndpoint = attribute.Key("cloudflare.endpoint")
	AttrCFPage     = attribute.Key("cloudflare.page")
)

// Breaker specific attributes
const (
	AttrBreakerOldState = attribute.Key("breaker.old_state")
	AttrBreakerNewState = attribute.Key("breaker.new_state")
	AttrBreakerReason   = attribute.Key("breaker.reason")
)
