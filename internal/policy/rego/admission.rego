package cfsync.admission

default decision = "allow"

# 1. Deny if breaker is open
decision = "deny" {
    input.runtime.breaker_state == "open"
}

# 2. Quarantine if hostile drift detected
decision = "quarantine" {
    input.drift.classification == "hostile"
    input.drift.risk_score >= 0.9
}

# 3. Require approval for large batches
decision = "require_approval" {
    input.batch.operations != null
    count(input.batch.operations) > 100
}

# 4. Require approval for destructive operations
decision = "require_approval" {
    input.batch.destructive_count > 25
}

# 5. Deny if governor pressure is critical
decision = "cooldown" {
    input.governor.pressure >= 0.95
}
