package wiring

import (
	"fmt"
	"strings"

	"github.com/jm/security-automation-go/internal/config"
)

type Matrix struct {
	Profile string

	Fencing                      bool
	Lease                        bool
	LeaderCoordination           bool
	Audit                        bool
	Telemetry                    bool
	Ownership                    bool
	PolicyEngine                 bool
	Governor                     bool
	OPA                          bool
	OutboxWorker                 bool
	OutboxLeaseGuard             bool
	AbuseIPDBReportingConfigured bool
	AbuseIPDBReportingEnabled    bool
}

func (m Matrix) ValidateStartup() error {
	var failures []string
	require := func(name string, ok bool, why string, configPath string) {
		if !ok {
			failures = append(failures, fmt.Sprintf("%s requires %s because %s. Active config: %s.", profileName(m.Profile), name, why, configPath))
		}
	}

	require("fencing", m.Fencing, "mutations and rollbacks must reject stale writers", "runtime.profile="+profileName(m.Profile))
	require("lease", m.Lease, "mutation epochs must be bound to owned execution", "runtime.profile="+profileName(m.Profile))
	require("audit", m.Audit, "append-only evidence and replay inputs must be recorded", "runtime.profile="+profileName(m.Profile))
	require("telemetry", m.Telemetry, "guard refusals and runtime failures must be observable", "runtime.profile="+profileName(m.Profile))
	require("ownership", m.Ownership, "domain authority checks must remain in the mutation path", "runtime.profile="+profileName(m.Profile))
	require("policy_engine", m.PolicyEngine, "admission policy must remain in the mutation path", "runtime.profile="+profileName(m.Profile))
	require("governor", m.Governor, "provider mutation limits must remain active", "runtime.profile="+profileName(m.Profile))
	require("opa", m.OPA, "OPA bundle evaluation must remain active", "runtime.profile="+profileName(m.Profile))

	if m.Profile == config.RuntimeProfileStrictHA {
		require("leader_coordination", m.LeaderCoordination, "HA execution must prevent split-brain writers", "runtime.profile=strict-ha")
		if !m.AbuseIPDBReportingConfigured {
			failures = append(failures, "strict-ha requires abuseipdb.reporting_enabled because reporting mode must be explicit. Active config: runtime.profile=strict-ha. Set abuseipdb.reporting_enabled to true or false.")
		}
		if m.AbuseIPDBReportingEnabled {
			if !m.OutboxWorker {
				failures = append(failures, "strict-ha requires outbox_worker because abuseipdb reporting is enabled. Active config: runtime.profile=strict-ha, abuseipdb.reporting_enabled=true. Configure AbuseIPDB client or disable reporting explicitly.")
			}
			if !m.OutboxLeaseGuard {
				failures = append(failures, "strict-ha requires outbox_lease_guard because abuseipdb reporting is enabled and retries must stop after lease loss. Active config: runtime.profile=strict-ha, abuseipdb.reporting_enabled=true. Configure the outbox lease guard or disable reporting explicitly.")
			}
		}
	}

	if len(failures) > 0 {
		return fmt.Errorf("runtime startup validation failed:\n%s", strings.Join(failures, "\n"))
	}
	return nil
}

func profileName(profile string) string {
	if profile == "" {
		return config.RuntimeProfileSingleNode
	}
	return profile
}
