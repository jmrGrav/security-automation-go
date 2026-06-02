package enrichment

import (
	"strings"
)

func scoreDNS(dnsConfirmed, trusted bool) (delta int, reason string) {
	if !dnsConfirmed || !trusted {
		return 0, ""
	}
	return -5, "trusted_forward_confirmed_bot"
}

func scoreASN(kind string, protected bool) (delta int, noHardBan bool, reason string) {
	if protected {
		switch strings.ToLower(kind) {
		case "searchbot":
			return 0, true, "search_bot_network"
		case "aiagent":
			return 0, true, "ai_agent_network"
		case "monitoring":
			return 0, true, "monitoring_network"
		default: // "protected" and any future kind
			return 0, true, "protected_network"
		}
	}
	switch strings.ToLower(kind) {
	case "datacenter":
		return 2, false, "datacenter_network"
	default:
		return 0, false, ""
	}
}

func scoreProvider(verdict ProviderVerdict) (delta int, reason string) {
	if verdict.Score <= 0 {
		return 0, ""
	}
	if verdict.Manual {
		if verdict.Score > 10 {
			return 10, verdict.Provider + "_manual_signal"
		}
		return verdict.Score, verdict.Provider + "_manual_signal"
	}
	switch {
	case verdict.Score >= 90:
		return 3, verdict.Provider + "_high_signal"
	case verdict.Score >= 70:
		return 2, verdict.Provider + "_elevated_signal"
	case verdict.Score >= 40:
		return 1, verdict.Provider + "_weak_signal"
	default:
		return 0, ""
	}
}
