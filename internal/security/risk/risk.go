// Package risk computes progressive security risk from normalized events. It
// exists to reduce false positives by separating benign probes from genuinely
// abusive behavior and by forcing progressive escalation instead of direct
// hard-ban on low-signal inputs.
package risk

import (
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/security/baseline"
)

const (
	CategoryBenignBootstrap  = "benign_bootstrap"
	CategoryBenignProbe      = "benign_probe"
	CategorySuspiciousProbe  = "suspicious_probe"
	CategoryWordPressProbe   = "wordpress_probe"
	CategoryScanner          = "scanner"
	CategoryExploitAttempt   = "exploit_attempt"
	CategoryCredentialAttack = "credential_attack"
	CategoryAppSecAttack     = "appsec_attack"
	CategoryConfirmedAbuse   = "confirmed_abuse"
)

const (
	DecisionObserveOnly    = "observe_only"
	DecisionSoftMitigation = "soft_mitigation"
	DecisionLocalBlock     = "local_block"
	DecisionPropagableBan  = "propagable_ban"
)

type Event struct {
	IP            string    `json:"ip"`
	URIs          []string  `json:"uris"`
	UserAgent     string    `json:"user_agent"`
	Action        string    `json:"action"`
	RuleID        string    `json:"rule_id"`
	RuleName      string    `json:"rule_name"`
	Source        string    `json:"source"`
	Timestamp     time.Time `json:"timestamp"`
	Hits          int       `json:"hits"`
	WindowSeconds int       `json:"window_seconds"`
	Allowlisted   bool      `json:"allowlisted"`
}

type Assessment struct {
	Score               int      `json:"score"`
	AbuseType           string   `json:"abuse_type"`
	Decision            string   `json:"decision"`
	Evidence            []string `json:"evidence"`
	BenignProbe         bool     `json:"benign_probe"`
	Confidence          float64  `json:"confidence"`
	SuppressedLowSignal bool     `json:"suppressed_low_signal"`
}

var defaultBaseline = baseline.NewArleoEUBaseline()

func Assess(event Event) Assessment {
	if event.Allowlisted {
		return Assessment{
			Score:               0,
			AbuseType:           CategoryBenignProbe,
			Decision:            DecisionObserveOnly,
			Evidence:            []string{"allowlisted"},
			BenignProbe:         true,
			Confidence:          0.10,
			SuppressedLowSignal: true,
		}
	}

	score := 0
	evidence := []string{}
	abuseType := CategoryBenignProbe

	uris := dedupNormalizeURIs(event.URIs)
	ua := strings.ToLower(event.UserAgent)
	ruleName := strings.ToLower(event.RuleName)
	method := strings.ToUpper(event.Action)

	onlyBenign := len(uris) > 0
	onlyBootstrap := len(uris) > 0
	for _, uri := range uris {
		switch {
		case isBaselineBootstrap(uri, method):
			score += 1
			evidence = append(evidence, "baseline_bootstrap:"+uri)
			onlyBenign = false
		case isBenignURI(uri):
			score += 1
			evidence = append(evidence, "benign_uri:"+uri)
			onlyBootstrap = false
		case isWordPressURI(uri):
			score += 3
			abuseType = CategoryWordPressProbe
			evidence = append(evidence, "wordpress_probe:"+uri)
			onlyBenign = false
			onlyBootstrap = false
		case isSensitiveExtension(uri):
			score += 10
			abuseType = CategoryExploitAttempt
			evidence = append(evidence, "sensitive_extension:"+uri)
			onlyBenign = false
			onlyBootstrap = false
		case isTraversal(uri):
			score += 10
			abuseType = CategoryExploitAttempt
			evidence = append(evidence, "traversal:"+uri)
			onlyBenign = false
			onlyBootstrap = false
		case isExploitPayload(uri):
			score += 10
			abuseType = CategoryExploitAttempt
			evidence = append(evidence, "payload:"+uri)
			onlyBenign = false
			onlyBootstrap = false
		default:
			onlyBenign = false
			onlyBootstrap = false
		}
	}
	// An explicit block by a Cloudflare firewall rule (Custom Rules, Managed Rules)
	// means the operator deliberately configured a rule to block this traffic.
	// Override the bootstrap early-return so these events reach the full scorer.
	cfExplicitBlock := strings.EqualFold(event.Action, "block") &&
		(strings.EqualFold(event.Source, "firewallCustom") ||
			strings.EqualFold(event.Source, "firewallRules") ||
			strings.EqualFold(event.Source, "firewallManaged"))

	if onlyBootstrap && !cfExplicitBlock {
		return Assessment{
			Score:               score,
			AbuseType:           CategoryBenignBootstrap,
			Decision:            DecisionObserveOnly,
			Evidence:            evidence,
			BenignProbe:         false,
			Confidence:          0.15,
			SuppressedLowSignal: true,
		}
	}

	if isLegitCrawler(ua) {
		score -= 2
		evidence = append(evidence, "legit_crawler")
	}
	knownScanner := isKnownScannerUA(ua)
	if knownScanner {
		score += 5
		if abuseType == CategoryBenignProbe || abuseType == CategorySuspiciousProbe {
			abuseType = CategoryScanner
		}
		evidence = append(evidence, "scanner_user_agent")
	}
	if strings.Contains(ruleName, "coraza") || strings.Contains(ruleName, "crs") || strings.Contains(ruleName, "owasp") {
		score += 10
		if abuseType != CategoryExploitAttempt {
			abuseType = CategoryAppSecAttack
		}
		evidence = append(evidence, "appsec_signature")
	}
	if event.Hits >= 10 {
		score += 10
		evidence = append(evidence, "high_hit_count")
	} else if event.Hits >= 3 {
		score += 5
		evidence = append(evidence, "repeat_hits")
	}

	if score < 0 {
		score = 0
	}

	if onlyBootstrap {
		abuseType = CategoryBenignBootstrap
	}
	if onlyBenign {
		abuseType = CategoryBenignProbe
	}

	// Boost score for explicit CF rule blocks; promote out of benign classification
	// so the reporting policy does not suppress them as benign_signal.
	if cfExplicitBlock {
		score += 10
		evidence = append(evidence, "cf_rule_block:"+event.Source)
		if abuseType == CategoryBenignBootstrap || abuseType == CategoryBenignProbe {
			abuseType = CategorySuspiciousProbe
		}
	}

	if abuseType == CategoryBenignProbe && score >= 5 {
		abuseType = CategorySuspiciousProbe
	}
	if score >= 20 {
		abuseType = maxSeverity(abuseType, CategoryConfirmedAbuse)
	}

	decision := DecisionObserveOnly
	switch {
	case score >= 20:
		decision = DecisionPropagableBan
	case score >= 10:
		decision = DecisionLocalBlock
	case score >= 5:
		decision = DecisionSoftMitigation
	default:
		decision = DecisionObserveOnly
	}

	confidence := confidenceFromScore(score)
	if knownScanner && confidence < 0.75 {
		confidence = 0.75
	}
	return Assessment{
		Score:               score,
		AbuseType:           abuseType,
		Decision:            decision,
		Evidence:            evidence,
		BenignProbe:         abuseType == CategoryBenignProbe,
		Confidence:          confidence,
		SuppressedLowSignal: score < 5,
	}
}

func isBaselineBootstrap(uri string, method string) bool {
	if method != "" && method != "GET" && method != "HEAD" && method != "BLOCK" && method != "ALLOW" {
		return false
	}
	_, ok := defaultBaseline.Match(uri)
	return ok
}

func dedupNormalizeURIs(uris []string) []string {
	seen := make(map[string]struct{}, len(uris))
	out := make([]string, 0, len(uris))
	for _, uri := range uris {
		normalized := strings.TrimSpace(strings.ToLower(uri))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func isBenignURI(uri string) bool {
	switch uri {
	case "/favicon.ico", "/robots.txt", "/sitemap.xml", "/apple-touch-icon.png", "/manifest.json", "/browserconfig.xml", "/health", "/healthz", "/ping":
		return true
	default:
		return false
	}
}

func isWordPressURI(uri string) bool {
	return strings.Contains(uri, "/wp-login.php") || strings.Contains(uri, "/xmlrpc.php") || strings.Contains(uri, "/wp-admin/") || strings.Contains(uri, "/wp-content")
}

func isSensitiveExtension(uri string) bool {
	return strings.Contains(uri, ".env") || strings.Contains(uri, ".bak") || strings.Contains(uri, ".sql") || strings.Contains(uri, ".zip")
}

func isTraversal(uri string) bool {
	return strings.Contains(uri, "../") || strings.Contains(uri, "%2e%2e") || strings.Contains(uri, "/etc/passwd")
}

func isExploitPayload(uri string) bool {
	return strings.Contains(uri, "union+select") || strings.Contains(uri, "<script") || strings.Contains(uri, "cmd=") || strings.Contains(uri, "exec=")
}

func isKnownScannerUA(ua string) bool {
	return strings.Contains(ua, "sqlmap") || strings.Contains(ua, "nikto") || strings.Contains(ua, "nmap") || strings.Contains(ua, "python-requests") || strings.Contains(ua, "curl/")
}

func isLegitCrawler(ua string) bool {
	return strings.Contains(ua, "googlebot") || strings.Contains(ua, "bingbot") || strings.Contains(ua, "uptimerobot") || strings.Contains(ua, "better uptime") || strings.Contains(ua, "facebookexternalhit") || strings.Contains(ua, "slackbot")
}

func confidenceFromScore(score int) float64 {
	switch {
	case score >= 20:
		return 0.95
	case score >= 10:
		return 0.82
	case score >= 5:
		return 0.65
	default:
		return 0.25
	}
}

func maxSeverity(a, b string) string {
	order := map[string]int{
		CategoryBenignBootstrap:  1,
		CategoryBenignProbe:      1,
		CategorySuspiciousProbe:  2,
		CategoryWordPressProbe:   3,
		CategoryScanner:          4,
		CategoryCredentialAttack: 5,
		CategoryAppSecAttack:     6,
		CategoryExploitAttempt:   7,
		CategoryConfirmedAbuse:   8,
	}
	if order[b] > order[a] {
		return b
	}
	return a
}
