// Package abuseformat generates canonical AbuseIPDB comments for every
// detection source. It enforces one stable format for local CrowdSec/OpenResty
// detections and Cloudflare-replayed detections.
package abuseformat

import (
	"fmt"
	"sort"
	"strings"
)

const maxCommentLength = 300
const maxURIs = 5

type Source string

const (
	SourceCrowdSecWAF   Source = "crowdsec_waf"
	SourceOpenRestyWAF  Source = "openresty_waf"
	SourceCloudflareWAF Source = "cloudflare_waf"
	SourceNginxError    Source = "nginx_http_error"
)

type Input struct {
	Source     Source
	Hits       int
	WindowSec  int
	Action     string
	AbuseType  string
	Categories []string
	RuleID     string
	URIs       []string
	Confidence float64
}

func Build(in Input) string {
	prefix := sourcePrefix(in.Source)
	categories := normalizeCategories(in.Categories)
	uris := normalizeURIs(in.URIs)
	if in.RuleID == "" {
		in.RuleID = "unknown"
	}

	comment := fmt.Sprintf(
		"%s: %d hits in %ds | action=%s | abuse=%s | categories=%s | rule_id=%s | URIs=%s | confidence=%.2f",
		prefix,
		in.Hits,
		in.WindowSec,
		in.Action,
		in.AbuseType,
		strings.Join(categories, ","),
		in.RuleID,
		strings.Join(uris, ","),
		in.Confidence,
	)

	if len(comment) > maxCommentLength {
		comment = comment[:maxCommentLength-1] + "…"
	}
	return comment
}

func normalizeCategories(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, category := range in {
		normalized := strings.TrimSpace(category)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func normalizeURIs(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, uri := range in {
		normalized := strings.TrimSpace(uri)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	if len(out) > maxURIs {
		out = out[:maxURIs]
	}
	return out
}

func sourcePrefix(source Source) string {
	switch source {
	case SourceCrowdSecWAF:
		return "CrowdSec WAF"
	case SourceOpenRestyWAF:
		return "OpenResty WAF"
	case SourceNginxError:
		return "Nginx HTTP Error"
	default:
		return "Cloudflare WAF"
	}
}
