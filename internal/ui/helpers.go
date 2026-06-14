package ui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"
)

func joinNonEmpty(values []string, sep string) string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	return strings.Join(cleaned, sep)
}

func newUIEventID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "evt-unknown"
	}
	return hex.EncodeToString(buf[:])
}

func compactText(value string, max int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	if max <= 0 || len(value) <= max {
		return value
	}
	if max <= 1 {
		return value[:max]
	}
	return value[:max-1] + "…"
}

func compactCopyHTML(value string, max int, label string) string {
	full := strings.TrimSpace(value)
	if full == "" {
		return `<span class="muted">unknown</span>`
	}
	if label == "" {
		label = "Copied"
	}
	return fmt.Sprintf(`<span class="inline-copy" role="button" tabindex="0" title="%s" data-copy-text="%s" data-copy-label="%s">%s</span>`,
		html.EscapeString(full),
		html.EscapeString(full),
		html.EscapeString(label),
		html.EscapeString(compactText(full, max)),
	)
}

func compactLinkCopyHTML(href, value, title, panelTitle, copyLabel string, max int) string {
	full := strings.TrimSpace(value)
	if href == "" {
		return compactCopyHTML(full, max, copyLabel)
	}
	if title == "" {
		title = full
	}
	if panelTitle == "" {
		panelTitle = "Evidence Detail"
	}
	if copyLabel == "" {
		copyLabel = "Copied"
	}
	return fmt.Sprintf(`<span class="inline-copy-group"><a class="badge" href="%s" title="%s" data-live-panel-link="true" data-live-panel-title="%s">%s</a><button type="button" class="copy-button inline-copy-button" title="Copy %s" data-copy-text="%s" data-copy-label="%s">Copy</button></span>`,
		html.EscapeString(href),
		html.EscapeString(title),
		html.EscapeString(panelTitle),
		html.EscapeString(compactText(full, max)),
		html.EscapeString(title),
		html.EscapeString(full),
		html.EscapeString(copyLabel),
	)
}

func stableUIReadContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func livePanelRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	return strings.TrimSpace(r.Header.Get("X-Live-Panel")) != ""
}
