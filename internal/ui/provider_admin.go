package ui

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/ai/providers"
)

const (
	providerStatusReady         = "READY"
	providerStatusDisabled      = "DISABLED"
	providerStatusMissingSecret = "MISSING_SECRET"
	providerStatusInvalidSecret = "INVALID_SECRET"
	providerStatusRateLimited   = "RATE_LIMITED"
	providerStatusError         = "ERROR"

	providerTestReady        = "READY"
	providerTestAuthFailed   = "AUTH_FAILED"
	providerTestRateLimited  = "RATE_LIMITED"
	providerTestNetworkError = "NETWORK_ERROR"
	providerTestTimeout      = "TIMEOUT"
	providerTestUnknownError = "UNKNOWN_ERROR"

	providerTestPrompt = "provider readiness check"
)

type ProviderFactory func(ai.ProviderConfig) providers.Provider

type AIProviderName string

const (
	AIProviderOpenAI    AIProviderName = "openai"
	AIProviderAnthropic AIProviderName = "anthropic"
	AIProviderGemini    AIProviderName = "gemini"
)

type AIProviderRecord struct {
	Enabled           bool
	Model             string
	LastTestAt        time.Time
	LastTestStatus    string
	LastTestLatencyMS int
	LastErrorCode     string
}

type AIProviderState struct {
	OpenAI    AIProviderRecord
	Anthropic AIProviderRecord
	Gemini    AIProviderRecord
}

func providerSpec(name AIProviderName) (display string, prefix string) {
	switch name {
	case AIProviderOpenAI:
		return "OpenAI", "AI_PROVIDER_OPENAI"
	case AIProviderAnthropic:
		return "Anthropic", "AI_PROVIDER_ANTHROPIC"
	case AIProviderGemini:
		return "Gemini", "AI_PROVIDER_GEMINI"
	default:
		return strings.Title(string(name)), ""
	}
}

func providerCredentialKeyForName(name AIProviderName) string {
	switch name {
	case AIProviderOpenAI:
		return "ai.openai.api_key"
	case AIProviderAnthropic:
		return "ai.anthropic.api_key"
	case AIProviderGemini:
		return "ai.gemini.api_key"
	default:
		return ""
	}
}

func providerStateRecord(state AIProviderState, name AIProviderName) AIProviderRecord {
	switch name {
	case AIProviderOpenAI:
		return state.OpenAI
	case AIProviderAnthropic:
		return state.Anthropic
	case AIProviderGemini:
		return state.Gemini
	default:
		return AIProviderRecord{}
	}
}

func setProviderStateRecord(state *AIProviderState, name AIProviderName, record AIProviderRecord) {
	if state == nil {
		return
	}
	switch name {
	case AIProviderOpenAI:
		state.OpenAI = record
	case AIProviderAnthropic:
		state.Anthropic = record
	case AIProviderGemini:
		state.Gemini = record
	}
}

func providerNames() []AIProviderName {
	return []AIProviderName{AIProviderOpenAI, AIProviderAnthropic, AIProviderGemini}
}

func loadAIProviderState(path string) (AIProviderState, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return AIProviderState{}, false, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return AIProviderState{}, false, nil
		}
		return AIProviderState{}, false, fmt.Errorf("read provider state file: %w", err)
	}
	return parseAIProviderState(raw)
}

func parseAIProviderState(raw []byte) (AIProviderState, bool, error) {
	state := AIProviderState{}
	seen := false
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		seen = true
		switch key {
		case "OPENAI_ENABLED", "AI_PROVIDER_OPENAI_ENABLED":
			state.OpenAI.Enabled, _ = strconv.ParseBool(value)
		case "OPENAI_MODEL", "AI_PROVIDER_OPENAI_MODEL":
			state.OpenAI.Model = value
		case "OPENAI_LAST_TEST_AT", "AI_PROVIDER_OPENAI_LAST_TEST_AT":
			state.OpenAI.LastTestAt, _ = time.Parse(time.RFC3339, value)
		case "OPENAI_LAST_TEST_STATUS", "AI_PROVIDER_OPENAI_LAST_TEST_STATUS":
			state.OpenAI.LastTestStatus = value
		case "OPENAI_LAST_TEST_LATENCY_MS", "AI_PROVIDER_OPENAI_LAST_TEST_LATENCY_MS":
			if n, err := strconv.Atoi(value); err == nil {
				state.OpenAI.LastTestLatencyMS = n
			}
		case "OPENAI_LAST_ERROR_CODE", "AI_PROVIDER_OPENAI_LAST_ERROR_CODE":
			state.OpenAI.LastErrorCode = value
		case "ANTHROPIC_ENABLED", "AI_PROVIDER_ANTHROPIC_ENABLED":
			state.Anthropic.Enabled, _ = strconv.ParseBool(value)
		case "ANTHROPIC_MODEL", "AI_PROVIDER_ANTHROPIC_MODEL":
			state.Anthropic.Model = value
		case "ANTHROPIC_LAST_TEST_AT", "AI_PROVIDER_ANTHROPIC_LAST_TEST_AT":
			state.Anthropic.LastTestAt, _ = time.Parse(time.RFC3339, value)
		case "ANTHROPIC_LAST_TEST_STATUS", "AI_PROVIDER_ANTHROPIC_LAST_TEST_STATUS":
			state.Anthropic.LastTestStatus = value
		case "ANTHROPIC_LAST_TEST_LATENCY_MS", "AI_PROVIDER_ANTHROPIC_LAST_TEST_LATENCY_MS":
			if n, err := strconv.Atoi(value); err == nil {
				state.Anthropic.LastTestLatencyMS = n
			}
		case "ANTHROPIC_LAST_ERROR_CODE", "AI_PROVIDER_ANTHROPIC_LAST_ERROR_CODE":
			state.Anthropic.LastErrorCode = value
		case "GEMINI_ENABLED", "AI_PROVIDER_GEMINI_ENABLED":
			state.Gemini.Enabled, _ = strconv.ParseBool(value)
		case "GEMINI_MODEL", "AI_PROVIDER_GEMINI_MODEL":
			state.Gemini.Model = value
		case "GEMINI_LAST_TEST_AT", "AI_PROVIDER_GEMINI_LAST_TEST_AT":
			state.Gemini.LastTestAt, _ = time.Parse(time.RFC3339, value)
		case "GEMINI_LAST_TEST_STATUS", "AI_PROVIDER_GEMINI_LAST_TEST_STATUS":
			state.Gemini.LastTestStatus = value
		case "GEMINI_LAST_TEST_LATENCY_MS", "AI_PROVIDER_GEMINI_LAST_TEST_LATENCY_MS":
			if n, err := strconv.Atoi(value); err == nil {
				state.Gemini.LastTestLatencyMS = n
			}
		case "GEMINI_LAST_ERROR_CODE", "AI_PROVIDER_GEMINI_LAST_ERROR_CODE":
			state.Gemini.LastErrorCode = value
		}
	}
	if err := scanner.Err(); err != nil {
		return AIProviderState{}, false, fmt.Errorf("scan provider state: %w", err)
	}
	return state, seen, nil
}

func saveAIProviderState(path string, state AIProviderState) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("provider state file path is required")
	}
	var buf bytes.Buffer
	for _, name := range providerNames() {
		record := providerStateRecord(state, name)
		prefix := providerStatePrefix(name)
		fmt.Fprintf(&buf, "%s_ENABLED=%t\n", prefix, record.Enabled)
		fmt.Fprintf(&buf, "%s_MODEL=%s\n", prefix, record.Model)
		if !record.LastTestAt.IsZero() {
			fmt.Fprintf(&buf, "%s_LAST_TEST_AT=%s\n", prefix, record.LastTestAt.UTC().Format(time.RFC3339))
		} else {
			fmt.Fprintf(&buf, "%s_LAST_TEST_AT=\n", prefix)
		}
		fmt.Fprintf(&buf, "%s_LAST_TEST_STATUS=%s\n", prefix, record.LastTestStatus)
		fmt.Fprintf(&buf, "%s_LAST_TEST_LATENCY_MS=%d\n", prefix, record.LastTestLatencyMS)
		fmt.Fprintf(&buf, "%s_LAST_ERROR_CODE=%s\n", prefix, record.LastErrorCode)
	}
	return atomicWriteFile(path, buf.Bytes(), 0o640, -1, -1)
}

func providerStatePrefix(name AIProviderName) string {
	switch name {
	case AIProviderOpenAI:
		return "OPENAI"
	case AIProviderAnthropic:
		return "ANTHROPIC"
	case AIProviderGemini:
		return "GEMINI"
	default:
		_, prefix := providerSpec(name)
		return prefix
	}
}

func applyAIProviderState(base ai.Config, state AIProviderState, loaded bool) ai.Config {
	if !loaded {
		return base
	}
	if state.OpenAI.Model != "" {
		base.OpenAI.Model = state.OpenAI.Model
	}
	base.OpenAI.Enabled = state.OpenAI.Enabled
	if state.Anthropic.Model != "" {
		base.Anthropic.Model = state.Anthropic.Model
	}
	base.Anthropic.Enabled = state.Anthropic.Enabled
	if state.Gemini.Model != "" {
		base.Gemini.Model = state.Gemini.Model
	}
	base.Gemini.Enabled = state.Gemini.Enabled
	return base
}

func atomicWriteFile(path string, data []byte, perm os.FileMode, uid, gid int) (retErr error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("file path is required")
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if retErr != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		retErr = fmt.Errorf("write temp file: %w", err)
		return retErr
	}
	if err := tmp.Chmod(perm); err != nil {
		retErr = fmt.Errorf("chmod temp file: %w", err)
		return retErr
	}
	if uid >= 0 || gid >= 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			retErr = fmt.Errorf("chown temp file: %w", err)
			return retErr
		}
	}
	if err := tmp.Sync(); err != nil {
		retErr = fmt.Errorf("fsync temp file: %w", err)
		return retErr
	}
	if err := tmp.Close(); err != nil {
		retErr = fmt.Errorf("close temp file: %w", err)
		return retErr
	}
	if err := os.Rename(tmpPath, path); err != nil {
		retErr = fmt.Errorf("rename temp file: %w", err)
		return retErr
	}
	if err := syncDir(dir); err != nil {
		retErr = fmt.Errorf("fsync dir: %w", err)
		return retErr
	}
	return nil
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return err
	}
	return nil
}

func aiProviderSettingKey(name AIProviderName, field string) string {
	return "ai." + strings.ToLower(string(name)) + "." + field
}

func loadAIProviderStateFromStore(ctx context.Context, store SetupStorer) (AIProviderState, bool, error) {
	var state AIProviderState
	seen := false
	for _, name := range providerNames() {
		rec := AIProviderRecord{}
		if v, ok, err := store.GetSetting(ctx, aiProviderSettingKey(name, "enabled")); err != nil {
			return AIProviderState{}, false, err
		} else if ok {
			rec.Enabled, _ = strconv.ParseBool(v)
			seen = true
		}
		if v, ok, err := store.GetSetting(ctx, aiProviderSettingKey(name, "model")); err != nil {
			return AIProviderState{}, false, err
		} else if ok {
			rec.Model = v
			seen = true
		}
		if v, ok, err := store.GetSetting(ctx, aiProviderSettingKey(name, "last_test_at")); err != nil {
			return AIProviderState{}, false, err
		} else if ok && v != "" {
			rec.LastTestAt, _ = time.Parse(time.RFC3339, v)
			seen = true
		}
		if v, ok, err := store.GetSetting(ctx, aiProviderSettingKey(name, "last_test_status")); err != nil {
			return AIProviderState{}, false, err
		} else if ok {
			rec.LastTestStatus = v
			seen = true
		}
		if v, ok, err := store.GetSetting(ctx, aiProviderSettingKey(name, "last_test_latency_ms")); err != nil {
			return AIProviderState{}, false, err
		} else if ok && v != "" {
			if n, parseErr := strconv.Atoi(v); parseErr == nil {
				rec.LastTestLatencyMS = n
			}
			seen = true
		}
		if v, ok, err := store.GetSetting(ctx, aiProviderSettingKey(name, "last_error_code")); err != nil {
			return AIProviderState{}, false, err
		} else if ok {
			rec.LastErrorCode = v
			seen = true
		}
		setProviderStateRecord(&state, name, rec)
	}
	return state, seen, nil
}

func saveAIProviderStateToStore(ctx context.Context, store SetupStorer, state AIProviderState) error {
	for _, name := range providerNames() {
		rec := providerStateRecord(state, name)
		if err := store.SetSetting(ctx, aiProviderSettingKey(name, "enabled"), strconv.FormatBool(rec.Enabled)); err != nil {
			return err
		}
		if err := store.SetSetting(ctx, aiProviderSettingKey(name, "model"), rec.Model); err != nil {
			return err
		}
		testAt := ""
		if !rec.LastTestAt.IsZero() {
			testAt = rec.LastTestAt.UTC().Format(time.RFC3339)
		}
		if err := store.SetSetting(ctx, aiProviderSettingKey(name, "last_test_at"), testAt); err != nil {
			return err
		}
		if err := store.SetSetting(ctx, aiProviderSettingKey(name, "last_test_status"), rec.LastTestStatus); err != nil {
			return err
		}
		if err := store.SetSetting(ctx, aiProviderSettingKey(name, "last_test_latency_ms"), strconv.Itoa(rec.LastTestLatencyMS)); err != nil {
			return err
		}
		if err := store.SetSetting(ctx, aiProviderSettingKey(name, "last_error_code"), rec.LastErrorCode); err != nil {
			return err
		}
	}
	return nil
}

func loadAIStateFromStoreOrFile(ctx context.Context, store SetupStorer, filePath string) (AIProviderState, bool, error) {
	if store != nil {
		state, loaded, err := loadAIProviderStateFromStore(ctx, store)
		if err != nil {
			return AIProviderState{}, false, err
		}
		if loaded {
			return state, true, nil
		}
	}
	return loadAIProviderState(filePath)
}

func providerStatePathHint(path string) string {
	lines := []string{
		fmt.Sprintf("impossible to write the provider state at %s", path),
		"Run:",
		"sudo install -d -m 755 -o root -g root /etc/security-automation-go",
	}
	lines = append(lines,
		"sudo install -d -m 750 -o security-automation -g security-automation /var/lib/security-automation-go/runtime",
		fmt.Sprintf("sudo install -m 0640 -o security-automation -g security-automation /dev/null %s", path),
	)
	return strings.Join(lines, "\n")
}

func providerManagementEntry(name AIProviderName, cfg ai.ProviderConfig, configured bool, record AIProviderRecord) AIProviderManagementEntry {
	display, _ := providerSpec(name)
	secretState := providerStatusMissingSecret
	if configured {
		secretState = "configured"
	}
	status := providerManagementStatus(record.Enabled, secretState, record.LastTestStatus)
	return AIProviderManagementEntry{
		Name:              display,
		Status:            status,
		Model:             valueOrFallback(cfg.Model, "unconfigured"),
		Enabled:           record.Enabled,
		SecretState:       secretState,
		SecretPathDisplay: "SQLite credential store",
		LastTestAt:        formatProviderTime(record.LastTestAt),
		LastTestStatus:    displayProviderTestStatus(valueOrFallback(record.LastTestStatus, "never")),
		LastTestLatencyMS: formatLatencyMS(record.LastTestLatencyMS),
		LastErrorCode:     displayProviderErrorCode(valueOrFallback(record.LastErrorCode, "none")),
		ValidationMessage: providerValidationMessage(status, secretState, record),
	}
}

func providerManagementStatus(enabled bool, secretState string, lastTest string) string {
	if !enabled {
		return providerStatusDisabled
	}
	switch secretState {
	case providerStatusMissingSecret:
		return providerStatusMissingSecret
	case providerStatusInvalidSecret:
		return providerStatusInvalidSecret
	}
	switch strings.ToUpper(strings.TrimSpace(lastTest)) {
	case "", providerTestReady:
		return providerStatusReady
	case providerTestRateLimited:
		return providerStatusRateLimited
	default:
		return providerStatusError
	}
}

func providerValidationMessage(status, secretState string, record AIProviderRecord) string {
	switch status {
	case providerStatusMissingSecret:
		return "credential missing from SQLite"
	case providerStatusInvalidSecret:
		return "credential unreadable from SQLite"
	case providerStatusDisabled:
		return "provider disabled by operator"
	case providerStatusRateLimited:
		return "last test reported rate limiting"
	case providerStatusError:
		if strings.TrimSpace(record.LastErrorCode) != "" {
			return "last test error code: " + record.LastErrorCode
		}
		return "last test reported an error"
	case providerStatusReady:
		return "credential present and configuration valid"
	default:
		return providerStatusError
	}
}

func providerDashboardEntry(name AIProviderName, cfg ai.ProviderConfig, credentialKey string, record AIProviderRecord) AIProviderDashboardView {
	_ = credentialKey
	entry := providerManagementEntry(name, cfg, strings.TrimSpace(cfg.APIKey) != "", record)
	return AIProviderDashboardView{
		Name:         entry.Name,
		Status:       entry.Status,
		Model:        entry.Model,
		LastTestAt:   entry.LastTestAt,
		LastLatency:  entry.LastTestLatencyMS,
		SecretState:  entry.SecretState,
		EnabledState: enabledText(record.Enabled),
	}
}

func displayProviderTestStatus(raw string) string {
	switch raw {
	case "READY":
		return "ready"
	case "AUTH_FAILED":
		return "authentication failed"
	case "RATE_LIMITED":
		return "rate limited"
	case "NETWORK_ERROR":
		return "network error"
	case "TIMEOUT":
		return "timeout"
	case "UNKNOWN_ERROR":
		return "test failed"
	default:
		return raw
	}
}

func displayProviderErrorCode(raw string) string {
	switch raw {
	case "UNKNOWN_ERROR":
		return "unknown failure"
	case "MISSING_SECRET":
		return "key not configured"
	default:
		return raw
	}
}

func formatProviderTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

func formatLatencyMS(ms int) string {
	if ms <= 0 {
		return "n/a"
	}
	return fmt.Sprintf("%dms", ms)
}

func providerTestOutcome(err error) (status string, errorCode string) {
	if err == nil {
		return providerTestReady, ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return providerTestTimeout, providerTestTimeout
	}
	var perr *providers.Error
	if errors.As(err, &perr) {
		reason := strings.ToLower(strings.TrimSpace(perr.Reason))
		switch {
		case perr.StatusCode == http.StatusUnauthorized || perr.StatusCode == http.StatusForbidden:
			return providerTestAuthFailed, providerTestAuthFailed
		case perr.StatusCode == http.StatusTooManyRequests:
			return providerTestRateLimited, providerTestRateLimited
		case strings.Contains(reason, "timeout"):
			return providerTestTimeout, providerTestTimeout
		case perr.Retryable:
			return providerTestNetworkError, providerTestNetworkError
		default:
			return providerTestUnknownError, providerTestUnknownError
		}
	}
	if strings.Contains(strings.ToLower(err.Error()), "timeout") {
		return providerTestTimeout, providerTestTimeout
	}
	return providerTestUnknownError, providerTestUnknownError
}

func providerKeySelection(name string) (AIProviderName, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case string(AIProviderOpenAI):
		return AIProviderOpenAI, true
	case string(AIProviderAnthropic):
		return AIProviderAnthropic, true
	case string(AIProviderGemini):
		return AIProviderGemini, true
	default:
		return "", false
	}
}

func providerRecordForName(state *AIProviderState, name AIProviderName) *AIProviderRecord {
	if state == nil {
		return nil
	}
	switch name {
	case AIProviderOpenAI:
		return &state.OpenAI
	case AIProviderAnthropic:
		return &state.Anthropic
	case AIProviderGemini:
		return &state.Gemini
	default:
		return nil
	}
}

func providerStatusFromRecordAndConfig(record AIProviderRecord, cfg ai.ProviderConfig) string {
	secretState := providerStatusMissingSecret
	if strings.TrimSpace(cfg.APIKey) != "" {
		secretState = "configured"
	}
	return providerManagementStatus(record.Enabled, secretState, record.LastTestStatus)
}

func providerManagementView(cfg ai.Config, state AIProviderState, loaded bool) AIProviderManagementView {
	effective := applyAIProviderState(cfg, state, loaded)
	views := make([]AIProviderManagementEntry, 0, 3)
	for _, name := range providerNames() {
		display, _ := providerSpec(name)
		record := providerStateRecord(state, name)
		providerCfg := providerConfigForName(effective, name)
		entry := providerManagementEntry(name, providerCfg, strings.TrimSpace(providerCfg.APIKey) != "", record)
		entry.Name = display
		views = append(views, entry)
	}
	sort.SliceStable(views, func(i, j int) bool { return views[i].Name < views[j].Name })
	return AIProviderManagementView{Providers: views}
}

func providerDashboardViews(cfg ai.Config, state AIProviderState, loaded bool) []AIProviderDashboardView {
	effective := applyAIProviderState(cfg, state, loaded)
	views := make([]AIProviderDashboardView, 0, 3)
	for _, name := range providerNames() {
		views = append(views, providerDashboardEntry(name, providerConfigForName(effective, name), providerCredentialKeyForName(name), providerStateRecord(state, name)))
	}
	sort.SliceStable(views, func(i, j int) bool { return views[i].Name < views[j].Name })
	return views
}

func providerConfigForName(cfg ai.Config, name AIProviderName) ai.ProviderConfig {
	switch name {
	case AIProviderOpenAI:
		return cfg.OpenAI
	case AIProviderAnthropic:
		return cfg.Anthropic
	case AIProviderGemini:
		return cfg.Gemini
	default:
		return ai.ProviderConfig{}
	}
}

func providerConfigValidationError(path string, err error) error {
	if os.IsPermission(err) || errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%s: %w\n%s", err.Error(), err, providerStatePathHint(path))
	}
	return err
}

func ProviderManagementPage(view AIProviderManagementView, csrfToken string) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Providers",
		Headline: "Provider Management",
		Subtitle: "Manage OpenAI, Anthropic, and Gemini locally with encrypted SQLite credentials and redacted operator state.",
		Active:   "/providers",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if _, err := fmt.Fprint(w, `<div class="panel"><p class="muted">Provider management is local-only. Keys are never rendered, never prefilled, and are stored encrypted in SQLite. Enable/Disable touches only provider state; the legacy import action is one-shot and explicit.</p></div>`); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, `<div class="panel"><p class="muted">Legacy file import is one-shot and explicit. It copies old secret files into the encrypted SQLite store, then the runtime continues from DB only.</p><form action="/admin/providers/import-legacy" method="post"><input type="hidden" name="csrf_token" value="%s"/><button type="submit">Import Legacy Secrets</button></form></div>`, html.EscapeString(csrfToken)); err != nil {
				return err
			}
			if strings.TrimSpace(view.Error) != "" {
				if _, err := fmt.Fprintf(w, `<div class="panel"><p class="error">%s</p></div>`, html.EscapeString(view.Error)); err != nil {
					return err
				}
			}
			if strings.TrimSpace(view.Notice) != "" {
				if _, err := fmt.Fprintf(w, `<div class="panel"><p class="muted">%s</p></div>`, html.EscapeString(view.Notice)); err != nil {
					return err
				}
			}
			if len(view.Providers) == 0 {
				return writeEmptyState(w, "No AI providers configured.")
			}
			if _, err := fmt.Fprint(w, `<section class="grid">`); err != nil {
				return err
			}
			for _, p := range view.Providers {
				if err := renderProviderManagementCard(w, p, csrfToken); err != nil {
					return err
				}
			}
			_, err := fmt.Fprint(w, `</section>`)
			return err
		}),
	})
}

func renderProviderManagementCard(w io.Writer, p AIProviderManagementEntry, csrfToken string) error {
	if _, err := fmt.Fprint(w, `<div class="panel">`); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, `<h2>%s</h2>`, html.EscapeString(p.Name)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, `<div class="badges"><span class="badge %s">%s</span><span class="badge %s">%s</span><span class="badge %s">%s</span></div>`,
		html.EscapeString(stateBadgeClass(strings.ToLower(p.Status))),
		html.EscapeString(strings.ToUpper(p.Status)),
		html.EscapeString(stateBadgeClass(enabledBadgeState(p.Enabled))),
		html.EscapeString(strings.ToUpper(enabledBadgeState(p.Enabled))),
		html.EscapeString(stateBadgeClass(strings.ToLower(p.SecretState))),
		html.EscapeString(strings.ToUpper(p.SecretState)),
	); err != nil {
		return err
	}
	rows := []struct {
		label string
		value string
	}{
		{label: "model", value: p.Model},
		{label: "credential store", value: p.SecretPathDisplay},
		{label: "last test at", value: p.LastTestAt},
		{label: "last test status", value: p.LastTestStatus},
		{label: "last test latency", value: p.LastTestLatencyMS},
		{label: "last error code", value: p.LastErrorCode},
		{label: "validation", value: p.ValidationMessage},
	}
	if _, err := fmt.Fprint(w, `<div class="kv">`); err != nil {
		return err
	}
	for _, row := range rows {
		if err := renderProviderHealthRow(w, row.label, row.value); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, `<form action="/admin/providers/%s/key" method="post"><input type="hidden" name="csrf_token" value="%s"/><input type="hidden" name="confirm_replace" value="yes"/><label>new api key</label><input type="password" name="new_api_key" autocomplete="new-password" spellcheck="false"/><button type="submit">Replace Key</button></form>`, strings.ToLower(p.Name), html.EscapeString(csrfToken)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, `<form action="/admin/providers/%s/test" method="post"><input type="hidden" name="csrf_token" value="%s"/><button type="submit">Test Provider</button></form>`, strings.ToLower(p.Name), html.EscapeString(csrfToken)); err != nil {
		return err
	}
	toggleAction := "enable"
	toggleLabel := "Enable"
	if p.Enabled {
		toggleAction = "disable"
		toggleLabel = "Disable"
	}
	if _, err := fmt.Fprintf(w, `<form action="/admin/providers/%s/%s" method="post"><input type="hidden" name="csrf_token" value="%s"/><button type="submit">%s Provider</button></form>`, strings.ToLower(p.Name), toggleAction, html.EscapeString(csrfToken), toggleLabel); err != nil {
		return err
	}
	_, err := fmt.Fprint(w, `</div>`)
	return err
}

func enabledBadgeState(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

// nonAICredentialKey returns the credential-store key for a non-AI provider by its URL-slug name.
// Returns "" for providers that are config-managed (no credential store key).
func nonAICredentialKey(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "abuseipdb":
		return "abuseipdb.api_key"
	case "spamhaus":
		return "spamhaus.api_key"
	case "virustotal":
		return "virustotal.api_key"
	default:
		return ""
	}
}

func nonAIProviderDisplayName(slug string) string {
	switch strings.ToLower(strings.TrimSpace(slug)) {
	case "abuseipdb":
		return "AbuseIPDB"
	case "spamhaus":
		return "Spamhaus"
	case "virustotal":
		return "VirusTotal"
	case "cloudflare":
		return "Cloudflare"
	case "crowdsec":
		return "CrowdSec"
	case "betterstack":
		return "BetterStack"
	default:
		return slug
	}
}

func nonAIProviderCategory(slug string) string {
	switch strings.ToLower(strings.TrimSpace(slug)) {
	case "abuseipdb":
		return "reporting"
	case "spamhaus", "virustotal":
		return "enrichment"
	case "cloudflare":
		return "detection"
	case "crowdsec":
		return "detection"
	case "betterstack":
		return "logging"
	default:
		return "provider"
	}
}

// UnifiedProvidersPage renders all providers on a single management page.
// AI providers (OpenAI, Anthropic, Gemini) are shown with full key/enable/test management.
// Non-AI providers with credential-store keys (AbuseIPDB, Spamhaus, VirusTotal) show key replace forms.
// Infrastructure providers (Cloudflare, CrowdSec, BetterStack) are shown read-only.
func UnifiedProvidersPage(view UnifiedProvidersView, csrfToken string) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Providers",
		Headline: "Providers",
		Subtitle: "All provider credentials and health. AI providers support full key/enable/test management. Enrichment/reporting providers support key rotation. Infrastructure providers are config-managed.",
		Active:   "/providers",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if _, err := fmt.Fprint(w, `<div class="panel"><p class="muted">Keys are never rendered or prefilled. Credential store keys are encrypted in SQLite. Infrastructure providers (Cloudflare, CrowdSec, BetterStack) require config-file changes — no mutation endpoints are exposed here.</p></div>`); err != nil {
				return err
			}
			if view.Error != "" {
				if _, err := fmt.Fprintf(w, `<div class="panel"><p class="error">%s</p></div>`, html.EscapeString(view.Error)); err != nil {
					return err
				}
			}
			// Reporting & enrichment providers
			hasNonAI := false
			for _, e := range view.NonAI {
				if e.HasKeyManagement {
					hasNonAI = true
					break
				}
			}
			if hasNonAI {
				if _, err := fmt.Fprint(w, `<h2 class="section-heading">Reporting &amp; Enrichment Providers</h2><section class="grid">`); err != nil {
					return err
				}
				for _, e := range view.NonAI {
					if !e.HasKeyManagement {
						continue
					}
					if err := renderNonAIProviderCard(w, e, csrfToken); err != nil {
						return err
					}
				}
				if _, err := fmt.Fprint(w, `</section>`); err != nil {
					return err
				}
			}
			// AI providers
			if len(view.AI.Providers) > 0 {
				if _, err := fmt.Fprint(w, `<h2 class="section-heading">AI Providers</h2><section class="grid">`); err != nil {
					return err
				}
				for _, p := range view.AI.Providers {
					if err := renderProviderManagementCard(w, p, csrfToken); err != nil {
						return err
					}
				}
				if _, err := fmt.Fprint(w, `</section>`); err != nil {
					return err
				}
			}
			// Infrastructure providers (config-managed, read-only)
			hasInfra := false
			for _, e := range view.NonAI {
				if !e.HasKeyManagement {
					hasInfra = true
					break
				}
			}
			if hasInfra {
				if _, err := fmt.Fprint(w, `<h2 class="section-heading">Infrastructure Providers</h2><p class="muted" style="margin:0 0 1rem">These providers are configured via config file. No credential rotation or enable/disable is available through this UI.</p><section class="grid">`); err != nil {
					return err
				}
				for _, e := range view.NonAI {
					if e.HasKeyManagement {
						continue
					}
					if err := renderInfraProviderCard(w, e); err != nil {
						return err
					}
				}
				if _, err := fmt.Fprint(w, `</section>`); err != nil {
					return err
				}
			}
			return nil
		}),
	})
}

func renderNonAIProviderCard(w io.Writer, e NonAIProviderEntry, csrfToken string) error {
	if _, err := fmt.Fprint(w, `<div class="panel">`); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, `<h2>%s</h2>`, html.EscapeString(e.Name)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, `<div class="badges"><span class="badge %s">%s</span><span class="badge %s">%s</span><span class="badge info">%s</span></div>`,
		html.EscapeString(stateBadgeClass(enabledBadgeState(e.Enabled))),
		html.EscapeString(strings.ToUpper(enabledBadgeState(e.Enabled))),
		html.EscapeString(stateBadgeClass(providerManagementStatus(e.Enabled, func() string {
			if e.Configured {
				return "configured"
			}
			return providerStatusMissingSecret
		}(), ""))),
		func() string {
			if e.Configured {
				return "CONFIGURED"
			}
			return "MISSING KEY"
		}(),
		html.EscapeString(e.Category),
	); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, `<div class="kv">`); err != nil {
		return err
	}
	if err := renderProviderHealthRow(w, "credential store", "SQLite (encrypted)"); err != nil {
		return err
	}
	if e.MaskedKey != "" {
		if err := renderProviderHealthRow(w, "current key", e.MaskedKey); err != nil {
			return err
		}
	}
	if e.Notes != "" {
		if err := renderProviderHealthRow(w, "notes", e.Notes); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w,
		`<form action="/admin/providers/%s/key" method="post"><input type="hidden" name="csrf_token" value="%s"/><input type="hidden" name="confirm_replace" value="yes"/><label>new api key</label><input type="password" name="new_api_key" autocomplete="new-password" spellcheck="false"/><button type="submit">Replace Key</button></form>`,
		html.EscapeString(strings.ToLower(e.Name)),
		html.EscapeString(csrfToken),
	); err != nil {
		return err
	}
	_, err := fmt.Fprint(w, `</div></div>`)
	return err
}

func renderInfraProviderCard(w io.Writer, e NonAIProviderEntry) error {
	if _, err := fmt.Fprint(w, `<div class="panel">`); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, `<h2>%s</h2>`, html.EscapeString(e.Name)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, `<div class="badges"><span class="badge %s">%s</span><span class="badge %s">%s</span><span class="badge info">%s</span><span class="badge muted">config-managed</span></div>`,
		html.EscapeString(stateBadgeClass(enabledBadgeState(e.Enabled))),
		html.EscapeString(strings.ToUpper(enabledBadgeState(e.Enabled))),
		html.EscapeString(stateBadgeClass(func() string {
			if e.Configured {
				return "configured"
			}
			return "missing"
		}())),
		func() string {
			if e.Configured {
				return "CONFIGURED"
			}
			return "NOT CONFIGURED"
		}(),
		html.EscapeString(e.Category),
	); err != nil {
		return err
	}
	if e.Notes != "" {
		if _, err := fmt.Fprintf(w, `<p class="muted">%s</p>`, html.EscapeString(e.Notes)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</div>`)
	return err
}
