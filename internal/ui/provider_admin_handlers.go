package ui

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/security/enrichment/spamhaus"
	"github.com/jm/security-automation-go/internal/security/enrichment/virustotal"
)

func (s *Server) loadAIState(ctx context.Context) (AIProviderState, bool, error) {
	return loadAIStateFromStoreOrFile(ctx, s.setupStore, s.cfg.UI.ProviderStateFile)
}

func (s *Server) saveAIState(ctx context.Context, state AIProviderState) error {
	if s.setupStore != nil {
		return saveAIProviderStateToStore(ctx, s.setupStore, state)
	}
	return saveAIProviderState(s.cfg.UI.ProviderStateFile, state)
}

func normalizeAIConfig(cfg ai.Config) ai.Config {
	if cfg.MaxContextBytes <= 0 {
		cfg.MaxContextBytes = 12_000
	}
	if cfg.MaxOutputTokens <= 0 {
		cfg.MaxOutputTokens = 800
	}
	if cfg.RateLimitPerMinute <= 0 {
		cfg.RateLimitPerMinute = 10
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 15 * time.Minute
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	// Restore safe model defaults when a provider is enabled but the model was
	// not persisted (e.g. after a credential store migration).
	if cfg.OpenAI.Enabled && cfg.OpenAI.Model == "" {
		cfg.OpenAI.Model = ai.DefaultOpenAIModel
	}
	if cfg.Anthropic.Enabled && cfg.Anthropic.Model == "" {
		cfg.Anthropic.Model = ai.DefaultAnthropicModel
	}
	if cfg.Gemini.Enabled && cfg.Gemini.Model == "" {
		cfg.Gemini.Model = ai.DefaultGeminiModel
	}
	if !cfg.Enabled && aiExplainShouldBeEnabled(cfg) {
		cfg.Enabled = true
	}
	return cfg
}

func aiExplainShouldBeEnabled(cfg ai.Config) bool {
	return (cfg.OpenAI.Enabled && strings.TrimSpace(cfg.OpenAI.APIKey) != "") ||
		(cfg.Anthropic.Enabled && strings.TrimSpace(cfg.Anthropic.APIKey) != "") ||
		(cfg.Gemini.Enabled && strings.TrimSpace(cfg.Gemini.APIKey) != "")
}

func (s *Server) nonAIProviderEntries() []NonAIProviderEntry {
	ctx := context.Background()
	cfSentinel := s.cfSentinelToken() != "" && s.cfZoneIDFromSetup(ctx) != ""
	crowdSecCfg := strings.TrimSpace(s.cfg.CrowdSec.APIKey) != "" || strings.TrimSpace(s.cfg.CrowdSec.DecisionsLog) != ""
	betterStackCfg := strings.TrimSpace(s.cfg.BetterStack.SourceToken) != ""

	const abKey = "abuseipdb.api_key"
	const shKey = "spamhaus.api_key"
	const vtKey = "virustotal.api_key"

	abConfigured := credentialConfigured(ctx, s.credentialStore, abKey)
	shConfigured := credentialConfigured(ctx, s.credentialStore, shKey)
	vtConfigured := credentialConfigured(ctx, s.credentialStore, vtKey)
	abState, abLoaded, _ := loadProviderRuntimeSnapshot(ctx, s.setupStore, "abuseipdb")
	shState, shLoaded, _ := loadProviderRuntimeSnapshot(ctx, s.setupStore, "spamhaus")
	vtState, vtLoaded, _ := loadProviderRuntimeSnapshot(ctx, s.setupStore, "virustotal")
	if !abLoaded {
		abState.Enabled = s.cfg.AbuseIPDB.Enabled
	}
	if !shLoaded {
		shState.Enabled = s.cfg.Spamhaus.Enabled
	}
	if !vtLoaded {
		vtState.Enabled = s.cfg.VirusTotal.Enabled
	}
	abView := providerDisplaySnapshot(abState)
	shView := providerDisplaySnapshot(shState)
	vtView := providerDisplaySnapshot(vtState)

	return []NonAIProviderEntry{
		{
			Name:             "AbuseIPDB",
			Category:         nonAIProviderCategory("abuseipdb"),
			CredentialKey:    abKey,
			HasKeyManagement: true,
			Enabled:          abView.Enabled,
			Configured:       abConfigured,
			MaskedKey:        maskedCredentialStoreValue(ctx, s.credentialStore, abKey),
			Healthy:          abView.Healthy,
			ConfiguredState:  configuredText(abConfigured),
			EnabledState:     enabledText(abView.Enabled),
			HealthyState:     providerHealthStateText(abConfigured, abView.Enabled, abView.Healthy),
			LastTestAt:       formatProviderTime(abView.LastTestAt),
			LastSuccessAt:    providerLastSuccessText(abView.Enabled, abView.Healthy, abView.LastTestAt, abView.LastSuccessAt),
			LastFailureAt:    providerLastFailureText(abView.Enabled, abView.Healthy, abView.LastTestAt, abView.LastFailureAt),
			LastLatencyMS:    formatLatencyMS(abView.LastLatencyMS),
			LastErrorCode:    providerLastErrorText(abView.Enabled, abView.Healthy, abView.LastErrorCode),
			Status:           providerSummaryStateText(abConfigured, abView.Enabled, abView.Healthy),
		},
		{
			Name:             "Spamhaus",
			Category:         nonAIProviderCategory("spamhaus"),
			CredentialKey:    shKey,
			HasKeyManagement: true,
			Enabled:          shView.Enabled,
			Configured:       shConfigured,
			MaskedKey:        maskedCredentialStoreValue(ctx, s.credentialStore, shKey),
			Healthy:          shView.Healthy,
			ConfiguredState:  configuredText(shConfigured),
			EnabledState:     enabledText(shView.Enabled),
			HealthyState:     providerHealthStateText(shConfigured, shView.Enabled, shView.Healthy),
			LastTestAt:       formatProviderTime(shView.LastTestAt),
			LastSuccessAt:    providerLastSuccessText(shView.Enabled, shView.Healthy, shView.LastTestAt, shView.LastSuccessAt),
			LastFailureAt:    providerLastFailureText(shView.Enabled, shView.Healthy, shView.LastTestAt, shView.LastFailureAt),
			LastLatencyMS:    formatLatencyMS(shView.LastLatencyMS),
			LastErrorCode:    providerLastErrorText(shView.Enabled, shView.Healthy, shView.LastErrorCode),
			Status:           providerSummaryStateText(shConfigured, shView.Enabled, shView.Healthy),
		},
		{
			Name:             "VirusTotal",
			Category:         nonAIProviderCategory("virustotal"),
			CredentialKey:    vtKey,
			HasKeyManagement: true,
			Enabled:          vtView.Enabled,
			Configured:       vtConfigured,
			MaskedKey:        maskedCredentialStoreValue(ctx, s.credentialStore, vtKey),
			Healthy:          vtView.Healthy,
			ConfiguredState:  configuredText(vtConfigured),
			EnabledState:     enabledText(vtView.Enabled),
			HealthyState:     providerHealthStateText(vtConfigured, vtView.Enabled, vtView.Healthy),
			LastTestAt:       formatProviderTime(vtView.LastTestAt),
			LastSuccessAt:    providerLastSuccessText(vtView.Enabled, vtView.Healthy, vtView.LastTestAt, vtView.LastSuccessAt),
			LastFailureAt:    providerLastFailureText(vtView.Enabled, vtView.Healthy, vtView.LastTestAt, vtView.LastFailureAt),
			LastLatencyMS:    formatLatencyMS(vtView.LastLatencyMS),
			LastErrorCode:    providerLastErrorText(vtView.Enabled, vtView.Healthy, vtView.LastErrorCode),
			Status:           providerSummaryStateText(vtConfigured, vtView.Enabled, vtView.Healthy),
		},
		{
			Name:             "Cloudflare",
			Category:         nonAIProviderCategory("cloudflare"),
			HasKeyManagement: false,
			Enabled:          cfSentinel,
			Configured:       cfSentinel,
			Notes:            "API token from environment; zone config from setup wizard.",
		},
		{
			Name:             "CrowdSec",
			Category:         nonAIProviderCategory("crowdsec"),
			HasKeyManagement: false,
			Enabled:          crowdSecCfg,
			Configured:       crowdSecCfg,
			Notes:            "API key and decisions-log path from config file.",
		},
		{
			Name:             "BetterStack",
			Category:         nonAIProviderCategory("betterstack"),
			HasKeyManagement: false,
			Enabled:          betterStackCfg,
			Configured:       betterStackCfg,
			Notes:            "Source token and ingesting host from config file.",
		},
	}
}

func (s *Server) unifiedProvidersView() (UnifiedProvidersView, error) {
	ai, err := s.providerManagementView()
	if err != nil {
		return UnifiedProvidersView{Error: err.Error()}, err
	}
	return UnifiedProvidersView{
		AI:    ai,
		NonAI: s.nonAIProviderEntries(),
	}, nil
}

func (s *Server) providerManagementView() (AIProviderManagementView, error) {
	state, loaded, err := s.loadAIState(context.Background())
	if err != nil {
		return AIProviderManagementView{}, err
	}
	aiCfg := normalizeAIConfig(s.aiConfigFromCredentialStore(applyAIProviderState(s.aiBaseConfig, state, loaded)))
	views := providerManagementView(aiCfg, state, loaded)
	return views, nil
}

func (s *Server) providerDashboardViews() []AIProviderDashboardView {
	state, loaded, err := s.loadAIState(context.Background())
	if err != nil {
		return nil
	}
	aiCfg := normalizeAIConfig(s.aiConfigFromCredentialStore(applyAIProviderState(s.aiBaseConfig, state, loaded)))
	return providerDashboardViews(aiCfg, state, loaded)
}

func (s *Server) rebuildAIExplainFromState() error {
	state, loaded, err := s.loadAIState(context.Background())
	if err != nil {
		return err
	}
	effective := normalizeAIConfig(s.aiConfigFromCredentialStore(applyAIProviderState(s.aiBaseConfig, state, loaded)))
	if s.aiExplainBuilder == nil {
		s.aiMu.Lock()
		s.aiConfig = effective
		s.aiMu.Unlock()
		return nil
	}
	explain := s.aiExplainBuilder(effective)
	if explain == nil {
		return fmt.Errorf("ai explain builder returned nil")
	}
	s.aiMu.Lock()
	s.aiConfig = effective
	s.aiExplain = explain
	s.aiMu.Unlock()
	return nil
}

func (s *Server) aiConfigFromCredentialStore(base ai.Config) ai.Config {
	if s.credentialStore == nil {
		return base
	}
	ctx := context.Background()
	if v, ok, err := s.credentialStore.Lookup(ctx, "ai.openai.api_key"); err == nil && ok {
		base.OpenAI.APIKey = v
	}
	if v, ok, err := s.credentialStore.Lookup(ctx, "ai.anthropic.api_key"); err == nil && ok {
		base.Anthropic.APIKey = v
	}
	if v, ok, err := s.credentialStore.Lookup(ctx, "ai.gemini.api_key"); err == nil && ok {
		base.Gemini.APIKey = v
	}
	return base
}

func (s *Server) renderUnifiedProvidersError(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	view, _ := s.unifiedProvidersView()
	view.Error = errMsg
	w.WriteHeader(status)
	_ = UnifiedProvidersPage(view, s.csrfTokenFromRequest(r)).Render(r.Context(), w)
}

func (s *Server) handleNonAIProviderReplaceKey(w http.ResponseWriter, r *http.Request, slug, credKey string) {
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if strings.ToLower(strings.TrimSpace(r.PostForm.Get("confirm_replace"))) != "yes" {
		s.renderUnifiedProvidersError(w, r, http.StatusBadRequest, "confirmation required before replacing a key")
		return
	}
	secret := strings.TrimSpace(r.PostForm.Get("new_api_key"))
	if secret == "" {
		s.renderUnifiedProvidersError(w, r, http.StatusBadRequest, "new API key is required")
		return
	}
	if s.credentialStore == nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, "credential store unavailable")
		return
	}
	if err := s.credentialStore.Set(r.Context(), credKey, secret, true); err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusForbidden, err.Error())
		return
	}
	s.audit.Record("provider_key_rotated", map[string]string{
		"provider":       slug,
		"result":         "redacted",
		"correlation_id": newUIEventID(),
	})
	if snapshot, loaded, err := loadProviderRuntimeSnapshot(r.Context(), s.setupStore, slug); err == nil {
		if !loaded {
			switch slug {
			case "abuseipdb":
				snapshot.Enabled = s.cfg.AbuseIPDB.Enabled
			case "spamhaus":
				snapshot.Enabled = s.cfg.Spamhaus.Enabled
			case "virustotal":
				snapshot.Enabled = s.cfg.VirusTotal.Enabled
			}
		}
		if snapshot.Enabled {
			s.scheduleNonAIProviderAutoTest(slug)
		}
	}
	http.Redirect(w, r, "/providers", http.StatusSeeOther)
}

func (s *Server) handleProviderReplaceKey(w http.ResponseWriter, r *http.Request) {
	rawName := r.PathValue("name")
	if credKey := nonAICredentialKey(rawName); credKey != "" {
		s.handleNonAIProviderReplaceKey(w, r, rawName, credKey)
		return
	}
	name, ok := providerKeySelection(rawName)
	if !ok {
		http.Error(w, "invalid provider", http.StatusBadRequest)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if strings.ToLower(strings.TrimSpace(r.PostForm.Get("confirm_replace"))) != "yes" {
		s.renderUnifiedProvidersError(w, r, http.StatusBadRequest, "confirmation required before replacing a key")
		return
	}
	secret := strings.TrimSpace(r.PostForm.Get("new_api_key"))
	if secret == "" {
		s.renderUnifiedProvidersError(w, r, http.StatusBadRequest, "new API key is required")
		return
	}
	if s.credentialStore == nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, "credential store unavailable")
		return
	}
	if err := s.credentialStore.Set(r.Context(), providerCredentialKeyForName(name), secret, true); err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusForbidden, err.Error())
		return
	}
	s.audit.Record("provider_key_rotated", map[string]string{
		"provider":       strings.ToLower(string(name)),
		"result":         "redacted",
		"correlation_id": newUIEventID(),
	})
	if err := s.rebuildAIExplainFromState(); err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, fmt.Sprintf("key written but AI explain could not be rebuilt: %v", err))
		return
	}
	s.scheduleAIProviderAutoTest(name)
	http.Redirect(w, r, "/providers", http.StatusSeeOther)
}

func (s *Server) handleLegacyCredentialImport(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if s.credentialStore == nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, "credential store unavailable")
		return
	}
	imported, err := s.credentialStore.ImportLegacyDir(r.Context(), legacySecretsDirPath)
	if err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit.Record("legacy_credentials_imported", map[string]string{
		"count":          fmt.Sprintf("%d", imported),
		"result":         "redacted",
		"correlation_id": newUIEventID(),
	})
	if err := s.rebuildAIExplainFromState(); err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, fmt.Sprintf("legacy credentials imported but AI explain could not be rebuilt: %v", err))
		return
	}
	s.scheduleAIProviderAutoTest(AIProviderOpenAI)
	s.scheduleAIProviderAutoTest(AIProviderAnthropic)
	s.scheduleAIProviderAutoTest(AIProviderGemini)
	http.Redirect(w, r, "/providers", http.StatusSeeOther)
}

func (s *Server) handleProviderEnable(w http.ResponseWriter, r *http.Request) {
	if s.handleNonAIProviderToggleIfNeeded(w, r, true) {
		return
	}
	s.handleProviderToggle(w, r, true)
}

func (s *Server) handleProviderDisable(w http.ResponseWriter, r *http.Request) {
	if s.handleNonAIProviderToggleIfNeeded(w, r, false) {
		return
	}
	s.handleProviderToggle(w, r, false)
}

func (s *Server) handleProviderToggle(w http.ResponseWriter, r *http.Request, enabled bool) {
	name, ok := providerKeySelection(r.PathValue("name"))
	if !ok {
		http.Error(w, "invalid provider", http.StatusBadRequest)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	state, _, err := s.loadAIState(r.Context())
	if err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	record := providerStateRecord(state, name)
	display, _ := providerSpec(name)
	configured := credentialConfigured(r.Context(), s.credentialStore, providerCredentialKeyForName(name))
	if enabled {
		if !configured {
			record.LastErrorCode = providerStatusMissingSecret
			setProviderStateRecord(&state, name, record)
			if err := s.saveAIState(r.Context(), state); err != nil {
				s.renderUnifiedProvidersError(w, r, http.StatusForbidden, err.Error())
				return
			}
			s.audit.Record("provider_config_validation_failed", map[string]string{
				"provider":       strings.ToLower(string(name)),
				"result":         providerStatusMissingSecret,
				"correlation_id": newUIEventID(),
			})
			s.renderUnifiedProvidersError(w, r, http.StatusForbidden, fmt.Sprintf("provider %s cannot be enabled: credential not configured in SQLite", display))
			return
		}
		record.Enabled = true
		clearAIProviderDiagnostics(&record)
		record.Enabled = true
		s.audit.Record("provider_enabled", map[string]string{
			"provider":       strings.ToLower(string(name)),
			"target":         display,
			"result":         "enabled",
			"correlation_id": newUIEventID(),
			"event_id":       newUIEventID(),
		})
	} else {
		record.Enabled = false
		record.Healthy = false
		record.LastErrorCode = providerTestDisabledByOperator
		s.audit.Record("provider_disabled", map[string]string{
			"provider":       strings.ToLower(string(name)),
			"target":         display,
			"result":         "disabled",
			"correlation_id": newUIEventID(),
			"event_id":       newUIEventID(),
		})
	}
	setProviderStateRecord(&state, name, record)
	if err := s.saveAIState(r.Context(), state); err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusForbidden, err.Error())
		return
	}
	if err := s.rebuildAIExplainFromState(); err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, fmt.Sprintf("provider state saved but AI explain could not be rebuilt: %v", err))
		return
	}
	if enabled {
		s.scheduleAIProviderAutoTest(name)
	}
	http.Redirect(w, r, "/providers", http.StatusSeeOther)
}

func (s *Server) handleProviderTest(w http.ResponseWriter, r *http.Request) {
	if s.handleNonAIProviderTestIfNeeded(w, r) {
		return
	}
	name, ok := providerKeySelection(r.PathValue("name"))
	if !ok {
		http.Error(w, "invalid provider", http.StatusBadRequest)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	state, loaded, err := s.loadAIState(r.Context())
	if err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	record := providerStateRecord(state, name)
	display, _ := providerSpec(name)
	providerCfg := providerConfigForName(s.aiConfigFromCredentialStore(applyAIProviderState(s.aiBaseConfig, state, loaded)), name)
	configured := strings.TrimSpace(providerCfg.APIKey) != ""
	outcome := providerTestUnknownError
	errorCode := providerTestUnknownError
	latencyMS := 0

	if !record.Enabled {
		outcome = providerTestDisabledByOperator
		errorCode = providerTestDisabledByOperator
	} else if !configured {
		outcome = providerTestUnknownError
		errorCode = providerStatusMissingSecret
	} else {
		outcome, errorCode, latencyMS = s.executeAIProviderHealthCheck(r.Context(), name, state, loaded)
	}

	record.LastTestAt = time.Now().UTC()
	record.LastTestStatus = outcome
	record.LastTestLatencyMS = latencyMS
	record.LastErrorCode = errorCode
	record.Healthy = outcome == providerTestReady
	if record.Healthy {
		record.LastSuccessAt = record.LastTestAt
		record.LastFailureAt = time.Time{}
	} else {
		record.LastFailureAt = record.LastTestAt
	}
	setProviderStateRecord(&state, name, record)
	if err := s.saveAIState(r.Context(), state); err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusForbidden, err.Error())
		return
	}
	if outcome == providerTestReady {
		s.audit.Record("provider_test", map[string]string{
			"provider":       strings.ToLower(string(name)),
			"target":         display,
			"result":         outcome,
			"correlation_id": newUIEventID(),
			"event_id":       newUIEventID(),
		})
	} else {
		s.audit.Record("provider_test_failed", map[string]string{
			"provider":       strings.ToLower(string(name)),
			"target":         display,
			"result":         outcome,
			"correlation_id": newUIEventID(),
			"event_id":       newUIEventID(),
		})
	}
	http.Redirect(w, r, "/providers", http.StatusSeeOther)
}

func (s *Server) handleProviderResetDiagnostics(w http.ResponseWriter, r *http.Request) {
	if s.handleNonAIProviderResetDiagnosticsIfNeeded(w, r) {
		return
	}
	name, ok := providerKeySelection(r.PathValue("name"))
	if !ok {
		http.Error(w, "invalid provider", http.StatusBadRequest)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	state, _, err := s.loadAIState(r.Context())
	if err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	record := providerStateRecord(state, name)
	display, _ := providerSpec(name)
	clearAIProviderDiagnostics(&record)
	setProviderStateRecord(&state, name, record)
	if err := s.saveAIState(r.Context(), state); err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit.Record("provider_diagnostics_reset", map[string]string{
		"provider":       strings.ToLower(string(name)),
		"target":         display,
		"result":         "reset",
		"correlation_id": newUIEventID(),
		"event_id":       newUIEventID(),
	})
	if err := s.rebuildAIExplainFromState(); err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, fmt.Sprintf("provider diagnostics reset but AI explain could not be rebuilt: %v", err))
		return
	}
	http.Redirect(w, r, "/providers", http.StatusSeeOther)
}

func (s *Server) scheduleAIProviderAutoTest(name AIProviderName) {
	if s == nil {
		return
	}
	switch name {
	case AIProviderOpenAI, AIProviderAnthropic, AIProviderGemini:
	default:
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		s.refreshAIProviderHealth(ctx, name)
	}()
}

func (s *Server) executeAIProviderHealthCheck(ctx context.Context, name AIProviderName, state AIProviderState, loaded bool) (string, string, int) {
	if s == nil || ctx == nil {
		return providerTestUnknownError, providerTestUnknownError, 0
	}
	providerCfg := providerConfigForName(s.aiConfigFromCredentialStore(applyAIProviderState(s.aiBaseConfig, state, loaded)), name)
	if strings.TrimSpace(providerCfg.APIKey) == "" {
		return providerStatusMissingSecret, providerStatusMissingSecret, 0
	}
	s.aiMu.RLock()
	explain := s.aiExplain
	aiCfg := s.aiConfig
	s.aiMu.RUnlock()
	if explain == nil {
		return providerTestUnknownError, providerTestUnknownError, 0
	}
	display, _ := providerSpec(name)
	testCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	start := time.Now()
	resp, testErr := explain.Explain(testCtx, ai.ExplainRequest{
		SubjectType:        ai.SubjectProvider,
		SubjectID:          display,
		ProviderPreference: strings.ToLower(string(name)),
		MaxContextBytes:    aiCfg.MaxContextBytes,
		MaxOutputTokens:    aiCfg.MaxOutputTokens,
	})
	_ = resp
	cancel()
	outcome, errorCode := providerTestOutcome(testErr)
	return outcome, errorCode, elapsedLatencyMS(start)
}

func (s *Server) refreshAIProviderHealth(ctx context.Context, name AIProviderName) {
	if s == nil || ctx == nil {
		return
	}
	switch name {
	case AIProviderOpenAI, AIProviderAnthropic, AIProviderGemini:
	default:
		return
	}
	state, loaded, err := s.loadAIState(ctx)
	if err != nil {
		return
	}
	record := providerStateRecord(state, name)
	if !record.Enabled {
		return
	}
	outcome, errorCode, latencyMS := s.executeAIProviderHealthCheck(ctx, name, state, loaded)
	record.LastTestAt = time.Now().UTC()
	record.LastTestStatus = outcome
	record.LastTestLatencyMS = latencyMS
	record.LastErrorCode = errorCode
	record.Healthy = outcome == providerTestReady
	if record.Healthy {
		record.LastSuccessAt = record.LastTestAt
		record.LastFailureAt = time.Time{}
	} else {
		record.LastFailureAt = record.LastTestAt
	}
	setProviderStateRecord(&state, name, record)
	_ = s.saveAIState(ctx, state)
}

const providerHealthRefreshIntervalDefault = time.Hour

func (s *Server) StartProviderHealthRefreshers(ctx context.Context, interval time.Duration) {
	if s == nil || ctx == nil {
		return
	}
	if interval <= 0 {
		interval = providerHealthRefreshIntervalDefault
	}
	go func() {
		s.refreshAllProviderHealthNow(ctx)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.refreshAllProviderHealthNow(ctx)
			}
		}
	}()
}

func (s *Server) refreshAllProviderHealthNow(ctx context.Context) {
	if s == nil {
		return
	}
	for _, name := range providerNames() {
		s.refreshAIProviderHealth(ctx, name)
	}
	for _, slug := range []string{"abuseipdb", "spamhaus", "virustotal"} {
		s.refreshNonAIProviderHealth(ctx, slug)
	}
}

func (s *Server) refreshNonAIProviderHealth(ctx context.Context, slug string) {
	if s == nil || ctx == nil {
		return
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	credKey := nonAICredentialKey(slug)
	if credKey == "" {
		return
	}

	snapshot, loaded, err := loadProviderRuntimeSnapshot(ctx, s.setupStore, slug)
	if err != nil {
		return
	}
	if !loaded {
		switch slug {
		case "abuseipdb":
			snapshot.Enabled = s.cfg.AbuseIPDB.Enabled
		case "spamhaus":
			snapshot.Enabled = s.cfg.Spamhaus.Enabled
		case "virustotal":
			snapshot.Enabled = s.cfg.VirusTotal.Enabled
		}
	}
	if !snapshot.Enabled {
		return
	}
	if !credentialConfigured(ctx, s.credentialStore, credKey) {
		return
	}
	outcome, errCode, latencyMS := s.testNonAIProvider(ctx, slug, credKey)
	now := time.Now().UTC()
	snapshot.LastTestAt = now
	snapshot.LastTestStatus = outcome
	snapshot.LastLatencyMS = latencyMS
	snapshot.LastErrorCode = errCode
	snapshot.Healthy = outcome == providerTestReady
	snapshot.LastSuccessAt = time.Time{}
	snapshot.LastFailureAt = time.Time{}
	if snapshot.Healthy {
		snapshot.LastSuccessAt = now
	} else {
		snapshot.LastFailureAt = now
	}
	_ = saveProviderRuntimeSnapshot(ctx, s.setupStore, slug, snapshot)
}

func elapsedLatencyMS(start time.Time) int {
	ms := int(time.Since(start) / time.Millisecond)
	if ms < 1 {
		return 1
	}
	return ms
}

func (s *Server) scheduleNonAIProviderAutoTest(slug string) {
	if s == nil {
		return
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	credKey := nonAICredentialKey(slug)
	if credKey == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		s.refreshNonAIProviderHealth(ctx, slug)
	}()
}

func (s *Server) testNonAIProvider(ctx context.Context, slug, credKey string) (string, string, int) {
	start := time.Now()
	if !credentialConfigured(ctx, s.credentialStore, credKey) {
		return providerStatusMissingSecret, providerStatusMissingSecret, elapsedLatencyMS(start)
	}

	var outcome string
	var errCode string
	switch slug {
	case "abuseipdb":
		if s.validateAbuseIPDB != nil {
			if secret, ok := s.credentialValue(ctx, credKey); ok {
				if err := s.validateAbuseIPDB(ctx, secret); err != nil {
					outcome, errCode = providerTestOutcome(err)
				} else {
					outcome, errCode = providerTestReady, ""
				}
			} else {
				outcome, errCode = providerStatusMissingSecret, providerStatusMissingSecret
			}
		} else {
			outcome, errCode = providerTestUnknownError, providerTestUnknownError
		}
	case "spamhaus":
		if secret, ok := s.credentialValue(ctx, credKey); ok {
			client := spamhaus.NewQuotaClient(httpclient.New(s.cfg.Global.HTTP), secret)
			obs, err := client.Fetch(ctx)
			_ = obs
			outcome, errCode = providerTestOutcome(err)
		} else {
			outcome, errCode = providerStatusMissingSecret, providerStatusMissingSecret
		}
	case "virustotal":
		if secret, ok := s.credentialValue(ctx, credKey); ok {
			client := virustotal.NewQuotaClient(httpclient.New(s.cfg.Global.HTTP), secret)
			obs, err := client.Fetch(ctx)
			_ = obs
			outcome, errCode = providerTestOutcome(err)
		} else {
			outcome, errCode = providerStatusMissingSecret, providerStatusMissingSecret
		}
	default:
		outcome, errCode = providerTestUnknownError, providerTestUnknownError
	}
	return outcome, errCode, elapsedLatencyMS(start)
}

func (s *Server) handleNonAIProviderToggleIfNeeded(w http.ResponseWriter, r *http.Request, enabled bool) bool {
	slug := strings.ToLower(strings.TrimSpace(r.PathValue("name")))
	if nonAICredentialKey(slug) == "" {
		return false
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return true
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return true
	}
	ctx := r.Context()
	snapshot, loaded, err := loadProviderRuntimeSnapshot(ctx, s.setupStore, slug)
	if err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, err.Error())
		return true
	}
	if !loaded {
		switch slug {
		case "abuseipdb":
			snapshot.Enabled = s.cfg.AbuseIPDB.Enabled
		case "spamhaus":
			snapshot.Enabled = s.cfg.Spamhaus.Enabled
		case "virustotal":
			snapshot.Enabled = s.cfg.VirusTotal.Enabled
		}
	}
	snapshot.Enabled = enabled
	if enabled {
		clearProviderRuntimeDiagnostics(&snapshot)
		snapshot.Enabled = true
	}
	if err := saveProviderRuntimeSnapshot(ctx, s.setupStore, slug, snapshot); err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, err.Error())
		return true
	}
	s.audit.Record("provider_runtime_toggled", map[string]string{
		"provider":       slug,
		"target":         strings.ToUpper(slug),
		"enabled":        strconv.FormatBool(enabled),
		"result":         providerEnabledLabel(enabled),
		"correlation_id": newUIEventID(),
		"event_id":       newUIEventID(),
	})
	if enabled {
		s.scheduleNonAIProviderAutoTest(slug)
	}
	http.Redirect(w, r, "/providers", http.StatusSeeOther)
	return true
}

func (s *Server) handleNonAIProviderResetDiagnosticsIfNeeded(w http.ResponseWriter, r *http.Request) bool {
	slug := strings.ToLower(strings.TrimSpace(r.PathValue("name")))
	if nonAICredentialKey(slug) == "" {
		return false
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return true
	}
	snapshot, loaded, err := loadProviderRuntimeSnapshot(r.Context(), s.setupStore, slug)
	if err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, err.Error())
		return true
	}
	if !loaded {
		switch slug {
		case "abuseipdb":
			snapshot.Enabled = s.cfg.AbuseIPDB.Enabled
		case "spamhaus":
			snapshot.Enabled = s.cfg.Spamhaus.Enabled
		case "virustotal":
			snapshot.Enabled = s.cfg.VirusTotal.Enabled
		}
	}
	snapshot.LastTestAt = time.Time{}
	snapshot.LastSuccessAt = time.Time{}
	snapshot.LastFailureAt = time.Time{}
	snapshot.LastLatencyMS = 0
	snapshot.LastErrorCode = ""
	snapshot.Healthy = false
	if err := saveProviderRuntimeSnapshot(r.Context(), s.setupStore, slug, snapshot); err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, err.Error())
		return true
	}
	s.audit.Record("provider_diagnostics_reset", map[string]string{
		"provider":       slug,
		"target":         strings.ToUpper(slug),
		"result":         "reset",
		"correlation_id": newUIEventID(),
		"event_id":       newUIEventID(),
	})
	http.Redirect(w, r, "/providers", http.StatusSeeOther)
	return true
}

func (s *Server) handleNonAIProviderTestIfNeeded(w http.ResponseWriter, r *http.Request) bool {
	slug := strings.ToLower(strings.TrimSpace(r.PathValue("name")))
	credKey := nonAICredentialKey(slug)
	if credKey == "" {
		return false
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return true
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return true
	}
	snapshot, loaded, err := loadProviderRuntimeSnapshot(r.Context(), s.setupStore, slug)
	if err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, err.Error())
		return true
	}
	if !loaded {
		switch slug {
		case "abuseipdb":
			snapshot.Enabled = s.cfg.AbuseIPDB.Enabled
		case "spamhaus":
			snapshot.Enabled = s.cfg.Spamhaus.Enabled
		case "virustotal":
			snapshot.Enabled = s.cfg.VirusTotal.Enabled
		}
	}
	configured := credentialConfigured(r.Context(), s.credentialStore, credKey)
	if !snapshot.Enabled {
		snapshot.LastTestAt = time.Now().UTC()
		snapshot.LastFailureAt = snapshot.LastTestAt
		snapshot.LastTestStatus = providerTestDisabledByOperator
		snapshot.LastErrorCode = providerTestDisabledByOperator
		snapshot.Healthy = false
		if err := saveProviderRuntimeSnapshot(r.Context(), s.setupStore, slug, snapshot); err != nil {
			s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, err.Error())
			return true
		}
		s.audit.Record("provider_test_failed", map[string]string{
			"provider":       slug,
			"target":         strings.ToUpper(slug),
			"result":         providerTestDisabledByOperator,
			"correlation_id": newUIEventID(),
			"event_id":       newUIEventID(),
		})
		http.Redirect(w, r, "/providers", http.StatusSeeOther)
		return true
	}
	if !configured {
		snapshot.LastTestAt = time.Now().UTC()
		snapshot.LastFailureAt = snapshot.LastTestAt
		snapshot.LastTestStatus = providerStatusMissingSecret
		snapshot.LastErrorCode = providerStatusMissingSecret
		snapshot.Healthy = false
		if err := saveProviderRuntimeSnapshot(r.Context(), s.setupStore, slug, snapshot); err != nil {
			s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, err.Error())
			return true
		}
		s.audit.Record("provider_test_failed", map[string]string{
			"provider":       slug,
			"target":         strings.ToUpper(slug),
			"result":         providerStatusMissingSecret,
			"correlation_id": newUIEventID(),
			"event_id":       newUIEventID(),
		})
		http.Redirect(w, r, "/providers", http.StatusSeeOther)
		return true
	}
	outcome, errCode, latencyMS := s.testNonAIProvider(r.Context(), slug, credKey)
	snapshot.LastTestAt = time.Now().UTC()
	snapshot.LastLatencyMS = latencyMS
	snapshot.LastTestStatus = outcome
	snapshot.LastErrorCode = errCode
	snapshot.LastSuccessAt = time.Time{}
	snapshot.LastFailureAt = time.Time{}
	snapshot.Healthy = outcome == providerTestReady
	if snapshot.Healthy {
		snapshot.LastSuccessAt = snapshot.LastTestAt
	} else {
		snapshot.LastFailureAt = snapshot.LastTestAt
	}
	if err := saveProviderRuntimeSnapshot(r.Context(), s.setupStore, slug, snapshot); err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusInternalServerError, err.Error())
		return true
	}
	s.audit.Record("provider_test", map[string]string{
		"provider":       slug,
		"target":         strings.ToUpper(slug),
		"result":         outcome,
		"correlation_id": newUIEventID(),
		"event_id":       newUIEventID(),
	})
	http.Redirect(w, r, "/providers", http.StatusSeeOther)
	return true
}

func (s *Server) handleProvidersTestAll(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.scheduleAIProviderAutoTest(AIProviderOpenAI)
	s.scheduleAIProviderAutoTest(AIProviderAnthropic)
	s.scheduleAIProviderAutoTest(AIProviderGemini)
	for _, slug := range []string{"abuseipdb", "spamhaus", "virustotal"} {
		s.scheduleNonAIProviderAutoTest(slug)
	}
	s.audit.Record("providers_test_all", map[string]string{
		"target":         "providers",
		"result":         "started",
		"correlation_id": newUIEventID(),
		"event_id":       newUIEventID(),
	})
	http.Redirect(w, r, "/providers", http.StatusSeeOther)
}

func (s *Server) providerDashboardEntries() []AIProviderDashboardView {
	return s.providerDashboardViews()
}
