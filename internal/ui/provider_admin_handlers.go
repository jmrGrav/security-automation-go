package ui

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
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
	return cfg
}

func (s *Server) nonAIProviderEntries() []NonAIProviderEntry {
	cfSentinel := s.cfSentinelToken() != "" && s.cfZoneIDFromSetup(context.Background()) != ""
	crowdSecCfg := strings.TrimSpace(s.cfg.CrowdSec.APIKey) != "" || strings.TrimSpace(s.cfg.CrowdSec.DecisionsLog) != ""
	betterStackCfg := strings.TrimSpace(s.cfg.BetterStack.SourceToken) != ""

	return []NonAIProviderEntry{
		{
			Name:             "AbuseIPDB",
			Category:         nonAIProviderCategory("abuseipdb"),
			CredentialKey:    "ABUSEIPDB_KEY",
			HasKeyManagement: true,
			Enabled:          s.cfg.AbuseIPDB.Enabled,
			Configured:       providerConfiguredValue(s.cfg.AbuseIPDB.APIKey, s.secretProvider, "ABUSEIPDB_KEY") != "",
			MaskedKey:        maskedProviderValue(s.cfg.AbuseIPDB.APIKey, s.secretProvider, "ABUSEIPDB_KEY"),
			Status:           providerStatus(s.cfg.AbuseIPDB.Enabled, providerConfiguredValue(s.cfg.AbuseIPDB.APIKey, s.secretProvider, "ABUSEIPDB_KEY") != ""),
		},
		{
			Name:             "Spamhaus",
			Category:         nonAIProviderCategory("spamhaus"),
			CredentialKey:    "SPAMHAUS_API_KEY",
			HasKeyManagement: true,
			Enabled:          s.cfg.Spamhaus.Enabled,
			Configured:       providerConfiguredValue(s.cfg.Spamhaus.APIKey, s.secretProvider, "SPAMHAUS_API_KEY") != "",
			MaskedKey:        maskedProviderValue(s.cfg.Spamhaus.APIKey, s.secretProvider, "SPAMHAUS_API_KEY"),
			Status:           providerStatus(s.cfg.Spamhaus.Enabled, providerConfiguredValue(s.cfg.Spamhaus.APIKey, s.secretProvider, "SPAMHAUS_API_KEY") != ""),
		},
		{
			Name:             "VirusTotal",
			Category:         nonAIProviderCategory("virustotal"),
			CredentialKey:    "VIRUSTOTAL_API_KEY",
			HasKeyManagement: true,
			Enabled:          s.cfg.VirusTotal.Enabled,
			Configured:       providerConfiguredValue(s.cfg.VirusTotal.APIKey, s.secretProvider, "VIRUSTOTAL_API_KEY") != "",
			MaskedKey:        maskedProviderValue(s.cfg.VirusTotal.APIKey, s.secretProvider, "VIRUSTOTAL_API_KEY"),
			Status:           providerStatus(s.cfg.VirusTotal.Enabled, providerConfiguredValue(s.cfg.VirusTotal.APIKey, s.secretProvider, "VIRUSTOTAL_API_KEY") != ""),
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

func (s *Server) providerFactory(name AIProviderName) (ProviderFactory, bool) {
	if s.providerFactories == nil {
		return nil, false
	}
	factory, ok := s.providerFactories[strings.ToLower(string(name))]
	return factory, ok && factory != nil
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
	http.Redirect(w, r, "/providers", http.StatusSeeOther)
}

func (s *Server) handleProviderEnable(w http.ResponseWriter, r *http.Request) {
	s.handleProviderToggle(w, r, true)
}

func (s *Server) handleProviderDisable(w http.ResponseWriter, r *http.Request) {
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
		record.LastErrorCode = ""
		s.audit.Record("provider_enabled", map[string]string{
			"provider":       strings.ToLower(string(name)),
			"result":         "redacted",
			"correlation_id": newUIEventID(),
		})
	} else {
		record.Enabled = false
		record.LastErrorCode = ""
		s.audit.Record("provider_disabled", map[string]string{
			"provider":       strings.ToLower(string(name)),
			"result":         "redacted",
			"correlation_id": newUIEventID(),
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
	http.Redirect(w, r, "/providers", http.StatusSeeOther)
}

func (s *Server) handleProviderTest(w http.ResponseWriter, r *http.Request) {
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
	var latency time.Duration

	if !configured {
		outcome = providerTestUnknownError
		errorCode = providerStatusMissingSecret
	} else {
		factory, ok := s.providerFactory(name)
		if !ok {
			outcome = providerTestUnknownError
			errorCode = providerTestUnknownError
		} else {
			provider := factory(ai.ProviderConfig{
				Enabled: true,
				Model:   providerCfg.Model,
				APIKey:  providerCfg.APIKey,
			})
			if provider == nil {
				outcome = providerTestUnknownError
				errorCode = providerTestUnknownError
			} else {
				testCtx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
				start := time.Now()
				resp, testErr := provider.Explain(testCtx, ai.ExplainRequest{
					SubjectType:        "provider",
					SubjectID:          display,
					ProviderPreference: strings.ToLower(string(name)),
					MaxContextBytes:    128,
					MaxOutputTokens:    48,
				})
				_ = resp
				cancel()
				latency = time.Since(start)
				outcome, errorCode = providerTestOutcome(testErr)
			}
		}
	}

	record.LastTestAt = time.Now().UTC()
	record.LastTestStatus = outcome
	record.LastTestLatencyMS = int(latency / time.Millisecond)
	record.LastErrorCode = errorCode
	setProviderStateRecord(&state, name, record)
	if err := s.saveAIState(r.Context(), state); err != nil {
		s.renderUnifiedProvidersError(w, r, http.StatusForbidden, err.Error())
		return
	}
	if outcome == providerTestReady {
		s.audit.Record("provider_test", map[string]string{
			"provider":       strings.ToLower(string(name)),
			"result":         outcome,
			"correlation_id": newUIEventID(),
		})
	} else {
		s.audit.Record("provider_test_failed", map[string]string{
			"provider":       strings.ToLower(string(name)),
			"result":         outcome,
			"correlation_id": newUIEventID(),
		})
	}
	http.Redirect(w, r, "/providers", http.StatusSeeOther)
}

func (s *Server) providerDashboardEntries() []AIProviderDashboardView {
	return s.providerDashboardViews()
}
