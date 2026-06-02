package ui

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
)

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

func (s *Server) providerManagementView() (AIProviderManagementView, error) {
	state, loaded, err := loadAIProviderState(s.cfg.UI.ProviderStateFile)
	if err != nil {
		return AIProviderManagementView{}, err
	}
	aiCfg := normalizeAIConfig(applyAIProviderState(s.aiBaseConfig, state, loaded))
	views := providerManagementView(aiCfg, state, loaded)
	return views, nil
}

func (s *Server) providerDashboardViews() []AIProviderDashboardView {
	state, loaded, err := loadAIProviderState(s.cfg.UI.ProviderStateFile)
	if err != nil {
		return nil
	}
	aiCfg := normalizeAIConfig(applyAIProviderState(s.aiBaseConfig, state, loaded))
	return providerDashboardViews(aiCfg, state, loaded)
}

func (s *Server) rebuildAIExplainFromState() error {
	state, loaded, err := loadAIProviderState(s.cfg.UI.ProviderStateFile)
	if err != nil {
		return err
	}
	effective := normalizeAIConfig(applyAIProviderState(s.aiBaseConfig, state, loaded))
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

func (s *Server) providerFactory(name AIProviderName) (ProviderFactory, bool) {
	if s.providerFactories == nil {
		return nil, false
	}
	factory, ok := s.providerFactories[strings.ToLower(string(name))]
	return factory, ok && factory != nil
}

func (s *Server) handleProviderReplaceKey(w http.ResponseWriter, r *http.Request) {
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
	if strings.ToLower(strings.TrimSpace(r.PostForm.Get("confirm_replace"))) != "yes" {
		view, _ := s.providerManagementView()
		view.Error = "confirmation required before replacing a key"
		w.WriteHeader(http.StatusBadRequest)
		_ = ProviderManagementPage(view, s.csrfTokenFromRequest(r)).Render(r.Context(), w)
		return
	}
	secret := strings.TrimSpace(r.PostForm.Get("new_api_key"))
	if secret == "" {
		view, _ := s.providerManagementView()
		view.Error = "new API key is required"
		w.WriteHeader(http.StatusBadRequest)
		_ = ProviderManagementPage(view, s.csrfTokenFromRequest(r)).Render(r.Context(), w)
		return
	}
	secretFile := providerSecretPathForName(s.aiBaseConfig, name)
	if err := writeProviderSecret(secretFile, secret); err != nil {
		view, _ := s.providerManagementView()
		view.Error = fmt.Sprintf("%s\n%s", err.Error(), providerStatePathHint(secretFile, true))
		w.WriteHeader(http.StatusForbidden)
		_ = ProviderManagementPage(view, s.csrfTokenFromRequest(r)).Render(r.Context(), w)
		return
	}
	s.audit.Record("provider_key_rotated", map[string]string{
		"provider":       strings.ToLower(string(name)),
		"result":         "redacted",
		"correlation_id": newUIEventID(),
	})
	if err := s.rebuildAIExplainFromState(); err != nil {
		view, _ := s.providerManagementView()
		view.Error = fmt.Sprintf("key written but AI explain could not be rebuilt: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = ProviderManagementPage(view, s.csrfTokenFromRequest(r)).Render(r.Context(), w)
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
	state, _, err := loadAIProviderState(s.cfg.UI.ProviderStateFile)
	if err != nil {
		view, _ := s.providerManagementView()
		view.Error = err.Error()
		w.WriteHeader(http.StatusInternalServerError)
		_ = ProviderManagementPage(view, s.csrfTokenFromRequest(r)).Render(r.Context(), w)
		return
	}
	record := providerStateRecord(state, name)
	display, secretFile, _ := providerSpec(name)
	secretFile = providerSecretPathForName(s.aiBaseConfig, name)
	secret := providerSecretSnapshotForPath(secretFile)
	if enabled {
		if !secret.present {
			record.LastErrorCode = providerStatusMissingSecret
			setProviderStateRecord(&state, name, record)
			if err := saveAIProviderState(s.cfg.UI.ProviderStateFile, state); err != nil {
				view, _ := s.providerManagementView()
				view.Error = fmt.Sprintf("%s\n%s", err.Error(), providerStatePathHint(s.cfg.UI.ProviderStateFile, false))
				w.WriteHeader(http.StatusForbidden)
				_ = ProviderManagementPage(view, s.csrfTokenFromRequest(r)).Render(r.Context(), w)
				return
			}
			s.audit.Record("provider_config_validation_failed", map[string]string{
				"provider":       strings.ToLower(string(name)),
				"result":         providerStatusMissingSecret,
				"correlation_id": newUIEventID(),
			})
			view, _ := s.providerManagementView()
			view.Error = fmt.Sprintf("provider %s cannot be enabled: secret file missing at %s\n%s", display, secretFile, providerStatePathHint(secretFile, true))
			w.WriteHeader(http.StatusForbidden)
			_ = ProviderManagementPage(view, s.csrfTokenFromRequest(r)).Render(r.Context(), w)
			return
		}
		if secret.state == providerStatusInvalidSecret {
			record.LastErrorCode = providerStatusInvalidSecret
			setProviderStateRecord(&state, name, record)
			if err := saveAIProviderState(s.cfg.UI.ProviderStateFile, state); err != nil {
				view, _ := s.providerManagementView()
				view.Error = fmt.Sprintf("%s\n%s", err.Error(), providerStatePathHint(s.cfg.UI.ProviderStateFile, false))
				w.WriteHeader(http.StatusForbidden)
				_ = ProviderManagementPage(view, s.csrfTokenFromRequest(r)).Render(r.Context(), w)
				return
			}
			s.audit.Record("provider_config_validation_failed", map[string]string{
				"provider":       strings.ToLower(string(name)),
				"result":         providerStatusInvalidSecret,
				"correlation_id": newUIEventID(),
			})
			view, _ := s.providerManagementView()
			view.Error = fmt.Sprintf("provider %s cannot be enabled: secret file is unreadable or invalid at %s\n%s", display, secretFile, providerStatePathHint(secretFile, true))
			w.WriteHeader(http.StatusForbidden)
			_ = ProviderManagementPage(view, s.csrfTokenFromRequest(r)).Render(r.Context(), w)
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
	if err := saveAIProviderState(s.cfg.UI.ProviderStateFile, state); err != nil {
		view, _ := s.providerManagementView()
		view.Error = fmt.Sprintf("%s\n%s", err.Error(), providerStatePathHint(s.cfg.UI.ProviderStateFile, false))
		w.WriteHeader(http.StatusForbidden)
		_ = ProviderManagementPage(view, s.csrfTokenFromRequest(r)).Render(r.Context(), w)
		return
	}
	if err := s.rebuildAIExplainFromState(); err != nil {
		view, _ := s.providerManagementView()
		view.Error = fmt.Sprintf("provider state saved but AI explain could not be rebuilt: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = ProviderManagementPage(view, s.csrfTokenFromRequest(r)).Render(r.Context(), w)
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
	state, loaded, err := loadAIProviderState(s.cfg.UI.ProviderStateFile)
	if err != nil {
		view, _ := s.providerManagementView()
		view.Error = err.Error()
		w.WriteHeader(http.StatusInternalServerError)
		_ = ProviderManagementPage(view, s.csrfTokenFromRequest(r)).Render(r.Context(), w)
		return
	}
	record := providerStateRecord(state, name)
	display, _, _ := providerSpec(name)
	secretFile := providerSecretPathForName(s.aiBaseConfig, name)
	secret := providerSecretSnapshotForPath(secretFile)
	outcome := providerTestUnknownError
	errorCode := providerTestUnknownError
	var latency time.Duration

	if !secret.present {
		outcome = providerTestUnknownError
		errorCode = providerStatusMissingSecret
	} else if secret.state == providerStatusInvalidSecret {
		outcome = providerTestUnknownError
		errorCode = providerStatusInvalidSecret
	} else {
		factory, ok := s.providerFactory(name)
		if !ok {
			outcome = providerTestUnknownError
			errorCode = providerTestUnknownError
		} else {
			providerCfg := providerConfigForName(applyAIProviderState(s.aiBaseConfig, state, loaded), name)
			provider := factory(ai.ProviderConfig{
				Enabled:    true,
				Model:      providerCfg.Model,
				APIKeyFile: secretFile,
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
	if err := saveAIProviderState(s.cfg.UI.ProviderStateFile, state); err != nil {
		view, _ := s.providerManagementView()
		view.Error = fmt.Sprintf("%s\n%s", err.Error(), providerStatePathHint(s.cfg.UI.ProviderStateFile, false))
		w.WriteHeader(http.StatusForbidden)
		_ = ProviderManagementPage(view, s.csrfTokenFromRequest(r)).Render(r.Context(), w)
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
