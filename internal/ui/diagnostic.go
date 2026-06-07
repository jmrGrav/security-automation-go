package ui

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/jm/security-automation-go/internal/detect"
	"github.com/jm/security-automation-go/internal/health"
)

// DiagnosticReport is the full diagnostic output stored to disk and returned as JSON.
type DiagnosticReport struct {
	GeneratedAt string            `json:"generated_at"`
	Health      []health.Check    `json:"health"`
	Detection   []detect.Result   `json:"detection"`
	RuntimeInfo map[string]string `json:"runtime_info"`
}

func (s *Server) handleRunDiagnostic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.getSession(r); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	report := DiagnosticReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Health:      health.RunAll(s.buildHealthConfig()),
		Detection:   detect.RunAll(s.buildDetectConfig()),
		RuntimeInfo: map[string]string{
			"state_dir": s.cfg.StateDir,
			"ui_addr":   s.cfg.UI.Addr,
		},
	}

	diagDir := filepath.Join(s.cfg.StateDir, "diagnostics")
	if err := os.MkdirAll(diagDir, 0o750); err != nil {
		http.Error(w, "cannot create diagnostics dir: "+err.Error(), http.StatusInternalServerError)
		return
	}
	filename := time.Now().UTC().Format("20060102-150405") + ".json"
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		http.Error(w, "marshal: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(filepath.Join(diagDir, filename), data, 0o640); err != nil {
		http.Error(w, "write: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}
