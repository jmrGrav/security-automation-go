package ui_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/ui"
)

func TestDashboardConsolePageUsesEncryptedSQLiteWording(t *testing.T) {
	view := ui.DashboardConsoleView{
		AIProviders: []ui.AIProviderDashboardView{{
			Name:         "OpenAI",
			Status:       "READY",
			Model:        "gpt-4.1-mini",
			SecretState:  "not configured",
			EnabledState: "disabled",
		}},
	}
	var buf bytes.Buffer
	if err := ui.DashboardConsolePage(view).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render dashboard console page: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "encrypted SQLite credential store") {
		t.Fatalf("dashboard should mention encrypted SQLite credential store, body=%s", body)
	}
	if strings.Contains(body, "file-backed secrets") {
		t.Fatalf("dashboard must not mention file-backed secrets, body=%s", body)
	}
}
