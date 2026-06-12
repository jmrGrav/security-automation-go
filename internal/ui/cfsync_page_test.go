package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/shadow"
)

// writeShadowCycle writes one shadow.Cycle as a JSONL record to the state dir.
func writeShadowCycle(t *testing.T, stateDir string, c shadow.Cycle) {
	t.Helper()
	store := shadow.NewStore(stateDir)
	if err := store.Append(c); err != nil {
		t.Fatalf("write shadow cycle: %v", err)
	}
}

func TestCFSyncView_NoData(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	view := srv.buildCFSyncView()
	if view.HasData {
		t.Error("expected HasData=false when no cycles recorded")
	}
	if view.Error != "" {
		t.Errorf("unexpected error: %s", view.Error)
	}
}

func TestCFSyncView_WithData(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	cycle := shadow.Cycle{
		CycleAt:        time.Now().UTC(),
		ActiveBanCount: 42,
		CFRuleCount:    40,
		PlannedAdds:    []string{"1.2.3.4", "5.6.7.8"},
		PlannedDeletes: []string{"9.10.11.12"},
		AgreementPct:   95.0,
		InSync:         false,
	}
	writeShadowCycle(t, srv.cfg.StateDir, cycle)

	view := srv.buildCFSyncView()
	if !view.HasData {
		t.Fatal("expected HasData=true when cycle recorded")
	}
	if len(view.ToAdd) != 2 {
		t.Errorf("expected 2 ToAdd entries, got %d", len(view.ToAdd))
	}
	if len(view.ToDelete) != 1 {
		t.Errorf("expected 1 ToDelete entry, got %d", len(view.ToDelete))
	}
	if view.ActiveBans != 42 {
		t.Errorf("expected ActiveBans=42, got %d", view.ActiveBans)
	}
	if view.InSync {
		t.Error("expected InSync=false")
	}
}

func TestCFSyncView_InSync(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	cycle := shadow.Cycle{
		CycleAt:        time.Now().UTC(),
		ActiveBanCount: 10,
		CFRuleCount:    10,
		PlannedAdds:    nil,
		PlannedDeletes: nil,
		AgreementPct:   100.0,
		InSync:         true,
	}
	writeShadowCycle(t, srv.cfg.StateDir, cycle)

	view := srv.buildCFSyncView()
	if !view.InSync {
		t.Error("expected InSync=true")
	}
	if len(view.ToAdd) != 0 || len(view.ToDelete) != 0 {
		t.Errorf("expected empty add/delete lists, got add=%v delete=%v", view.ToAdd, view.ToDelete)
	}
}

func TestCFSyncView_LatestCycleReturned(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	first := shadow.Cycle{
		CycleAt:      time.Now().UTC().Add(-1 * time.Hour),
		PlannedAdds:  []string{"old.ip"},
		AgreementPct: 50.0,
	}
	second := shadow.Cycle{
		CycleAt:      time.Now().UTC(),
		PlannedAdds:  []string{"new.ip"},
		AgreementPct: 99.0,
	}
	writeShadowCycle(t, srv.cfg.StateDir, first)
	writeShadowCycle(t, srv.cfg.StateDir, second)

	view := srv.buildCFSyncView()
	if view.CycleCount != 2 {
		t.Errorf("expected CycleCount=2, got %d", view.CycleCount)
	}
	if len(view.ToAdd) != 1 || view.ToAdd[0] != "new.ip" {
		t.Errorf("expected latest cycle ToAdd=[new.ip], got %v", view.ToAdd)
	}
}

func TestCFSyncPage_RendersNoData(t *testing.T) {
	view := CFSyncView{HasData: false}
	comp := CFSyncPage(view)
	w := httptest.NewRecorder()
	_ = comp.Render(nil, w)
	body := w.Body.String()

	if !strings.Contains(body, "CF Ban Sync") {
		t.Error("expected page title in body")
	}
	if !strings.Contains(body, "No sync cycles recorded") {
		t.Error("expected no-data message")
	}
}

func TestCFSyncPage_RendersDriftDetected(t *testing.T) {
	view := CFSyncView{
		HasData:      true,
		CycleAt:      time.Now().UTC(),
		AgreementPct: 80.0,
		InSync:       false,
		ToAdd:        []string{"1.2.3.4"},
		ToDelete:     []string{"9.8.7.6"},
		ActiveBans:   20,
		CFRules:      19,
		CycleCount:   5,
	}
	comp := CFSyncPage(view)
	w := httptest.NewRecorder()
	_ = comp.Render(nil, w)
	body := w.Body.String()

	if !strings.Contains(body, "DRIFT DETECTED") {
		t.Error("expected DRIFT DETECTED badge")
	}
	if !strings.Contains(body, "1.2.3.4") {
		t.Error("expected ToAdd IP in body")
	}
	if !strings.Contains(body, "9.8.7.6") {
		t.Error("expected ToDelete IP in body")
	}
}

func TestCFSyncPage_RendersInSync(t *testing.T) {
	view := CFSyncView{
		HasData:      true,
		CycleAt:      time.Now().UTC(),
		AgreementPct: 100.0,
		InSync:       true,
		ToAdd:        nil,
		ToDelete:     nil,
		ActiveBans:   15,
		CFRules:      15,
		CycleCount:   3,
	}
	comp := CFSyncPage(view)
	w := httptest.NewRecorder()
	_ = comp.Render(nil, w)
	body := w.Body.String()

	if !strings.Contains(body, "IN SYNC") {
		t.Error("expected IN SYNC badge")
	}
}

func TestHandleCFSyncPage_HTTPIntegration(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	cycle := shadow.Cycle{
		CycleAt:      time.Now().UTC(),
		PlannedAdds:  []string{"10.0.0.1"},
		AgreementPct: 98.0,
		InSync:       false,
	}
	writeShadowCycle(t, srv.cfg.StateDir, cycle)

	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodGet, "/sync", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "CF Ban Sync") {
		t.Error("expected page title")
	}
	if !strings.Contains(body, "10.0.0.1") {
		t.Error("expected IP in sync page")
	}
}

func TestCFSyncView_CorruptCycleFile(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	// Write a corrupt JSONL file
	path := srv.cfg.StateDir + "/shadow-cycles.jsonl"
	if err := os.WriteFile(path, []byte("not valid json\n"), 0644); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	view := srv.buildCFSyncView()
	// Corrupt lines are skipped by the store — no data returned, no error
	if view.Error != "" {
		t.Errorf("unexpected error for corrupt file: %s", view.Error)
	}
	if view.HasData {
		t.Error("expected HasData=false when all lines are corrupt")
	}
}

func TestCFSyncView_MixedValidAndCorruptLines(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	path := srv.cfg.StateDir + "/shadow-cycles.jsonl"
	validCycle := shadow.Cycle{
		CycleAt:      time.Now().UTC(),
		PlannedAdds:  []string{"1.1.1.1"},
		AgreementPct: 90.0,
	}
	line, _ := json.Marshal(validCycle)
	content := "corrupt line\n" + string(line) + "\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	view := srv.buildCFSyncView()
	if !view.HasData {
		t.Error("expected HasData=true when at least one valid cycle exists")
	}
	if len(view.ToAdd) != 1 || view.ToAdd[0] != "1.1.1.1" {
		t.Errorf("expected ToAdd=[1.1.1.1], got %v", view.ToAdd)
	}
}
