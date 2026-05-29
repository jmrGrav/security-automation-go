package shadow_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/shadow"
)

func makePlan(active, cf []string) shadow.SyncPlan {
	activeSet := make(map[string]bool)
	for _, ip := range active {
		activeSet[ip] = true
	}
	cfSet := make(map[string]bool)
	for _, ip := range cf {
		cfSet[ip] = true
	}
	var toAdd, toDelete []string
	for ip := range activeSet {
		if !cfSet[ip] {
			toAdd = append(toAdd, ip)
		}
	}
	for ip := range cfSet {
		if !activeSet[ip] {
			toDelete = append(toDelete, ip)
		}
	}
	return shadow.SyncPlan{ActiveBans: activeSet, CFRules: cfSet, ToAdd: toAdd, ToDelete: toDelete}
}

func TestCompare_FullAgreement(t *testing.T) {
	plan := makePlan([]string{"1.2.3.4", "5.6.7.8"}, []string{"1.2.3.4", "5.6.7.8"})
	c := shadow.Compare(plan, time.Now())
	if !c.InSync {
		t.Error("want InSync=true when plans match exactly")
	}
	if c.AgreementPct != 100.0 {
		t.Errorf("want 100%% agreement, got %.2f", c.AgreementPct)
	}
	if len(c.FalsePositives) != 0 || len(c.FalseNegatives) != 0 {
		t.Error("want no false positives or negatives when in sync")
	}
}

func TestCompare_FalsePositives(t *testing.T) {
	// Go would add 9.10.11.12, Python hasn't
	plan := makePlan([]string{"1.2.3.4", "9.10.11.12"}, []string{"1.2.3.4"})
	c := shadow.Compare(plan, time.Now())
	if c.InSync {
		t.Error("want InSync=false when Go has extra IPs")
	}
	if len(c.FalsePositives) != 1 {
		t.Errorf("want 1 false positive, got %d", len(c.FalsePositives))
	}
}

func TestCompare_FalseNegatives(t *testing.T) {
	// Python has 9.10.11.12, Go would remove it
	plan := makePlan([]string{"1.2.3.4"}, []string{"1.2.3.4", "9.10.11.12"})
	c := shadow.Compare(plan, time.Now())
	if c.InSync {
		t.Error("want InSync=false when CF has extra IPs")
	}
	if len(c.FalseNegatives) != 1 {
		t.Errorf("want 1 false negative, got %d", len(c.FalseNegatives))
	}
}

func TestCompare_BothEmpty(t *testing.T) {
	plan := makePlan(nil, nil)
	c := shadow.Compare(plan, time.Now())
	if !c.InSync {
		t.Error("want InSync=true when both empty")
	}
	if c.AgreementPct != 100.0 {
		t.Errorf("want 100%% when both empty, got %.2f", c.AgreementPct)
	}
}

func TestCompare_JaccardSimilarity(t *testing.T) {
	// |A ∩ B| = 1, |A ∪ B| = 3, Jaccard = 1/3 ≈ 33.3%
	plan := makePlan([]string{"1.1.1.1", "2.2.2.2"}, []string{"1.1.1.1", "3.3.3.3"})
	c := shadow.Compare(plan, time.Now())
	want := 100.0 / 3.0
	if c.AgreementPct < want-0.1 || c.AgreementPct > want+0.1 {
		t.Errorf("want ~33.3%% Jaccard, got %.2f", c.AgreementPct)
	}
}

func TestComputeMetrics_SevenDayEligibility(t *testing.T) {
	now := time.Now().UTC()
	var cycles []shadow.Cycle
	// 350 cycles × 30 min = 175 hours > 7 days (168h)
	for i := 0; i < 350; i++ {
		cycles = append(cycles, shadow.Cycle{
			CycleAt:      now.Add(-time.Duration(i) * 30 * time.Minute),
			AgreementPct: 100.0,
			InSync:       true,
		})
	}
	m := shadow.ComputeMetrics(cycles)
	if !m.SevenDayEligible {
		t.Errorf("want SevenDayEligible=true with 175 hours of data, got span check failed")
	}
	if m.SevenDayPct != 100.0 {
		t.Errorf("want 100%% 7-day avg, got %.2f", m.SevenDayPct)
	}
	if m.AgreementPctAvg != 100.0 {
		t.Errorf("want 100%% avg, got %.2f", m.AgreementPctAvg)
	}
}

func TestComputeMetrics_ConsecutiveSync(t *testing.T) {
	cycles := []shadow.Cycle{
		{InSync: true, AgreementPct: 100, CycleAt: time.Now()},
		{InSync: true, AgreementPct: 100, CycleAt: time.Now()},
		{InSync: false, AgreementPct: 80, CycleAt: time.Now()},
		{InSync: true, AgreementPct: 100, CycleAt: time.Now()},
		{InSync: true, AgreementPct: 100, CycleAt: time.Now()},
		{InSync: true, AgreementPct: 100, CycleAt: time.Now()},
	}
	m := shadow.ComputeMetrics(cycles)
	if m.ConsecutiveSync != 3 {
		t.Errorf("want max consecutive run of 3, got %d", m.ConsecutiveSync)
	}
}

func TestStore_AppendAndRead(t *testing.T) {
	dir := t.TempDir()
	store := shadow.NewStore(dir)

	c1 := shadow.Cycle{CycleAt: time.Now(), AgreementPct: 100, InSync: true}
	c2 := shadow.Cycle{CycleAt: time.Now().Add(time.Minute), AgreementPct: 90, InSync: false}

	if err := store.Append(c1); err != nil {
		t.Fatalf("Append c1: %v", err)
	}
	if err := store.Append(c2); err != nil {
		t.Fatalf("Append c2: %v", err)
	}

	cycles, err := store.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(cycles) != 2 {
		t.Fatalf("want 2 cycles, got %d", len(cycles))
	}
	if cycles[0].AgreementPct != 100 || cycles[1].AgreementPct != 90 {
		t.Error("cycle data not preserved")
	}
}

func TestStore_Prune(t *testing.T) {
	dir := t.TempDir()
	store := shadow.NewStore(dir)

	old := shadow.Cycle{CycleAt: time.Now().Add(-8 * 24 * time.Hour), AgreementPct: 100}
	recent := shadow.Cycle{CycleAt: time.Now(), AgreementPct: 99}

	_ = store.Append(old)
	_ = store.Append(recent)

	retainSince := time.Now().Add(-7 * 24 * time.Hour)
	if err := store.Prune(retainSince); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	cycles, _ := store.ReadAll()
	if len(cycles) != 1 {
		t.Fatalf("want 1 cycle after prune, got %d", len(cycles))
	}
	if cycles[0].AgreementPct != 99 {
		t.Error("wrong cycle retained after prune")
	}
}

func TestWriteReport(t *testing.T) {
	dir := t.TempDir()
	cycles := []shadow.Cycle{
		{CycleAt: time.Now(), AgreementPct: 100, InSync: true, ActiveBanCount: 5, CFRuleCount: 5},
	}
	outPath := filepath.Join(dir, "SHADOW_MODE_REPORT.md")
	if err := shadow.WriteReport(outPath, cycles); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if len(data) == 0 {
		t.Error("report is empty")
	}
	content := string(data)
	if !contains(content, "Shadow Mode Validation Report") {
		t.Error("report missing title")
	}
	if !contains(content, "IN SYNC") {
		t.Error("report missing IN SYNC status")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
