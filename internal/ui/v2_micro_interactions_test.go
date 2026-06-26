package ui

import (
	"strings"
	"testing"
)

func TestRenderV2StatusBannerOk(t *testing.T) {
	out := renderV2StatusBanner("ok", "● HEALTHY", "All systems operational", "", "", "")
	if !strings.Contains(out, "#4cc79a") {
		t.Errorf("expected ok color #4cc79a in output, got: %s", out)
	}
}

func TestRenderV2StatusBannerWarn(t *testing.T) {
	out := renderV2StatusBanner("warn", "⚠ DEGRADED", "Some services degraded", "", "", "")
	if !strings.Contains(out, "#f5a443") {
		t.Errorf("expected warn color #f5a443 in output, got: %s", out)
	}
}

func TestRenderV2StatusBannerError(t *testing.T) {
	out := renderV2StatusBanner("error", "✗ CRITICAL", "System outage detected", "", "", "")
	if !strings.Contains(out, "#ef5f6b") {
		t.Errorf("expected error color #ef5f6b in output, got: %s", out)
	}
}

func TestRenderV2StatusBannerInfo(t *testing.T) {
	out := renderV2StatusBanner("info", "ℹ INFO", "Maintenance window active", "", "", "")
	if !strings.Contains(out, "#9b8cff") {
		t.Errorf("expected info color #9b8cff in output, got: %s", out)
	}
}

func TestRenderV2StatusBannerWithCTA(t *testing.T) {
	out := renderV2StatusBanner("ok", "● HEALTHY", "All systems operational", "secondary info", "/details", "View Details")
	if !strings.Contains(out, "/details") {
		t.Errorf("expected ctaHref /details in output, got: %s", out)
	}
	if !strings.Contains(out, "View Details") {
		t.Errorf("expected ctaLabel 'View Details' in output, got: %s", out)
	}
}

func TestRenderV2StatusBannerNoCTA(t *testing.T) {
	out := renderV2StatusBanner("ok", "● HEALTHY", "All systems operational", "", "", "")
	if strings.Contains(out, "<a ") {
		t.Errorf("expected no anchor tag when ctaHref is empty, got: %s", out)
	}
}

func TestRenderV2SectionHeader(t *testing.T) {
	out := renderV2SectionHeader("Infrastructure Health", "INFRASTRUCTURE", "")
	if !strings.Contains(out, "Infrastructure Health") {
		t.Errorf("expected title 'Infrastructure Health' in output, got: %s", out)
	}
	if !strings.Contains(out, "INFRASTRUCTURE") {
		t.Errorf("expected eyebrow 'INFRASTRUCTURE' in output, got: %s", out)
	}
}

func TestRenderV2SectionHeaderNoDetail(t *testing.T) {
	out := renderV2SectionHeader("Infrastructure Health", "INFRASTRUCTURE", "")
	// When detail is empty, there should be no empty detail element rendered
	if strings.Contains(out, `class="v2-section-detail"`) {
		t.Errorf("expected no detail element when detail is empty, got: %s", out)
	}
}

func TestRenderV2FreshnessStamp(t *testing.T) {
	out := renderV2FreshnessStamp("refreshed", "2m ago")
	if !strings.Contains(out, "refreshed") {
		t.Errorf("expected label 'refreshed' in output, got: %s", out)
	}
	if !strings.Contains(out, "2m ago") {
		t.Errorf("expected value '2m ago' in output, got: %s", out)
	}
}

func TestRenderV2ActionHint(t *testing.T) {
	out := renderV2ActionHint("View all incidents", "/incidents")
	if !strings.Contains(out, "/incidents") {
		t.Errorf("expected href /incidents in output, got: %s", out)
	}
	if !strings.Contains(out, "View all incidents") {
		t.Errorf("expected label 'View all incidents' in output, got: %s", out)
	}
	if !strings.Contains(out, "<a ") {
		t.Errorf("expected anchor tag in output, got: %s", out)
	}
}
