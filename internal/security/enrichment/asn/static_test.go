package asn_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/jm/security-automation-go/internal/security/enrichment/asn"
)

func TestStaticProvider_CloudflareIPIsProtected(t *testing.T) {
	p := asn.NewStaticProvider()
	// 104.16.0.1 is inside Cloudflare's 104.16.0.0/13.
	ip := netip.MustParseAddr("104.16.0.1")
	result, err := p.Lookup(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Protected {
		t.Errorf("Cloudflare IP should be protected, got %+v", result)
	}
	if result.Kind != asn.KindProtected {
		t.Errorf("expected KindProtected, got %q", result.Kind)
	}
	if result.Org != "cloudflare" {
		t.Errorf("expected org=cloudflare, got %q", result.Org)
	}
}

func TestStaticProvider_GoogleIPIsSearchBot(t *testing.T) {
	p := asn.NewStaticProvider()
	// 66.249.64.1 is inside Google's 66.249.64.0/19.
	ip := netip.MustParseAddr("66.249.64.1")
	result, err := p.Lookup(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Protected {
		t.Errorf("Google IP should be protected, got %+v", result)
	}
	if result.Kind != asn.KindSearchBot {
		t.Errorf("expected KindSearchBot, got %q", result.Kind)
	}
	if result.Org != "google" {
		t.Errorf("expected org=google, got %q", result.Org)
	}
}

func TestStaticProvider_MicrosoftIPIsSearchBot(t *testing.T) {
	p := asn.NewStaticProvider()
	// 40.74.0.1 is inside Microsoft's 40.74.0.0/15.
	ip := netip.MustParseAddr("40.74.0.1")
	result, err := p.Lookup(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Protected {
		t.Errorf("Microsoft IP should be protected, got %+v", result)
	}
	if result.Kind != asn.KindSearchBot {
		t.Errorf("expected KindSearchBot, got %q", result.Kind)
	}
	if result.Org != "microsoft" {
		t.Errorf("expected org=microsoft, got %q", result.Org)
	}
}

func TestStaticProvider_UnknownIPIsNeutral(t *testing.T) {
	p := asn.NewStaticProvider()
	// 203.0.113.1 is a TEST-NET-3 address, not in any protected range.
	ip := netip.MustParseAddr("203.0.113.1")
	result, err := p.Lookup(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Protected {
		t.Errorf("unknown IP must not be protected, got %+v", result)
	}
	if result.Kind != asn.KindUnknown {
		t.Errorf("expected KindUnknown, got %q", result.Kind)
	}
}

func TestStaticProvider_IPv6CloudflareIsProtected(t *testing.T) {
	p := asn.NewStaticProvider()
	// 2606:4700::1 is inside Cloudflare's 2606:4700::/32.
	ip := netip.MustParseAddr("2606:4700::1")
	result, err := p.Lookup(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Protected {
		t.Errorf("Cloudflare IPv6 should be protected, got %+v", result)
	}
	if result.Kind != asn.KindProtected {
		t.Errorf("expected KindProtected, got %q", result.Kind)
	}
}

func TestStaticProvider_NameIsStatic(t *testing.T) {
	p := asn.NewStaticProvider()
	if p.Name() != "static" {
		t.Errorf("expected name=static, got %q", p.Name())
	}
}

// ── OpenAI GPTBot ─────────────────────────────────────────────────────────────

func TestStaticProvider_OpenAIGPTBotIsAIAgent(t *testing.T) {
	p := asn.NewStaticProvider()
	// 20.171.206.1 is inside OpenAI GPTBot range 20.171.206.0/24
	// (source: https://openai.com/gptbot.json, verified 2026-06-01).
	ip := netip.MustParseAddr("20.171.206.1")
	result, err := p.Lookup(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Protected {
		t.Errorf("OpenAI GPTBot IP should be protected, got %+v", result)
	}
	if result.Kind != asn.KindAIAgent {
		t.Errorf("expected KindAIAgent, got %q", result.Kind)
	}
	if result.Org != "openai-gptbot" {
		t.Errorf("expected org=openai-gptbot, got %q", result.Org)
	}
}

// ── OpenAI OAI-SearchBot ──────────────────────────────────────────────────────

func TestStaticProvider_OpenAISearchBotIsAIAgent(t *testing.T) {
	p := asn.NewStaticProvider()
	// 51.8.102.1 is inside OAI-SearchBot range 51.8.102.0/24
	// (source: https://openai.com/searchbot.json, verified 2026-06-01).
	ip := netip.MustParseAddr("51.8.102.1")
	result, err := p.Lookup(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Protected {
		t.Errorf("OpenAI SearchBot IP should be protected, got %+v", result)
	}
	if result.Kind != asn.KindAIAgent {
		t.Errorf("expected KindAIAgent, got %q", result.Kind)
	}
	if result.Org != "openai-searchbot" {
		t.Errorf("expected org=openai-searchbot, got %q", result.Org)
	}
}

// ── GitHub Copilot ────────────────────────────────────────────────────────────

func TestStaticProvider_GitHubCopilotIsAIAgent(t *testing.T) {
	p := asn.NewStaticProvider()
	// 140.82.112.1 is inside GitHub Copilot range 140.82.112.0/20
	// (source: https://api.github.com/meta copilot section, verified 2026-06-01).
	ip := netip.MustParseAddr("140.82.112.1")
	result, err := p.Lookup(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Protected {
		t.Errorf("GitHub Copilot IP should be protected, got %+v", result)
	}
	if result.Kind != asn.KindAIAgent {
		t.Errorf("expected KindAIAgent, got %q", result.Kind)
	}
	if result.Org != "github-copilot" {
		t.Errorf("expected org=github-copilot, got %q", result.Org)
	}
}

// ── Anthropic ─────────────────────────────────────────────────────────────────

// TestStaticProvider_AnthropicIsAIAgent verifies that Anthropic's published
// outbound IP range is classified as KindAIAgent with no-hard-ban protection.
// Source: https://platform.claude.com/docs/en/api/ip-addresses (verified 2026-06-01).
// Anthropic states "These addresses will not change without notice."
func TestStaticProvider_AnthropicIsAIAgent(t *testing.T) {
	p := asn.NewStaticProvider()
	// 160.79.104.1 is inside Anthropic's outbound range 160.79.104.0/21.
	ip := netip.MustParseAddr("160.79.104.1")
	result, err := p.Lookup(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Protected {
		t.Errorf("Anthropic IP should be protected, got %+v", result)
	}
	if result.Kind != asn.KindAIAgent {
		t.Errorf("expected KindAIAgent, got %q", result.Kind)
	}
	if result.Org != "anthropic" {
		t.Errorf("expected org=anthropic, got %q", result.Org)
	}
}

// TestStaticProvider_AnthropicIPv6IsAIAgent verifies Anthropic's IPv6 inbound range.
func TestStaticProvider_AnthropicIPv6IsAIAgent(t *testing.T) {
	p := asn.NewStaticProvider()
	// 2607:6bc0::1 is inside Anthropic's 2607:6bc0::/48.
	ip := netip.MustParseAddr("2607:6bc0::1")
	result, err := p.Lookup(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Protected {
		t.Errorf("Anthropic IPv6 should be protected, got %+v", result)
	}
	if result.Kind != asn.KindAIAgent {
		t.Errorf("expected KindAIAgent, got %q", result.Kind)
	}
}

// TestStaticProvider_AnthropicPhasedOutIPIsNeutral ensures that Anthropic's
// phased-out /32 addresses (explicitly retired per their docs) are NOT classified
// as protected — they must not be in the registry.
func TestStaticProvider_AnthropicPhasedOutIPIsNeutral(t *testing.T) {
	p := asn.NewStaticProvider()
	// 34.162.46.92 was in Anthropic's phased-out list; no longer active.
	ip := netip.MustParseAddr("34.162.46.92")
	result, err := p.Lookup(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Protected {
		t.Errorf("Anthropic phased-out IP must not be protected, got %+v", result)
	}
	if result.Kind != asn.KindUnknown {
		t.Errorf("phased-out Anthropic IP should be KindUnknown, got %q", result.Kind)
	}
}
