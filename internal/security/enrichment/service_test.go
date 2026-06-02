package enrichment

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/security/enrichment/asn"
)

type fakeDNSResolver struct {
	reverse []string
	forward []string
	err     error
	block   bool
	calls   int
}

func (f *fakeDNSResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	f.calls++
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.reverse, nil
}

func (f *fakeDNSResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.forward, nil
}

type fakeLookupProvider struct {
	name   string
	mode   LookupMode
	result ProviderVerdict
	err    error
	block  bool
	calls  int
}

func (f *fakeLookupProvider) Name() string     { return f.name }
func (f *fakeLookupProvider) Mode() LookupMode { return f.mode }
func (f *fakeLookupProvider) Lookup(ctx context.Context, ip netip.Addr) (ProviderVerdict, error) {
	f.calls++
	if f.block {
		<-ctx.Done()
		return ProviderVerdict{}, ctx.Err()
	}
	if f.err != nil {
		return ProviderVerdict{}, f.err
	}
	return f.result, nil
}

type fakeReporter struct {
	name  string
	calls int
}

func (f *fakeReporter) Name() string { return f.name }
func (f *fakeReporter) Report(ctx context.Context, ip netip.Addr, reason string) error {
	f.calls++
	return nil
}

type fakeASNProvider struct {
	result asn.Result
	err    error
	calls  int
}

func (f *fakeASNProvider) Name() string { return "asn" }
func (f *fakeASNProvider) Lookup(ctx context.Context, ip netip.Addr) (asn.Result, error) {
	f.calls++
	if f.err != nil {
		return asn.Result{}, f.err
	}
	return f.result, nil
}

func TestService_ForwardConfirmedTrustedBotScoresNegative(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.10")
	dnsResolver := &fakeDNSResolver{
		reverse: []string{"bot.example.test."},
		forward: []string{"203.0.113.10"},
	}
	asnProvider := &fakeASNProvider{result: asn.Result{Kind: asn.KindUnknown, Provider: "local"}}
	svc := NewService(Config{
		Enabled:         true,
		DNSEnabled:      true,
		ASNEnabled:      true,
		Timeout:         50 * time.Millisecond,
		CacheTTL:        time.Minute,
		TrustedSuffixes: []string{"example.test"},
	}, dnsResolver, asnProvider, nil, nil)

	summary, err := svc.Enrich(context.Background(), ip, LookupOptions{})
	if err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}
	assessment := svc.Assess(summary)
	if !summary.DNS.Confirmed || !summary.DNS.TrustedBot {
		t.Fatalf("expected confirmed trusted DNS, got %+v", summary.DNS)
	}
	if assessment.Score >= 0 {
		t.Fatalf("expected negative score for trusted bot, got %+v", assessment)
	}
}

func TestService_SpoofedRdnsIsNeutral(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.11")
	dnsResolver := &fakeDNSResolver{
		reverse: []string{"spoof.example.test."},
		forward: []string{"203.0.113.12"},
	}
	svc := NewService(Config{
		Enabled:    true,
		DNSEnabled: true,
		ASNEnabled: false,
		Timeout:    50 * time.Millisecond,
		CacheTTL:   time.Minute,
	}, dnsResolver, nil, nil, nil)

	summary, err := svc.Enrich(context.Background(), ip, LookupOptions{})
	if err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}
	assessment := svc.Assess(summary)
	if summary.DNS.Confirmed {
		t.Fatalf("expected spoofed rDNS to remain unconfirmed, got %+v", summary.DNS)
	}
	if assessment.Score != 0 {
		t.Fatalf("expected neutral score, got %+v", assessment)
	}
}

func TestService_DNSTimeoutIsNeutral(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.12")
	dnsResolver := &fakeDNSResolver{block: true}
	svc := NewService(Config{
		Enabled:    true,
		DNSEnabled: true,
		ASNEnabled: false,
		Timeout:    5 * time.Millisecond,
		CacheTTL:   time.Minute,
	}, dnsResolver, nil, nil, nil)

	summary, err := svc.Enrich(context.Background(), ip, LookupOptions{})
	if err != nil {
		t.Fatalf("Enrich should stay neutral on DNS timeout: %v", err)
	}
	if summary.DNS.Confirmed || summary.DNS.Hostname != "" {
		t.Fatalf("timeout should not produce DNS signal: %+v", summary.DNS)
	}
	if dnsResolver.calls != 1 {
		t.Fatalf("expected one DNS attempt, got %d", dnsResolver.calls)
	}
}

func TestService_ASNProtectedNetworkSetsNoHardBan(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.13")
	asnProvider := &fakeASNProvider{result: asn.Result{Provider: "local", Kind: asn.KindProtected, Protected: true, Network: "cloudflare"}}
	svc := NewService(Config{
		Enabled:    true,
		DNSEnabled: false,
		ASNEnabled: true,
		Timeout:    50 * time.Millisecond,
		CacheTTL:   time.Minute,
	}, nil, asnProvider, nil, nil)

	summary, err := svc.Enrich(context.Background(), ip, LookupOptions{LocalSignalScore: 2})
	if err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}
	assessment := svc.Assess(summary)
	if !assessment.NoHardBan {
		t.Fatalf("expected protected ASN to set no-hard-ban, got %+v", assessment)
	}
}

func TestService_ASNUnknownIsNeutral(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.14")
	asnProvider := &fakeASNProvider{result: asn.Result{Provider: "local", Kind: asn.KindUnknown}}
	svc := NewService(Config{
		Enabled:    true,
		DNSEnabled: false,
		ASNEnabled: true,
		Timeout:    50 * time.Millisecond,
		CacheTTL:   time.Minute,
	}, nil, asnProvider, nil, nil)

	summary, err := svc.Enrich(context.Background(), ip, LookupOptions{})
	if err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}
	assessment := svc.Assess(summary)
	if assessment.Score != 0 || assessment.NoHardBan {
		t.Fatalf("unknown ASN should be neutral: %+v", assessment)
	}
}

func TestService_CacheHitSkipsProviderSecondLookup(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.15")
	provider := &fakeLookupProvider{
		name:   "abuseipdb",
		mode:   LookupModeAutomatic,
		result: ProviderVerdict{Provider: "abuseipdb", Score: 72},
	}
	svc := NewService(Config{
		Enabled:    true,
		DNSEnabled: false,
		ASNEnabled: false,
		Timeout:    50 * time.Millisecond,
		CacheTTL:   time.Hour,
	}, nil, nil, []LookupProvider{provider}, nil)

	if _, err := svc.Enrich(context.Background(), ip, LookupOptions{}); err != nil {
		t.Fatalf("first lookup failed: %v", err)
	}
	if _, err := svc.Enrich(context.Background(), ip, LookupOptions{}); err != nil {
		t.Fatalf("second lookup failed: %v", err)
	}
	if provider.calls != 1 {
		t.Fatalf("expected cache hit to skip second provider call, got %d", provider.calls)
	}
}

func TestService_CacheExpiresAndRefreshesLookup(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.20")
	provider := &fakeLookupProvider{
		name:   "abuseipdb",
		mode:   LookupModeAutomatic,
		result: ProviderVerdict{Provider: "abuseipdb", Score: 72},
	}
	svc := NewService(Config{
		Enabled:    true,
		DNSEnabled: false,
		ASNEnabled: false,
		Timeout:    50 * time.Millisecond,
		CacheTTL:   10 * time.Millisecond,
	}, nil, nil, []LookupProvider{provider}, nil)

	if _, err := svc.Enrich(context.Background(), ip, LookupOptions{}); err != nil {
		t.Fatalf("first lookup failed: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := svc.Enrich(context.Background(), ip, LookupOptions{}); err != nil {
		t.Fatalf("second lookup failed: %v", err)
	}
	if provider.calls != 2 {
		t.Fatalf("expected cache expiry to refresh provider lookup, got %d calls", provider.calls)
	}
}

func TestService_VirusTotalIsManualOnly(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.16")
	vt := &fakeLookupProvider{
		name:   "virustotal",
		mode:   LookupModeManual,
		result: ProviderVerdict{Provider: "virustotal", Score: 100},
	}
	svc := NewService(Config{
		Enabled:    true,
		DNSEnabled: false,
		ASNEnabled: false,
		Timeout:    50 * time.Millisecond,
		CacheTTL:   time.Minute,
	}, nil, nil, []LookupProvider{vt}, nil)

	if _, err := svc.Enrich(context.Background(), ip, LookupOptions{ManualForensics: false}); err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if vt.calls != 0 {
		t.Fatalf("VirusTotal must not be called automatically, got %d", vt.calls)
	}

	if _, err := svc.Enrich(context.Background(), ip, LookupOptions{ManualForensics: true}); err != nil {
		t.Fatalf("manual lookup failed: %v", err)
	}
	if vt.calls != 1 {
		t.Fatalf("VirusTotal must be called in manual mode, got %d", vt.calls)
	}
}

func TestService_SpamhausReportNeedsExplicitToggle(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.17")
	reporter := &fakeReporter{name: "spamhaus"}
	svc := NewService(Config{
		Enabled:    true,
		DNSEnabled: false,
		ASNEnabled: false,
		Timeout:    50 * time.Millisecond,
		CacheTTL:   time.Minute,
	}, nil, nil, nil, []ReporterProvider{reporter})

	if err := svc.Report(context.Background(), ip, LookupOptions{SpamhausReport: false}, "test"); err != nil {
		t.Fatalf("report should be neutral without explicit toggle: %v", err)
	}
	if reporter.calls != 0 {
		t.Fatalf("spamhaus report must not run without toggle, got %d", reporter.calls)
	}
	if err := svc.Report(context.Background(), ip, LookupOptions{SpamhausReport: true}, "test"); err != nil {
		t.Fatalf("report with toggle failed: %v", err)
	}
	if reporter.calls != 1 {
		t.Fatalf("spamhaus report should run once with toggle, got %d", reporter.calls)
	}
}

func TestService_ExternalSignalAloneCannotHardBan(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.18")
	provider := &fakeLookupProvider{
		name:   "abuseipdb",
		mode:   LookupModeAutomatic,
		result: ProviderVerdict{Provider: "abuseipdb", Score: 100},
	}
	svc := NewService(Config{
		Enabled:    true,
		DNSEnabled: false,
		ASNEnabled: false,
		Timeout:    50 * time.Millisecond,
		CacheTTL:   time.Minute,
	}, nil, nil, []LookupProvider{provider}, nil)

	summary, err := svc.Enrich(context.Background(), ip, LookupOptions{LocalSignalScore: 0})
	if err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}
	assessment := svc.Assess(summary)
	if assessment.HardBanAllowed {
		t.Fatalf("external signal alone must not hard-ban: %+v", assessment)
	}
}

func TestService_ProviderTimeoutIsNeutral(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.19")
	provider := &fakeLookupProvider{
		name:  "abuseipdb",
		mode:  LookupModeAutomatic,
		block: true,
	}
	svc := NewService(Config{
		Enabled:    true,
		DNSEnabled: false,
		ASNEnabled: false,
		Timeout:    5 * time.Millisecond,
		CacheTTL:   time.Minute,
	}, nil, nil, []LookupProvider{provider}, nil)

	summary, err := svc.Enrich(context.Background(), ip, LookupOptions{})
	if err != nil {
		t.Fatalf("provider timeout should be neutral: %v", err)
	}
	assessment := svc.Assess(summary)
	if assessment.Score != 0 {
		t.Fatalf("timeout should not affect score: %+v", assessment)
	}
	if provider.calls != 1 {
		t.Fatalf("expected one provider attempt, got %d", provider.calls)
	}
}
