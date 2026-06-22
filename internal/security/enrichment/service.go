package enrichment

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/security/enrichment/asn"
	dnsenrichment "github.com/jm/security-automation-go/internal/security/enrichment/dns"
)

type Service struct {
	cfg               Config
	dnsResolver       DNSResolver
	asnProvider       ASNProvider
	lookupProviders   []LookupProvider
	reporterProviders []ReporterProvider
	cache             *summaryCache
}

func NewService(cfg Config, dnsResolver DNSResolver, asnProvider ASNProvider, lookupProviders []LookupProvider, reporterProviders []ReporterProvider) *Service {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 800 * time.Millisecond
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 6 * time.Hour
	}
	return &Service{
		cfg:               cfg,
		dnsResolver:       dnsResolver,
		asnProvider:       asnProvider,
		lookupProviders:   append([]LookupProvider(nil), lookupProviders...),
		reporterProviders: append([]ReporterProvider(nil), reporterProviders...),
		cache:             newSummaryCache(cfg.CacheTTL),
	}
}

func (s *Service) Enrich(ctx context.Context, ip netip.Addr, opts LookupOptions) (EnrichmentSummary, error) {
	if !ip.IsValid() {
		return EnrichmentSummary{}, errors.New("ip is required")
	}
	if !s.cfg.Enabled {
		return EnrichmentSummary{IP: ip}, nil
	}

	cacheKey := s.cacheKey(ip, opts)
	if cached, ok := s.cache.Get(cacheKey); ok {
		cached.CacheHit = true
		return cached, nil
	}

	summary := EnrichmentSummary{IP: ip}
	summary.LocalSignalScore = opts.LocalSignalScore

	if s.cfg.DNSEnabled && s.dnsResolver != nil {
		dnsResult, _ := s.lookupDNS(ctx, ip)
		summary.DNS = dnsResult
	}

	if s.cfg.ASNEnabled && s.asnProvider != nil {
		asnResult, _ := s.lookupASN(ctx, ip)
		summary.ASN = asnResult
	}

	manualTriggered := opts.ManualForensics || opts.ReputationCheck
	for _, provider := range s.lookupProviders {
		if provider == nil {
			continue
		}
		if provider.Mode() == LookupModeManual && !manualTriggered {
			continue
		}
		if provider.Mode() == LookupModeAutomatic || manualTriggered {
			verdict, err := s.lookupProvider(ctx, provider, ip)
			if err != nil {
				continue
			}
			summary.Providers = append(summary.Providers, verdict)
		}
	}

	summaryCacheValue := summary
	summaryCacheValue.CacheHit = false
	summaryCacheValue.LocalSignalScore = opts.LocalSignalScore
	s.cache.Put(cacheKey, summaryCacheValue)
	return summaryCacheValue, nil
}

func (s *Service) Assess(summary EnrichmentSummary) Assessment {
	score := 0
	reasons := make([]string, 0, 8)
	noHardBan := false

	if delta, reason := scoreDNS(summary.DNS.Confirmed, summary.DNS.TrustedBot); delta != 0 {
		score += delta
		reasons = append(reasons, reason)
	}
	if delta, protected, reason := scoreASN(string(summary.ASN.Kind), summary.ASN.Protected); delta != 0 || protected || reason != "" {
		score += delta
		noHardBan = noHardBan || protected
		if reason != "" {
			reasons = append(reasons, reason)
		}
	}
	for _, verdict := range summary.Providers {
		if delta, reason := scoreProvider(verdict); delta != 0 {
			score += delta
			reasons = append(reasons, reason)
		}
	}
	return Assessment{
		Score:          score,
		NoHardBan:      noHardBan,
		HardBanAllowed: summary.IP.IsValid() && summary.LocalSignalScore > 0 && !noHardBan && score >= 50,
		Reasons:        uniqStrings(reasons),
	}
}

func (s *Service) Report(ctx context.Context, ip netip.Addr, opts LookupOptions, reason string) error {
	if !opts.SpamhausReport {
		return nil
	}
	if len(s.reporterProviders) == 0 {
		return nil
	}
	for _, provider := range s.reporterProviders {
		if provider == nil {
			continue
		}
		if err := provider.Report(ctx, ip, reason); err != nil {
			return fmt.Errorf("%s report failed: %w", provider.Name(), err)
		}
	}
	return nil
}

func (s *Service) lookupDNS(ctx context.Context, ip netip.Addr) (dnsenrichment.Result, string) {
	if !ip.IsValid() || s.dnsResolver == nil {
		return dnsenrichment.Result{}, ""
	}
	res := dnsenrichment.Result{}
	ctx, cancel := s.lookupContext(ctx)
	defer cancel()

	hosts, err := s.dnsResolver.LookupAddr(ctx, ip.String())
	if err != nil || len(hosts) == 0 {
		return res, ""
	}
	hostname := normalizeHostname(hosts[0])
	if hostname == "" {
		return res, ""
	}
	ips, err := s.dnsResolver.LookupHost(ctx, hostname)
	if err != nil {
		return dnsenrichment.Result{Hostname: hostname, Addresses: append([]string(nil), hosts...)}, ""
	}
	res.Hostname = hostname
	res.Addresses = append([]string(nil), ips...)
	for _, candidate := range ips {
		if parsed, err := netip.ParseAddr(candidate); err == nil && parsed == ip {
			res.Confirmed = true
			break
		}
	}
	if res.Confirmed && s.isTrustedHostname(hostname) {
		res.TrustedBot = true
	}
	return res, ""
}

func (s *Service) lookupASN(ctx context.Context, ip netip.Addr) (asn.Result, string) {
	if !ip.IsValid() || s.asnProvider == nil {
		return asn.Result{}, ""
	}
	ctx, cancel := s.lookupContext(ctx)
	defer cancel()
	result, err := s.asnProvider.Lookup(ctx, ip)
	if err != nil {
		return asn.Result{}, ""
	}
	return result, ""
}

func (s *Service) lookupProvider(ctx context.Context, provider LookupProvider, ip netip.Addr) (ProviderVerdict, error) {
	ctx, cancel := s.lookupContext(ctx)
	defer cancel()
	verdict, err := provider.Lookup(ctx, ip)
	if err != nil {
		return ProviderVerdict{}, err
	}
	if verdict.Provider == "" {
		verdict.Provider = provider.Name()
	}
	verdict.Mode = provider.Mode()
	if provider.Mode() == LookupModeManual {
		verdict.Manual = true
	}
	return verdict, nil
}

func (s *Service) lookupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.cfg.Timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, s.cfg.Timeout)
}

func (s *Service) cacheKey(ip netip.Addr, opts LookupOptions) string {
	return ip.String() + "|manual=" + fmt.Sprintf("%t", opts.ManualForensics) + "|repcheck=" + fmt.Sprintf("%t", opts.ReputationCheck)
}

func (s *Service) isTrustedHostname(hostname string) bool {
	if hostname == "" {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(hostname), ".")
	for _, suffix := range s.cfg.TrustedSuffixes {
		suffix = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(suffix, ".")))
		if suffix == "" {
			continue
		}
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func normalizeHostname(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

func uniqStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
