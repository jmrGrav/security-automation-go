package asn

// RegistryStatus describes the load state of a registry entry's CIDRs.
type RegistryStatus string

const (
	// RegistryStatusLoaded means CIDRs are populated in the static provider.
	RegistryStatusLoaded RegistryStatus = "loaded"
	// RegistryStatusSourceUnavailable means no official IP range publication was found.
	RegistryStatusSourceUnavailable RegistryStatus = "source_unavailable"
	// RegistryStatusTooVolatile means a source exists but the ranges are too
	// numerous or change too frequently to embed statically; periodic refresh is needed.
	RegistryStatusTooVolatile RegistryStatus = "too_volatile"
)

// RegistryEntry documents one protected-network entry: who published the ranges,
// where to verify them, when they were last confirmed, and which CIDRs are loaded.
//
// CIDRs is empty when Status is not RegistryStatusLoaded; those entries exist only
// as documentation of a known organisation that may be loaded in a future refresh.
type RegistryEntry struct {
	// Organization is the canonical owner label returned in asn.Result.Org.
	Organization string
	// Kind is the classification used for scoring and no-hard-ban decisions.
	Kind Kind
	// CIDRs are the ranges loaded into the static provider.
	// Empty means this entry is documented but not yet loaded (see Status / Notes).
	CIDRs []string
	// SourceURL is the authoritative URL from which the ranges were obtained.
	// Never invent a URL; only set this when you have fetched the document this session.
	SourceURL string
	// LastVerified is the RFC 3339 date on which CIDRs were last confirmed against SourceURL.
	LastVerified string
	// Notes records maintenance caveats such as refresh cadence or size constraints.
	Notes string
}

// Status derives the load state of the entry from its fields.
func (e RegistryEntry) Status() RegistryStatus {
	if len(e.CIDRs) > 0 {
		return RegistryStatusLoaded
	}
	if e.SourceURL != "" {
		return RegistryStatusTooVolatile
	}
	return RegistryStatusSourceUnavailable
}

// DefaultRegistry returns all known protected-network entries.
// Only entries whose Status() == RegistryStatusLoaded are injected into the
// static provider at runtime. All entries are available for audit and UI display.
//
// Maintenance rule: every CIDR here must have been fetched from SourceURL this
// session before being committed. Never copy ranges from memory or third-party
// sources.
func DefaultRegistry() []RegistryEntry {
	return []RegistryEntry{
		// ── Cloudflare ─────────────────────────────────────────────────────────
		// Verified 2026-06-01 against https://www.cloudflare.com/ips-v4 and ips-v6.
		{
			Organization: "cloudflare",
			Kind:         KindProtected,
			CIDRs: []string{
				// IPv4 (https://www.cloudflare.com/ips-v4, verified 2026-06-01)
				"173.245.48.0/20",
				"103.21.244.0/22",
				"103.22.200.0/22",
				"103.31.4.0/22",
				"141.101.64.0/18",
				"108.162.192.0/18",
				"190.93.240.0/20",
				"188.114.96.0/20",
				"197.234.240.0/22",
				"198.41.128.0/17",
				"162.158.0.0/15",
				"104.16.0.0/13",
				"104.24.0.0/14",
				"172.64.0.0/13",
				"131.0.72.0/22",
				// IPv6 (https://www.cloudflare.com/ips-v6, verified 2026-06-01)
				"2400:cb00::/32",
				"2606:4700::/32",
				"2803:f800::/32",
				"2405:b500::/32",
				"2405:8100::/32",
				"2a06:98c0::/29",
				"2c0f:f248::/32",
			},
			SourceURL:    "https://www.cloudflare.com/ips-v4",
			LastVerified: "2026-06-01",
			Notes:        "IPv6 source: https://www.cloudflare.com/ips-v6",
		},

		// ── Google ─────────────────────────────────────────────────────────────
		// Source: https://developers.google.com/search/apis/ipranges/googlebot.json
		// NOTE: ranges below were present in the codebase before 2026-06-01 and have
		// not been re-fetched this session. Schedule a re-verification against the
		// official source before the next release.
		{
			Organization: "google",
			Kind:         KindSearchBot,
			CIDRs: []string{
				"66.249.64.0/19",
				"64.233.160.0/19",
				"72.14.192.0/18",
				"74.125.0.0/16",
				"209.85.128.0/17",
				"216.239.32.0/19",
				"2001:4860::/32",
			},
			SourceURL:    "https://developers.google.com/search/apis/ipranges/googlebot.json",
			LastVerified: "pre-2026-06-01",
			Notes:        "Ranges not re-fetched 2026-06-01; re-verify before next release.",
		},

		// ── Microsoft / Bing ───────────────────────────────────────────────────
		// Source: https://www.microsoft.com/en-us/download/details.aspx?id=56519
		// NOTE: ranges below were present in the codebase before 2026-06-01 and have
		// not been re-fetched this session. Microsoft publishes Azure IP ranges in a
		// weekly JSON file; schedule a re-verification.
		{
			Organization: "microsoft",
			Kind:         KindSearchBot,
			CIDRs: []string{
				"40.74.0.0/15",
				"40.76.0.0/14",
				"40.80.0.0/12",
				"40.96.0.0/12",
				"40.112.0.0/13",
				"40.120.0.0/14",
				"40.124.0.0/16",
				"65.52.0.0/14",
				"13.64.0.0/11",
				"20.33.0.0/16",
				"157.54.0.0/15",
				"2603:1000::/25",
			},
			SourceURL:    "https://www.microsoft.com/en-us/download/details.aspx?id=56519",
			LastVerified: "pre-2026-06-01",
			Notes:        "Azure IP Ranges JSON; re-verify weekly. Bing crawler ASN: AS8075.",
		},

		// ── BetterStack ────────────────────────────────────────────────────────
		// Source: https://betterstack.com/docs/uptime/ip-ranges/
		// NOTE: range below was present in the codebase before 2026-06-01 and has
		// not been re-fetched this session. Re-verify against BetterStack docs.
		{
			Organization: "betterstack",
			Kind:         KindMonitoring,
			CIDRs: []string{
				"103.167.32.0/22",
			},
			SourceURL:    "https://betterstack.com/docs/uptime/ip-ranges/",
			LastVerified: "pre-2026-06-01",
			Notes:        "Re-verify against BetterStack official documentation.",
		},

		// ── UptimeRobot / Pingdom ──────────────────────────────────────────────
		// NOTE: ranges below were present in the codebase before 2026-06-01 and have
		// not been re-fetched this session.
		{
			Organization: "uptime-monitoring",
			Kind:         KindMonitoring,
			CIDRs: []string{
				"216.144.248.0/24", // UptimeRobot
				"69.162.124.0/22",  // Pingdom
			},
			SourceURL:    "https://uptimerobot.com/blog/ip-addresses-for-uptime-robot-monitors/",
			LastVerified: "pre-2026-06-01",
			Notes:        "Covers UptimeRobot and Pingdom; re-verify each vendor separately.",
		},

		// ── OpenAI GPTBot ──────────────────────────────────────────────────────
		// Source: https://openai.com/gptbot.json (fetched 2026-06-01, created 2025-10-30)
		// Used for training generative AI foundation models.
		{
			Organization: "openai-gptbot",
			Kind:         KindAIAgent,
			CIDRs: []string{
				"132.196.86.0/24",
				"172.182.202.0/25",
				"172.182.204.0/24",
				"172.182.207.0/25",
				"172.182.214.0/24",
				"172.182.215.0/24",
				"20.125.66.80/28",
				"20.171.206.0/24",
				"20.171.207.0/24",
				"4.227.36.0/25",
				"52.230.152.0/24",
				"74.7.175.128/25",
				"74.7.227.0/25",
				"74.7.227.128/25",
				"74.7.228.0/25",
				"74.7.230.0/25",
				"74.7.241.0/25",
				"74.7.241.128/25",
				"74.7.242.0/25",
				"74.7.243.128/25",
				"74.7.244.0/25",
			},
			SourceURL:    "https://openai.com/gptbot.json",
			LastVerified: "2026-06-01",
			Notes:        "Source JSON created 2025-10-30. Re-verify periodically; list is relatively stable.",
		},

		// ── OpenAI OAI-SearchBot ───────────────────────────────────────────────
		// Source: https://openai.com/searchbot.json (fetched 2026-06-01, created 2026-01-02)
		// Powers ChatGPT search features.
		{
			Organization: "openai-searchbot",
			Kind:         KindAIAgent,
			CIDRs: []string{
				"104.210.140.128/28",
				"135.234.64.0/24",
				"172.182.193.224/28",
				"172.182.193.80/28",
				"172.182.194.144/28",
				"172.182.194.32/28",
				"172.182.195.48/28",
				"172.182.209.208/28",
				"172.182.211.192/28",
				"172.182.213.192/28",
				"172.182.224.0/28",
				"172.203.190.128/28",
				"20.14.99.96/28",
				"20.168.18.32/28",
				"20.169.6.224/28",
				"20.169.7.48/28",
				"20.169.77.0/25",
				"20.171.123.64/28",
				"20.171.53.224/28",
				"20.25.151.224/28",
				"20.42.10.176/28",
				"4.227.36.0/25",
				"40.67.175.0/25",
				"40.90.214.16/28",
				"51.8.102.0/24",
				"74.7.175.128/25",
				"74.7.228.0/25",
				"74.7.228.128/25",
				"74.7.229.0/25",
				"74.7.229.128/25",
				"74.7.230.0/25",
				"74.7.241.128/25",
				"74.7.242.128/25",
				"74.7.243.0/25",
				"74.7.244.0/25",
			},
			SourceURL:    "https://openai.com/searchbot.json",
			LastVerified: "2026-06-01",
			Notes:        "Source JSON created 2026-01-02. Re-verify periodically.",
		},

		// ── OpenAI ChatGPT-User ────────────────────────────────────────────────
		// Source: https://openai.com/chatgpt-user.json (fetched 2026-06-01, 237 /28 ranges)
		// Handles user-initiated browsing actions within ChatGPT.
		// NOT loaded: 237 Azure /28 blocks that change frequently; embedding them
		// statically would require weekly updates. Use an automated refresh job.
		{
			Organization: "openai-chatgpt-user",
			Kind:         KindAIAgent,
			CIDRs:        nil, // not loaded — see Notes
			SourceURL:    "https://openai.com/chatgpt-user.json",
			LastVerified: "2026-06-01",
			Notes: "237 Azure /28 ranges (as of 2026-05-21). Too volatile for static embedding; " +
				"requires automated refresh. Status: too_volatile.",
		},

		// ── GitHub Copilot ─────────────────────────────────────────────────────
		// Source: https://api.github.com/meta (copilot section, fetched 2026-06-01)
		{
			Organization: "github-copilot",
			Kind:         KindAIAgent,
			CIDRs: []string{
				// Shared GitHub infrastructure ranges
				"192.30.252.0/22",
				"185.199.108.0/22",
				"140.82.112.0/20",
				"143.55.64.0/20",
				"2a0a:a440::/29",
				"2606:50c0::/32",
				// Copilot-specific Azure single-host entries
				"20.85.130.105/32",
				"4.237.22.41/32",
				"4.228.31.153/32",
				"4.249.131.160/32",
				"20.199.39.224/32",
				"52.175.140.176/32",
				"52.140.63.241/32",
				"4.225.11.192/32",
				"20.250.119.64/32",
				"138.91.182.224/32",
				"13.107.5.93/32",
			},
			SourceURL:    "https://api.github.com/meta",
			LastVerified: "2026-06-01",
			Notes:        "copilot section of GitHub Meta API. Single-host /32 entries may change; re-verify weekly.",
		},

		// ── Anthropic ──────────────────────────────────────────────────────────
		// Source: https://platform.claude.com/docs/en/api/ip-addresses
		// (fetched 2026-06-01; Anthropic states "These addresses will not change without notice")
		//
		// Inbound to Anthropic (where Anthropic services receive connections):
		//   IPv4: 160.79.104.0/23   IPv6: 2607:6bc0::/48
		// Outbound from Anthropic (origin IPs for MCP tool calls, web fetch, etc.):
		//   IPv4: 160.79.104.0/21
		//
		// 160.79.104.0/21 is the superset and covers both inbound and outbound.
		// The /23 is a subset of the /21; including both would double-match the
		// /23 range. We load the /21 (superset) plus the IPv6 /48.
		//
		// Phased-out addresses (34.162.x.x/32) are explicitly "no longer in use"
		// and must NOT be added here.
		{
			Organization: "anthropic",
			Kind:         KindAIAgent,
			CIDRs: []string{
				"160.79.104.0/21", // outbound superset (covers inbound /23 too)
				"2607:6bc0::/48",  // IPv6 inbound
			},
			SourceURL:    "https://platform.claude.com/docs/en/api/ip-addresses",
			LastVerified: "2026-06-01",
			Notes: "Anthropic states these addresses will not change without notice. " +
				"Phased-out /32 ranges (34.162.x.x) are no longer active and excluded. " +
				"AWS-platform inbound resolves to AWS IP ranges (not listed here).",
		},
	}
}
