package asn

type Kind string

const (
	KindUnknown     Kind = "unknown"
	KindProtected   Kind = "protected"  // infrastructure protection (e.g. Cloudflare edge nodes)
	KindSearchBot   Kind = "searchbot"  // search engine crawlers (Google, Bing)
	KindAIAgent     Kind = "aiagent"    // AI agent crawlers and API infrastructure
	KindMonitoring  Kind = "monitoring" // uptime / synthetic monitoring services
	KindDatacenter  Kind = "datacenter"
	KindResidential Kind = "residential"
)

type Result struct {
	Provider  string
	Kind      Kind
	ASN       int
	Org       string
	Network   string
	Country   string
	Protected bool
}
