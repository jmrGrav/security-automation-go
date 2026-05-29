// Package baseline defines a replay-safe browser bootstrap baseline so normal
// homepage and asset loading does not get escalated as malicious behavior.
package baseline

import "strings"

type BenignAsset struct {
	Path               string   `json:"path"`
	Frequency          float64  `json:"frequency"`
	ExpectedMethods    []string `json:"expected_methods"`
	TypicalStatusCodes []int    `json:"typical_status_codes"`
}

type Matcher struct {
	assets   []BenignAsset
	prefixes []string
}

func NewArleoEUBaseline() *Matcher {
	return &Matcher{
		assets: []BenignAsset{
			{Path: "/", Frequency: 1.0, ExpectedMethods: []string{"GET", "HEAD"}, TypicalStatusCodes: []int{200, 304}},
			{Path: "/favicon.ico", Frequency: 1.0, ExpectedMethods: []string{"GET", "HEAD"}, TypicalStatusCodes: []int{200, 304, 404}},
			{Path: "/robots.txt", Frequency: 0.8, ExpectedMethods: []string{"GET", "HEAD"}, TypicalStatusCodes: []int{200, 304, 404}},
			{Path: "/sitemap.xml", Frequency: 0.5, ExpectedMethods: []string{"GET", "HEAD"}, TypicalStatusCodes: []int{200, 304, 404}},
			{Path: "/manifest.json", Frequency: 0.4, ExpectedMethods: []string{"GET", "HEAD"}, TypicalStatusCodes: []int{200, 304, 404}},
			{Path: "/apple-touch-icon.png", Frequency: 0.3, ExpectedMethods: []string{"GET", "HEAD"}, TypicalStatusCodes: []int{200, 304, 404}},
			{Path: "/browserconfig.xml", Frequency: 0.2, ExpectedMethods: []string{"GET", "HEAD"}, TypicalStatusCodes: []int{200, 304, 404}},
		},
		prefixes: []string{"/css/", "/js/", "/fonts/", "/images/", "/img/", "/assets/"},
	}
}

func (m *Matcher) Match(path string) (BenignAsset, bool) {
	normalized := strings.TrimSpace(strings.ToLower(path))
	for _, asset := range m.assets {
		if normalized == asset.Path {
			return asset, true
		}
	}
	for _, prefix := range m.prefixes {
		if strings.HasPrefix(normalized, prefix) {
			return BenignAsset{
				Path:               prefix + "*",
				Frequency:          0.6,
				ExpectedMethods:    []string{"GET", "HEAD"},
				TypicalStatusCodes: []int{200, 304, 404},
			}, true
		}
	}
	return BenignAsset{}, false
}

func (m *Matcher) All() []BenignAsset {
	out := make([]BenignAsset, len(m.assets))
	copy(out, m.assets)
	return out
}
