package poller

import "testing"

func TestCategorizeWAFRule(t *testing.T) {
	cases := map[string]string{
		"native_rule:941100": "xss",
		"native_rule:941110": "xss",
		"native_rule:942100": "sqli",
		"native_rule:932100": "rce",
		"native_rule:933100": "rce",
		"native_rule:930100": "traversal",
		"native_rule:913100": "scanner",
		"native_rule:901340": "waf",
		"":                   "waf",
	}
	for rule, want := range cases {
		if got := categorizeWAFRule(rule); got != want {
			t.Errorf("categorizeWAFRule(%q) = %q, want %q", rule, got, want)
		}
	}
}

// TestPrimaryWAFMatch_SkipsSetupRule reproduces the live alert 5016 fixture:
// a CRS body-inspection setup event with no matched payload, followed by the
// actual XSS rule match with non-empty "data". primaryWAFMatch must return
// the XSS rule, not the setup rule.
func TestPrimaryWAFMatch_SkipsSetupRule(t *testing.T) {
	alert := LAPIAlert{
		Events: []alertEvent{
			{Meta: []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			}{
				{Key: "rule_name", Value: "native_rule:901340"},
				{Key: "message", Value: "Enabling body inspection"},
				{Key: "uri", Value: "/?q=%3Cscript%3Ealert(1)%3C/script%3E%22"},
				{Key: "matched_zones", Value: "REQBODY_PROCESSOR"},
				{Key: "data", Value: ""},
				{Key: "target_fqdn", Value: "www.arleo.eu"},
			}},
			{Meta: []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			}{
				{Key: "rule_name", Value: "native_rule:941100"},
				{Key: "message", Value: "XSS Attack Detected via libinjection"},
				{Key: "uri", Value: "/?q=%3Cscript%3Ealert(1)%3C/script%3E%22"},
				{Key: "matched_zones", Value: "ARGS.q,ARGS.q"},
				{Key: "data", Value: `Matched Data: XSS data found within ARGS:q: <script>alert(1)</script>"`},
				{Key: "target_fqdn", Value: "www.arleo.eu"},
			}},
		},
	}

	match, ok := alert.primaryWAFMatch()
	if !ok {
		t.Fatal("expected a WAF match")
	}
	if match.RuleID != "native_rule:941100" {
		t.Errorf("RuleID = %q, want native_rule:941100 (the actual XSS rule, not the setup rule)", match.RuleID)
	}
	if match.Category != "xss" {
		t.Errorf("Category = %q, want xss", match.Category)
	}
	if match.Data == "" {
		t.Error("Data should not be empty")
	}
}

func TestPrimaryWAFMatch_FallsBackWhenNoDataAnywhere(t *testing.T) {
	alert := LAPIAlert{
		Events: []alertEvent{
			{Meta: []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			}{
				{Key: "rule_name", Value: "native_rule:901340"},
				{Key: "message", Value: "Enabling body inspection"},
			}},
		},
	}
	match, ok := alert.primaryWAFMatch()
	if !ok {
		t.Fatal("expected fallback match")
	}
	if match.RuleID != "native_rule:901340" {
		t.Errorf("RuleID = %q, want fallback native_rule:901340", match.RuleID)
	}
}

func TestPrimaryWAFMatch_NoEvents(t *testing.T) {
	alert := LAPIAlert{}
	if _, ok := alert.primaryWAFMatch(); ok {
		t.Error("expected no match for an alert with no events")
	}
}
