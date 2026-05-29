package source_test

import (
	"context"
	"testing"

	"github.com/jm/security-automation-go/internal/crowdsec/source"
)

// fakeRunner implements CommandRunner for tests.
type fakeRunner struct {
	stdout   []byte
	exitCode int
	err      error
}

func (f *fakeRunner) Run(_ context.Context, _ string, _ ...string) ([]byte, int, error) {
	return f.stdout, f.exitCode, f.err
}

// Fixture JSON matching cscli decisions list -o json output format.
// Two alerts: one crowdsec IP ban, one cscli IP ban, one crowdsec range (excluded), one api origin (excluded).
const fixtureDecisionsJSON = `[
  {
    "decisions": [
      {"origin": "crowdsec", "type": "ban", "scope": "Ip",    "value": "1.2.3.4",    "scenario": "crowdsecurity/http-scan"},
      {"origin": "crowdsec", "type": "ban", "scope": "Ip",    "value": "5.6.7.8",    "scenario": "crowdsecurity/ssh-bf"},
      {"origin": "crowdsec", "type": "ban", "scope": "Range", "value": "9.0.0.0/24", "scenario": "crowdsecurity/http-probing"},
      {"origin": "api",      "type": "ban", "scope": "Ip",    "value": "10.0.0.1",   "scenario": "crowdsecurity/http-scan"}
    ]
  },
  {
    "decisions": [
      {"origin": "cscli", "type": "ban", "scope": "Ip", "value": "11.22.33.44", "scenario": "manual"},
      {"origin": "cscli", "type": "captcha", "scope": "Ip", "value": "55.66.77.88", "scenario": "manual"}
    ]
  }
]`

func TestCSCLISource_ListAlerts_filters(t *testing.T) {
	src := source.NewCSCLISource("cscli", 0).
		WithRunner(&fakeRunner{stdout: []byte(fixtureDecisionsJSON)})

	alerts, err := src.ListAlerts(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 2 {
		t.Fatalf("want 2 alerts, got %d", len(alerts))
	}
}

func TestFilterActiveBanIPs_parity(t *testing.T) {
	src := source.NewCSCLISource("cscli", 0).
		WithRunner(&fakeRunner{stdout: []byte(fixtureDecisionsJSON)})

	alerts, _ := src.ListAlerts(context.Background())
	ips := source.FilterActiveBanIPs(alerts)

	// Expected: crowdsec+cscli, ban, scope Ip only → 1.2.3.4, 5.6.7.8, 11.22.33.44
	// Excluded: Range scope (9.0.0.0/24), non-local origin api (10.0.0.1), captcha type (55.66.77.88)
	want := map[string]bool{
		"1.2.3.4":     true,
		"5.6.7.8":     true,
		"11.22.33.44": true,
	}
	if len(ips) != len(want) {
		t.Fatalf("want %d IPs, got %d: %v", len(want), len(ips), ips)
	}
	for _, ip := range ips {
		if !want[ip] {
			t.Errorf("unexpected IP in result: %s", ip)
		}
	}
}

func TestCSCLISource_EmptyStdout(t *testing.T) {
	src := source.NewCSCLISource("cscli", 0).
		WithRunner(&fakeRunner{stdout: []byte("")})

	alerts, err := src.ListAlerts(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on empty output: %v", err)
	}
	if alerts != nil {
		t.Errorf("want nil alerts on empty output, got %v", alerts)
	}
}

func TestCSCLISource_NullJSON(t *testing.T) {
	src := source.NewCSCLISource("cscli", 0).
		WithRunner(&fakeRunner{stdout: []byte("null")})

	alerts, err := src.ListAlerts(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on null JSON: %v", err)
	}
	if alerts != nil {
		t.Errorf("want nil alerts on null JSON, got %v", alerts)
	}
}

func TestCSCLISource_NonZeroExit(t *testing.T) {
	src := source.NewCSCLISource("cscli", 0).
		WithRunner(&fakeRunner{stdout: []byte("error msg"), exitCode: 1, err: &exitErr{code: 1}})

	_, err := src.ListAlerts(context.Background())
	if err == nil {
		t.Fatal("want error on non-zero exit, got nil")
	}
}

func TestCSCLISource_InvalidJSON(t *testing.T) {
	src := source.NewCSCLISource("cscli", 0).
		WithRunner(&fakeRunner{stdout: []byte(`{"not": "a list"}`)})

	_, err := src.ListAlerts(context.Background())
	if err == nil {
		t.Fatal("want error on invalid JSON (not array), got nil")
	}
}

func TestFilterActiveBanIPs_Deduplication(t *testing.T) {
	alerts := []source.RawAlert{
		{Decisions: []source.RawDecision{
			{Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: "1.2.3.4"},
			{Origin: "cscli", Type: "ban", Scope: "Ip", Value: "1.2.3.4"},
		}},
	}
	ips := source.FilterActiveBanIPs(alerts)
	if len(ips) != 1 {
		t.Errorf("want 1 deduplicated IP, got %d: %v", len(ips), ips)
	}
}

func TestFilterActiveBanIPs_ScopeCaseInsensitive(t *testing.T) {
	alerts := []source.RawAlert{
		{Decisions: []source.RawDecision{
			{Origin: "crowdsec", Type: "ban", Scope: "IP", Value: "1.2.3.4"},
			{Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: "5.6.7.8"},
			{Origin: "crowdsec", Type: "ban", Scope: "ip", Value: "9.10.11.12"},
		}},
	}
	ips := source.FilterActiveBanIPs(alerts)
	if len(ips) != 3 {
		t.Errorf("want 3 IPs (case-insensitive scope), got %d: %v", len(ips), ips)
	}
}

func TestFixtureSource(t *testing.T) {
	fs, err := source.NewFixtureSourceFromJSON([]byte(fixtureDecisionsJSON))
	if err != nil {
		t.Fatalf("fixture parse error: %v", err)
	}
	alerts, err := fs.ListAlerts(context.Background())
	if err != nil {
		t.Fatalf("fixture ListAlerts error: %v", err)
	}
	ips := source.FilterActiveBanIPs(alerts)
	if len(ips) != 3 {
		t.Errorf("fixture: want 3 IPs, got %d: %v", len(ips), ips)
	}
}

func TestEmptyFixtureSource(t *testing.T) {
	alerts, err := source.EmptyFixtureSource().ListAlerts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ips := source.FilterActiveBanIPs(alerts); len(ips) != 0 {
		t.Errorf("want 0 IPs from empty source, got %v", ips)
	}
}

// exitErr mimics exec.ExitError for tests.
type exitErr struct{ code int }

func (e *exitErr) Error() string { return "exit status 1" }
