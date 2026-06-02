package crowdsec

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/crowdsec/models"
	"github.com/jm/security-automation-go/internal/crowdsec/source"
)

type recordingRunner struct {
	calls []runnerCall
	out   []byte
	err   error
}

type runnerCall struct {
	bin  string
	args []string
}

func (r *recordingRunner) run(_ context.Context, bin string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, runnerCall{bin: bin, args: append([]string(nil), args...)})
	return r.out, r.err
}

type fixedDecisionSource struct {
	alerts []source.RawAlert
	err    error
}

func (s fixedDecisionSource) ListAlerts(context.Context) ([]source.RawAlert, error) {
	return s.alerts, s.err
}

func newClientWithRunner(r *recordingRunner) *Client {
	return &Client{
		src:        fixedDecisionSource{},
		decLogPath: "/dev/null",
		lookback:   lookbackDefault,
		cscliBin:   "cscli-test",
		runner:     r,
	}
}

func TestClientSatisfiesCrowdSecWriteAndReadBoundaries(t *testing.T) {
	var _ DecisionWriter = (*Client)(nil)
	var _ DecisionRemover = (*Client)(nil)
	var _ AllowlistWriter = (*Client)(nil)
	var _ AllowlistReader = (*Client)(nil)
	var _ CrowdSecAdminWriter = (*Client)(nil)
}

func TestClientDecisionCommandsAreSingleWriterBoundary(t *testing.T) {
	runner := &recordingRunner{}
	client := newClientWithRunner(runner)

	if err := client.AddIPDecision(context.Background(), "1.2.3.4", "4h", "unit-test"); err != nil {
		t.Fatalf("AddIPDecision: %v", err)
	}
	if err := client.AddRangeDecision(context.Background(), "10.0.0.0/24", "24h", "range-test"); err != nil {
		t.Fatalf("AddRangeDecision: %v", err)
	}
	if err := client.DeleteIPDecision(context.Background(), "5.6.7.8"); err != nil {
		t.Fatalf("DeleteIPDecision: %v", err)
	}
	if err := client.DeleteRangeDecision(context.Background(), "192.0.2.0/24"); err != nil {
		t.Fatalf("DeleteRangeDecision: %v", err)
	}

	want := []runnerCall{
		{bin: "cscli-test", args: []string{"decisions", "add", "--ip", "1.2.3.4", "--duration", "4h", "--type", "ban", "--reason", "unit-test"}},
		{bin: "cscli-test", args: []string{"decisions", "add", "--range", "10.0.0.0/24", "--duration", "24h", "--type", "ban", "--reason", "range-test"}},
		{bin: "cscli-test", args: []string{"decisions", "delete", "--ip", "5.6.7.8"}},
		{bin: "cscli-test", args: []string{"decisions", "delete", "--range", "192.0.2.0/24"}},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("unexpected cscli calls:\n got %#v\nwant %#v", runner.calls, want)
	}
}

func TestClientAllowlistCommandsAreSingleWriterBoundary(t *testing.T) {
	runner := &recordingRunner{out: []byte(`{"items":[{"value":"1.2.3.4","comment":"operator"},{"value":"","comment":"ignored"}]}`)}
	client := newClientWithRunner(runner)

	entries, err := client.ListAllowlist(context.Background(), "lab")
	if err != nil {
		t.Fatalf("ListAllowlist: %v", err)
	}
	if len(entries) != 1 || entries[0] != (models.AllowlistEntry{Value: "1.2.3.4", Comment: "operator"}) {
		t.Fatalf("unexpected entries: %#v", entries)
	}
	if err := client.AddAllowlistEntry(context.Background(), "lab", models.AllowlistEntry{Value: "10.0.0.0/24", Comment: "lan"}); err != nil {
		t.Fatalf("AddAllowlistEntry: %v", err)
	}
	if err := client.RemoveAllowlistEntry(context.Background(), "lab", "10.0.0.0/24"); err != nil {
		t.Fatalf("RemoveAllowlistEntry: %v", err)
	}

	want := []runnerCall{
		{bin: "cscli-test", args: []string{"allowlists", "inspect", "lab", "-o", "json"}},
		{bin: "cscli-test", args: []string{"allowlists", "add", "lab", "10.0.0.0/24", "--comment", "lan"}},
		{bin: "cscli-test", args: []string{"allowlists", "remove", "lab", "10.0.0.0/24"}},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("unexpected cscli calls:\n got %#v\nwant %#v", runner.calls, want)
	}
}

func TestClientListActiveDecisionsPreservesRawDecisionScope(t *testing.T) {
	client := &Client{
		src: fixedDecisionSource{alerts: []source.RawAlert{{
			Decisions: []source.RawDecision{
				{Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: "1.2.3.4", ID: 10},
				{Origin: "cscli", Type: "ban", Scope: "Range", Value: "10.0.0.0/24", ID: 11},
			},
		}}},
		decLogPath: "/dev/null",
		lookback:   48 * time.Hour,
		cscliBin:   "cscli-test",
		runner:     &recordingRunner{},
	}

	decisions, err := client.ListActiveDecisions(context.Background())
	if err != nil {
		t.Fatalf("ListActiveDecisions: %v", err)
	}
	if len(decisions) != 2 {
		t.Fatalf("want 2 decisions, got %d", len(decisions))
	}
	if decisions[1].Scope != "Range" || decisions[1].Value != "10.0.0.0/24" {
		t.Fatalf("raw decision lost range data: %#v", decisions[1])
	}
}

func TestClientWriterValidationFailsClosedBeforeRunner(t *testing.T) {
	runner := &recordingRunner{}
	client := newClientWithRunner(runner)

	cases := []struct {
		name string
		call func() error
	}{
		{name: "bad ip add", call: func() error { return client.AddIPDecision(context.Background(), "bad-ip", "4h", "x") }},
		{name: "bad cidr add", call: func() error { return client.AddRangeDecision(context.Background(), "10.0.0.0/99", "4h", "x") }},
		{name: "bad ip delete", call: func() error { return client.DeleteIPDecision(context.Background(), "bad-ip") }},
		{name: "bad cidr delete", call: func() error { return client.DeleteRangeDecision(context.Background(), "10.0.0.0/99") }},
		{name: "bad allowlist value", call: func() error {
			return client.AddAllowlistEntry(context.Background(), "lab", models.AllowlistEntry{Value: "--flag"})
		}},
		{name: "bad allowlist remove", call: func() error { return client.RemoveAllowlistEntry(context.Background(), "lab", "--flag") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if len(runner.calls) != 0 {
		t.Fatalf("validation failure must not invoke cscli, got calls %#v", runner.calls)
	}
}

func TestCrowdSecWriteCommandsOnlyInClient(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))

	writeFragments := []string{
		`"decisions", "add"`,
		`"decisions", "delete"`,
		`"allowlists", "add"`,
		`"allowlists", "remove"`,
	}
	var offenders []string
	err := filepath.WalkDir(filepath.Join(repoRoot, "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(data)
		for _, fragment := range writeFragments {
			if strings.Contains(text, fragment) && filepath.ToSlash(path) != filepath.ToSlash(filepath.Join(repoRoot, "internal", "crowdsec", "client.go")) {
				offenders = append(offenders, path+" contains "+fragment)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	if len(offenders) != 0 {
		t.Fatalf("CrowdSec write commands must stay in internal/crowdsec/client.go:\n%s", strings.Join(offenders, "\n"))
	}
}
