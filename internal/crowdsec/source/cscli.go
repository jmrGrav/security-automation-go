package source

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// CommandRunner abstracts subprocess execution so tests can inject a fake.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (stdout []byte, exitCode int, err error)
}

type realRunner struct{}

func (r *realRunner) Run(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return out, exitErr.ExitCode(), err
		}
		return nil, -1, err
	}
	return out, 0, nil
}

// CSCLISource fetches decisions by running `cscli decisions list -o json`.
//
// This matches Python's _fetch_all_cscli_decisions() exactly, including the
// workaround for CrowdSec bug #4470 (using --origin causes 25s+ SQLite timeout
// in v1.7.8): we fetch ALL decisions and filter client-side.
type CSCLISource struct {
	binPath string
	timeout time.Duration
	runner  CommandRunner
}

// NewCSCLISource creates a CSCLISource with the given cscli binary path and timeout.
// Defaults: binPath="cscli", timeout=15s (matching Python).
func NewCSCLISource(binPath string, timeout time.Duration) *CSCLISource {
	if binPath == "" {
		binPath = "cscli"
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	return &CSCLISource{
		binPath: binPath,
		timeout: timeout,
		runner:  &realRunner{},
	}
}

// WithRunner replaces the command runner — used in tests to inject a fake.
func (s *CSCLISource) WithRunner(r CommandRunner) *CSCLISource {
	s.runner = r
	return s
}

// ListAlerts runs `cscli decisions list -o json` and parses the result.
//
// Behavior mirrors Python exactly:
//   - empty stdout → (nil, nil)  ← no decisions
//   - "null" JSON  → (nil, nil)  ← CrowdSec reports null when empty
//   - non-list JSON → (nil, err)
//   - non-zero exit → (nil, err)
//   - timeout → (nil, err)
func (s *CSCLISource) ListAlerts(ctx context.Context) ([]RawAlert, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	out, code, err := s.runner.Run(opCtx, s.binPath, "decisions", "list", "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("cscli decisions list (exit=%d): %w", code, err)
	}

	trimmed := bytes.TrimSpace(out)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, nil
	}

	var alerts []RawAlert
	if err := json.Unmarshal(trimmed, &alerts); err != nil {
		return nil, fmt.Errorf("cscli decisions list: invalid JSON: %w", err)
	}

	return alerts, nil
}
