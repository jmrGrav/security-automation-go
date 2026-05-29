package source

import (
	"context"
	"encoding/json"
)

// FixtureSource is a deterministic DecisionSource for testing and replay.
// It returns a pre-loaded alert list without any subprocess or network calls.
type FixtureSource struct {
	alerts []RawAlert
}

// NewFixtureSource creates a FixtureSource from a pre-built alert slice.
func NewFixtureSource(alerts []RawAlert) *FixtureSource {
	return &FixtureSource{alerts: alerts}
}

// NewFixtureSourceFromJSON creates a FixtureSource by parsing cscli JSON output.
// The JSON must be the exact format produced by `cscli decisions list -o json`.
func NewFixtureSourceFromJSON(raw []byte) (*FixtureSource, error) {
	var alerts []RawAlert
	if err := json.Unmarshal(raw, &alerts); err != nil {
		return nil, err
	}
	return &FixtureSource{alerts: alerts}, nil
}

func (f *FixtureSource) ListAlerts(_ context.Context) ([]RawAlert, error) {
	if f == nil {
		return nil, nil
	}
	return f.alerts, nil
}

// EmptyFixtureSource returns a source that reports no active decisions (empty cscli output).
func EmptyFixtureSource() *FixtureSource {
	return &FixtureSource{}
}
