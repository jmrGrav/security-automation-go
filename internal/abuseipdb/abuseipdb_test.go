package abuseipdb_test

import (
	"context"
	"testing"

	"github.com/jm/security-automation-go/internal/abuseipdb/executor"
	"github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/abuseipdb/transport"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/fixtures"
	"github.com/jm/security-automation-go/internal/httpclient"
)

func TestAbuseIPDB_Execute_Success(t *testing.T) {
	// 1. Setup fixtures
	f1 := fixtures.SanitizedFixture{
		SourceFixtureID: "report-ok",
		ResponseStatus:  200,
		ResponseBody:    []byte(`{"data": {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 100}}`),
	}
	f1.IntegrityHash = fixtures.IntegrityHashSanitized(f1)

	meta := fixtures.ReplayMetadata{
		Ordering: []string{"report-ok"},
	}

	engine := fixtures.NewReplayEngine([]fixtures.SanitizedFixture{f1}, meta)
	doer := fixtures.NewReplayDoer(engine)

	// 2. Setup Executor
	hc := httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(doer))
	trans := transport.New(hc, "fake-key")
	exec := executor.New(trans)

	// 3. Execute
	reports := []models.ExecutableReport{
		{IP: "1.2.3.4", Categories: "21", Comment: "test", OriginatingOpID: "op-1"},
	}
	err := exec.Execute(context.Background(), reports)
	if err != nil {
		t.Fatalf("Execution failed: %v", err)
	}
}

func TestAbuseIPDB_Execute_RateLimit(t *testing.T) {
	// 1. Setup fixtures (429 then success)
	fErr := fixtures.SanitizedFixture{
		SourceFixtureID: "report-429",
		ResponseStatus:  429,
		ResponseBody:    []byte(`{"errors": [{"detail": "Daily rate limit exceeded", "status": 429}]}`),
	}
	fErr.IntegrityHash = fixtures.IntegrityHashSanitized(fErr)

	meta := fixtures.ReplayMetadata{
		Ordering: []string{"report-429"},
	}

	engine := fixtures.NewReplayEngine([]fixtures.SanitizedFixture{fErr}, meta)
	doer := fixtures.NewReplayDoer(engine)

	// 2. Setup Executor
	hc := httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(doer))
	trans := transport.New(hc, "fake-key")
	exec := executor.New(trans)

	// 3. Execute
	reports := []models.ExecutableReport{
		{IP: "1.2.3.4", Categories: "21", Comment: "test", OriginatingOpID: "op-1"},
	}
	err := exec.Execute(context.Background(), reports)
	_ = err
}
