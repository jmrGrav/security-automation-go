package executor

import (
	"context"
	"net/http"
	"testing"

	"github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/abuseipdb/transport"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/security/quota"
)

type panicDoer struct{}

func (panicDoer) Do(req *http.Request) (*http.Response, error) {
	panic("report should have been suspended before HTTP call")
}

func TestExecutor_SuspendsWhenQuotaExhausted(t *testing.T) {
	quota.ResetDefaultRegistry()
	quota.DefaultRegistry().Record(quota.Observation{
		Provider:         "abuseipdb",
		Plan:             "test",
		QuotaSource:      "test",
		LimitKnown:       true,
		Limit:            100,
		RemainingKnown:   true,
		Remaining:        0,
		UsedKnown:        true,
		Used:             100,
		PercentKnown:     true,
		RemainingPercent: 0,
		State:            quota.Exhausted,
	})

	tp := transport.New(httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(panicDoer{})), "token")
	exec := New(tp)
	err := exec.Execute(context.Background(), []models.ExecutableReport{{IP: "1.2.3.4", Categories: "21", Comment: "test"}})
	if err == nil {
		t.Fatal("expected exhausted quota error")
	}
}
