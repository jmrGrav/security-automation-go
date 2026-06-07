package detect_test

import (
	"testing"

	"github.com/jm/security-automation-go/internal/detect"
)

func TestRunAll_ReturnsNineResults(t *testing.T) {
	cfg := detect.Config{}
	results := detect.RunAll(cfg)
	if len(results) != 9 {
		t.Fatalf("expected 9 results, got %d", len(results))
	}
}

func TestToJSON_Valid(t *testing.T) {
	results := []detect.Result{{Name: "test", Installed: true, Details: map[string]string{"key": "val"}}}
	data, err := detect.ToJSON(results)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty JSON")
	}
}

func TestRunAll_AllHaveNames(t *testing.T) {
	results := detect.RunAll(detect.Config{})
	for i, r := range results {
		if r.Name == "" {
			t.Errorf("result[%d] has empty name", i)
		}
	}
}
