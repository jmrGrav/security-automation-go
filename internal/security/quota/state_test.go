package quota

import "testing"

func TestClassifyState(t *testing.T) {
	tests := []struct {
		name      string
		known     bool
		remaining float64
		want      State
	}{
		{name: "unknown", known: false, remaining: 0, want: Unknown},
		{name: "normal", known: true, remaining: 15.0001, want: Normal},
		{name: "warning", known: true, remaining: 15, want: Warning},
		{name: "throttled", known: true, remaining: 5, want: Throttled},
		{name: "exhausted", known: true, remaining: 0, want: Exhausted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.known, tt.remaining); got != tt.want {
				t.Fatalf("Classify(%v, %v) = %v, want %v", tt.known, tt.remaining, got, tt.want)
			}
		})
	}
}
