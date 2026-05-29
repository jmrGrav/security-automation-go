package trust

import "testing"

func TestDefaultRegistryProtectsRFC1918(t *testing.T) {
	reg := DefaultRegistry()
	matches := reg.MatchIP("192.168.1.26")
	if len(matches) == 0 {
		t.Fatal("expected RFC1918 address to be protected")
	}
	if matches[0].Resource.AllowPropagation {
		t.Fatal("expected RFC1918 propagation to be forbidden")
	}
}

func TestDefaultRegistryProtectsCriticalServices(t *testing.T) {
	reg := DefaultRegistry()
	matches := reg.MatchService("sonarr")
	if len(matches) == 0 {
		t.Fatal("expected sonarr to be protected")
	}
	if matches[0].Resource.MinConfidence < 0.95 {
		t.Fatal("expected high confidence floor for critical service")
	}
}
