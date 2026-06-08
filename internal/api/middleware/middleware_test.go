package middleware

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jm/security-automation-go/internal/api/auth"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestAuth_NoBearerHeader_Returns401(t *testing.T) {
	a := auth.NewAuthenticator(map[string]auth.Identity{
		"tok": {OperatorID: "op", Scopes: []auth.Scope{auth.ScopeRuntimeRead}},
	})
	h := Auth(a)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestAuth_InvalidToken_Returns401(t *testing.T) {
	a := auth.NewAuthenticator(map[string]auth.Identity{})
	h := Auth(a)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestAuth_ValidToken_SetsIdentityAndPassesThrough(t *testing.T) {
	a := auth.NewAuthenticator(map[string]auth.Identity{
		"valid-tok": {OperatorID: "op-1", Scopes: []auth.Scope{auth.ScopeRuntimeRead}},
	})

	var gotIdentity auth.Identity
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := auth.FromContext(r.Context())
		if !ok {
			http.Error(w, "no identity", http.StatusInternalServerError)
			return
		}
		gotIdentity = id
		w.WriteHeader(http.StatusOK)
	})
	h := Auth(a)(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-tok")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if gotIdentity.OperatorID != "op-1" {
		t.Errorf("expected op-1, got %s", gotIdentity.OperatorID)
	}
}

func TestAuth_NonBearerScheme_Returns401(t *testing.T) {
	a := auth.NewAuthenticator(map[string]auth.Identity{
		"tok": {OperatorID: "op"},
	})
	h := Auth(a)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: Basic auth should be rejected", rr.Code)
	}
}

func TestRecovery_PanickingHandler_Returns500(t *testing.T) {
	logger := slog.Default()
	h := Recovery(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 from recovered panic, got %d", rr.Code)
	}
}

func TestLogging_PassesThrough(t *testing.T) {
	logger := slog.Default()
	h := Logging(logger)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestStringsTrimPrefix(t *testing.T) {
	cases := []struct {
		s, prefix, want string
	}{
		{"Bearer tok", "Bearer ", "tok"},
		{"Basic data", "Bearer ", "Basic data"},
		{"", "Bearer ", ""},
		{"Bearer", "Bearer ", "Bearer"},
	}
	for _, c := range cases {
		if got := stringsTrimPrefix(c.s, c.prefix); got != c.want {
			t.Errorf("stringsTrimPrefix(%q, %q) = %q, want %q", c.s, c.prefix, got, c.want)
		}
	}
}
