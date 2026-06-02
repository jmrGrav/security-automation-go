package security

import (
	"net/http"
	"testing"
)

func TestGetRequestInfo(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddr     string
		xff            string
		trustedProxies []string
		expectedIP     string
	}{
		{
			name:       "Simple direct",
			remoteAddr: "1.2.3.4:1234",
			expectedIP: "1.2.3.4",
		},
		{
			name:       "Invalid remote addr",
			remoteAddr: "invalid",
			expectedIP: "invalid",
		},
		{
			name:           "Trusted proxy IP matches",
			remoteAddr:     "127.0.0.1:1234",
			xff:            "5.6.7.8",
			trustedProxies: []string{"127.0.0.1"},
			expectedIP:     "5.6.7.8",
		},
		{
			name:           "Trusted proxy subnet matches",
			remoteAddr:     "192.168.1.10:1234",
			xff:            "5.6.7.8",
			trustedProxies: []string{"192.168.1.0/24"},
			expectedIP:     "5.6.7.8",
		},
		{
			name:           "Untrusted proxy",
			remoteAddr:     "1.1.1.1:1234",
			xff:            "5.6.7.8",
			trustedProxies: []string{"127.0.0.1"},
			expectedIP:     "1.1.1.1",
		},
		{
			name:           "Trusted proxy but malformed XFF",
			remoteAddr:     "127.0.0.1:1234",
			xff:            "invalid",
			trustedProxies: []string{"127.0.0.1"},
			expectedIP:     "127.0.0.1",
		},
		{
			name:           "Trusted proxy multiple XFF rejected",
			remoteAddr:     "127.0.0.1:1234",
			xff:            "9.9.9.9, 8.8.8.8",
			trustedProxies: []string{"127.0.0.1"},
			expectedIP:     "127.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			info := GetRequestInfo(req, tt.trustedProxies)
			if info.SourceIP != tt.expectedIP {
				t.Fatalf("expected %s, got %s", tt.expectedIP, info.SourceIP)
			}
		})
	}
}
