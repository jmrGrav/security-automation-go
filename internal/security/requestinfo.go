package security

import (
	"net"
	"net/http"
	"strings"
)

type RequestInfo struct {
	SourceIP string
}

func GetRequestInfo(r *http.Request, trustedProxies []string) *RequestInfo {
	remoteAddr := r.RemoteAddr
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	remoteIP := net.ParseIP(host)
	if remoteIP == nil {
		return &RequestInfo{SourceIP: host}
	}

	isTrusted := false
	for _, tp := range trustedProxies {
		if strings.Contains(tp, "/") {
			_, subnet, err := net.ParseCIDR(tp)
			if err == nil && subnet.Contains(remoteIP) {
				isTrusted = true
				break
			}
		} else {
			trustedIP := net.ParseIP(tp)
			if trustedIP != nil && trustedIP.Equal(remoteIP) {
				isTrusted = true
				break
			}
		}
	}

	if isTrusted {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			parts := strings.Split(xff, ",")
			if len(parts) == 1 {
				clientIPStr := strings.TrimSpace(parts[0])
				clientIP := net.ParseIP(clientIPStr)
				if clientIP != nil {
					return &RequestInfo{SourceIP: clientIPStr}
				}
			}
		}
	}

	return &RequestInfo{SourceIP: host}
}
