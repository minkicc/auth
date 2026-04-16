package common

import (
	"net/http"
	"strings"
)

func IsSecureRequest(r *http.Request, configuredBaseURL string) bool {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(configuredBaseURL)), "https://") {
		return true
	}
	if r == nil {
		return false
	}
	if proto := firstForwardedValue(r.Header.Get("X-Forwarded-Proto")); strings.EqualFold(proto, "https") {
		return true
	}
	if scheme := firstForwardedValue(r.Header.Get("X-Forwarded-Scheme")); strings.EqualFold(scheme, "https") {
		return true
	}
	if ssl := firstForwardedValue(r.Header.Get("X-Forwarded-Ssl")); strings.EqualFold(ssl, "on") {
		return true
	}
	return r.TLS != nil
}

func firstForwardedValue(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, ",")
	return strings.TrimSpace(parts[0])
}
