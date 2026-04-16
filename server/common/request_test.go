package common

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestIsSecureRequest(t *testing.T) {
	t.Run("configured https issuer wins", func(t *testing.T) {
		if !IsSecureRequest(&http.Request{}, "https://auth.example.com") {
			t.Fatalf("expected configured https issuer to mark request secure")
		}
	})

	t.Run("forwarded proto https", func(t *testing.T) {
		req := &http.Request{Header: make(http.Header)}
		req.Header.Set("X-Forwarded-Proto", "https")
		if !IsSecureRequest(req, "") {
			t.Fatalf("expected forwarded https proto to mark request secure")
		}
	})

	t.Run("tls request is secure", func(t *testing.T) {
		req := &http.Request{TLS: &tls.ConnectionState{}}
		if !IsSecureRequest(req, "") {
			t.Fatalf("expected tls request to mark request secure")
		}
	})

	t.Run("plain http is not secure", func(t *testing.T) {
		req := &http.Request{Header: make(http.Header)}
		if IsSecureRequest(req, "") {
			t.Fatalf("expected plain http request to stay non-secure")
		}
	})
}
