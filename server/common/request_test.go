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

func TestRequestOrigin(t *testing.T) {
	t.Run("configured base url wins", func(t *testing.T) {
		req := &http.Request{Header: make(http.Header), Host: "internal.example"}
		got := RequestOrigin(req, "https://auth.example.com/path")
		if got != "https://auth.example.com" {
			t.Fatalf("expected configured origin, got %q", got)
		}
	})

	t.Run("forwarded host and https are respected", func(t *testing.T) {
		req := &http.Request{Header: make(http.Header), Host: "internal.example"}
		req.Header.Set("X-Forwarded-Host", "auth.example.com")
		req.Header.Set("X-Forwarded-Proto", "https")
		got := RequestOrigin(req, "")
		if got != "https://auth.example.com" {
			t.Fatalf("expected forwarded origin, got %q", got)
		}
	})

	t.Run("falls back to request host", func(t *testing.T) {
		req := &http.Request{Header: make(http.Header), Host: "localhost:5180"}
		got := RequestOrigin(req, "")
		if got != "http://localhost:5180" {
			t.Fatalf("expected request host origin, got %q", got)
		}
	})
}
