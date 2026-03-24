package auth

import (
	"net/http"
	"testing"
)

func TestNormalizeAPIAddr(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "bare host gets api suffix",
			input: "http://auth-service:8080",
			want:  "http://auth-service:8080/api",
		},
		{
			name:  "existing api path preserved",
			input: "http://auth-service:8080/api",
			want:  "http://auth-service:8080/api",
		},
		{
			name:  "legacy auth path remapped",
			input: "http://auth-service:8080/auth/token/validate",
			want:  "http://auth-service:8080/api",
		},
		{
			name:  "existing api endpoint path collapses to api base",
			input: "http://auth-service:8080/api/user",
			want:  "http://auth-service:8080/api",
		},
		{
			name:  "trailing slash removed",
			input: "http://auth-service:8080/",
			want:  "http://auth-service:8080/api",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeAPIAddr(tt.input)
			if got != tt.want {
				t.Fatalf("normalizeAPIAddr(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNewAuthClientUsesSecureDefaults(t *testing.T) {
	client := NewAuthClient("http://auth-service:8080", "", "")
	if client.HTTPClient == nil {
		t.Fatal("expected HTTP client to be initialized")
	}
	if client.HTTPClient.Transport != nil {
		t.Fatalf("expected secure default transport, got %#v", client.HTTPClient.Transport)
	}
}

func TestUseInsecureTLS(t *testing.T) {
	client := NewAuthClient("http://auth-service:8080", "", "")
	client.HTTPClient.Transport = http.DefaultTransport

	client.UseInsecureTLS()

	transport, ok := client.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.HTTPClient.Transport)
	}
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("expected insecure TLS to be enabled")
	}
}
