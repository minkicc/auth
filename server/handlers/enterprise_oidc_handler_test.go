package handlers

import (
	"testing"

	"minki.cc/mkauth/server/config"
)

func TestSafeEnterpriseOIDCReturnURI(t *testing.T) {
	h := &AuthHandler{config: &config.Config{OIDC: config.OIDCConfig{Issuer: "https://auth.example.com"}}}

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "relative path", raw: "/oauth2/authorize?client_id=demo", want: "/oauth2/authorize?client_id=demo"},
		{name: "same origin absolute", raw: "https://auth.example.com/oauth2/authorize", want: "https://auth.example.com/oauth2/authorize"},
		{name: "cross origin absolute", raw: "https://evil.example.com/callback", want: ""},
		{name: "protocol relative", raw: "//evil.example.com/callback", want: ""},
		{name: "plain text", raw: "not a url", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.safeEnterpriseOIDCReturnURI(tc.raw); got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}
