package oidc

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
	"minki.cc/mkauth/server/config"
)

func TestVerifyPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if !verifyPKCE(verifier, challenge, "S256") {
		t.Fatalf("expected pkce verification to succeed")
	}
	if verifyPKCE("wrong", challenge, "S256") {
		t.Fatalf("expected pkce verification to fail for wrong verifier")
	}
}

func TestMatchSecret(t *testing.T) {
	if !matchSecret("plain-secret", "plain-secret") {
		t.Fatalf("expected plain secret to match")
	}
	if matchSecret("plain-secret", "wrong") {
		t.Fatalf("expected plain secret mismatch")
	}

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte("s3cr3t"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash secret: %v", err)
	}
	if !matchSecret(string(hashedSecret), "s3cr3t") {
		t.Fatalf("expected bcrypt secret to match")
	}
	if matchSecret(string(hashedSecret), "wrong") {
		t.Fatalf("expected bcrypt secret mismatch")
	}
}

func TestValidPostLogoutRedirect(t *testing.T) {
	provider := &Provider{
		cfg: config.OIDCConfig{
			Clients: []config.OIDCClientConfig{
				{
					ClientID: "demo-spa",
					RedirectURIs: []string{
						"http://127.0.0.1:3000/",
					},
				},
			},
		},
	}

	if !provider.validPostLogoutRedirect("demo-spa", "") {
		t.Fatalf("empty redirect should be allowed")
	}
	if !provider.validPostLogoutRedirect("demo-spa", "http://127.0.0.1:3000/") {
		t.Fatalf("registered redirect should be allowed")
	}
	if provider.validPostLogoutRedirect("", "http://127.0.0.1:3000/") {
		t.Fatalf("client_id should be required when redirect is present")
	}
	if provider.validPostLogoutRedirect("demo-spa", "http://127.0.0.1:4000/") {
		t.Fatalf("unregistered redirect should be rejected")
	}
}
