package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
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

func TestBrowserSessionCookieSecure(t *testing.T) {
	t.Run("plain http stays insecure in local development", func(t *testing.T) {
		provider := &Provider{}
		req, err := http.NewRequest(http.MethodGet, "http://localhost:5180/oauth2/authorize", nil)
		if err != nil {
			t.Fatalf("failed to build request: %v", err)
		}
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request = req
		if provider.browserSessionCookieSecure(ctx) {
			t.Fatalf("expected local http request to use a non-secure cookie")
		}
	})

	t.Run("configured https issuer stays secure behind proxies", func(t *testing.T) {
		provider := &Provider{cfg: config.OIDCConfig{Issuer: "https://auth.example.com"}}
		req, err := http.NewRequest(http.MethodGet, "http://mkauth-server/oauth2/authorize", nil)
		if err != nil {
			t.Fatalf("failed to build request: %v", err)
		}
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request = req
		if !provider.browserSessionCookieSecure(ctx) {
			t.Fatalf("expected configured https issuer to keep cookie secure")
		}
	})
}
