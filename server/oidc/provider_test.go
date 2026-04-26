package oidc

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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

func TestProtectAccessTokenClaimsRestoresProtectedFields(t *testing.T) {
	now := time.Unix(1710000000, 0)
	claims := AccessTokenClaims{
		Scope:          "openid profile",
		ClientID:       "demo-spa",
		TokenType:      "access_token",
		TokenVersion:   1,
		GrantType:      grantTypeClientCredentials,
		SubjectType:    accessTokenSubjectTypeServiceAccount,
		ServiceAccount: true,
		OrgID:          "org_acme",
		OrgSlug:        "acme",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Subject:   "usr_test",
			Audience:  jwt.ClaimStrings{"demo-spa"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
			ID:        "jwt-id",
		},
	}
	claimMap := map[string]any{
		"iss":             "evil",
		"sub":             "evil",
		"aud":             []string{"evil"},
		"scope":           "evil",
		"client_id":       "evil",
		"token_type":      "evil",
		"token_version":   99,
		"grant_type":      "evil",
		"subject_type":    "evil",
		"service_account": false,
		"iat":             int64(1),
		"exp":             int64(2),
		"nbf":             int64(3),
		"jti":             "evil",
		"org_id":          "evil",
		"org_slug":        "evil",
		"custom":          "keep",
	}

	protectAccessTokenClaims(claimMap, claims)

	expected := map[string]any{
		"iss":             "https://auth.example.com",
		"sub":             "usr_test",
		"aud":             []string{"demo-spa"},
		"scope":           "openid profile",
		"client_id":       "demo-spa",
		"token_type":      "access_token",
		"token_version":   1,
		"grant_type":      grantTypeClientCredentials,
		"subject_type":    accessTokenSubjectTypeServiceAccount,
		"service_account": true,
		"iat":             now.Unix(),
		"exp":             now.Add(time.Hour).Unix(),
		"nbf":             now.Add(-time.Minute).Unix(),
		"jti":             "jwt-id",
		"org_id":          "org_acme",
		"org_slug":        "acme",
		"custom":          "keep",
	}
	if !reflect.DeepEqual(claimMap, expected) {
		t.Fatalf("protected claims were not restored:\nexpected %#v\nactual   %#v", expected, claimMap)
	}
}

func TestProtectAccessTokenClaimsRemovesUnsetOptionalProtectedFields(t *testing.T) {
	claims := AccessTokenClaims{
		Scope:        "openid",
		ClientID:     "demo-spa",
		TokenType:    "access_token",
		TokenVersion: 1,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "https://auth.example.com",
			Subject:  "usr_test",
			Audience: jwt.ClaimStrings{"demo-spa"},
		},
	}
	claimMap := map[string]any{
		"nbf":             int64(3),
		"jti":             "evil",
		"grant_type":      "evil",
		"subject_type":    "evil",
		"service_account": true,
		"org_id":          "evil",
		"org_slug":        "evil",
	}

	protectAccessTokenClaims(claimMap, claims)

	for _, key := range []string{"iat", "exp", "nbf", "jti", "grant_type", "subject_type", "service_account", "org_id", "org_slug"} {
		if _, ok := claimMap[key]; ok {
			t.Fatalf("expected %s to be removed from unset optional protected claims: %#v", key, claimMap)
		}
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
