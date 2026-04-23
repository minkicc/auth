package iam

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
)

func TestEnterpriseOIDCAuthenticateCreatesUserAndExternalIdentity(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:enterprise-oidc-create?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&auth.User{}); err != nil {
		t.Fatalf("failed to migrate user table: %v", err)
	}
	service := NewService(db)
	if err := service.AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}

	issuer, _ := newFakeEnterpriseIssuer(t, fakeEnterpriseUser{
		Subject:           "enterprise-user-1",
		Email:             "User@Example.COM",
		EmailVerified:     true,
		Name:              "Enterprise User",
		PreferredUsername: "enterprise.user",
	})
	manager, err := NewEnterpriseOIDCManager(config.IAMConfig{EnterpriseOIDC: []config.EnterpriseOIDCProviderConfig{{
		Slug:           "acme",
		Name:           "Acme",
		OrganizationID: "org_acme000000000000",
		Issuer:         issuer.URL,
		ClientID:       "acme-client",
		ClientSecret:   "acme-secret",
		RedirectURI:    "https://auth.example.com/api/enterprise/oidc/acme/callback",
	}}}, db, nil)
	if err != nil {
		t.Fatalf("failed to create enterprise oidc manager: %v", err)
	}

	user, err := manager.Authenticate(context.Background(), "acme", "valid-code", "expected-nonce")
	if err != nil {
		t.Fatalf("failed to authenticate enterprise oidc user: %v", err)
	}
	if !strings.HasPrefix(user.UserID, auth.UserIDPrefix) {
		t.Fatalf("expected internal user ID, got %q", user.UserID)
	}
	if user.Nickname != "Enterprise User" {
		t.Fatalf("expected nickname from enterprise profile, got %q", user.Nickname)
	}

	var identity ExternalIdentity
	if err := db.First(&identity, "provider_type = ? AND provider_id = ? AND subject = ?", IdentityProviderTypeOIDC, "acme", "enterprise-user-1").Error; err != nil {
		t.Fatalf("failed to load external identity: %v", err)
	}
	if identity.UserID != user.UserID {
		t.Fatalf("expected identity user %s, got %s", user.UserID, identity.UserID)
	}
	if identity.Email != "user@example.com" || !identity.EmailVerified {
		t.Fatalf("expected normalized verified email, got %q verified=%v", identity.Email, identity.EmailVerified)
	}

	var membership OrganizationMembership
	if err := db.First(&membership, "organization_id = ? AND user_id = ?", "org_acme000000000000", user.UserID).Error; err != nil {
		t.Fatalf("expected organization membership: %v", err)
	}
}

func TestEnterpriseOIDCAuthenticateReusesExternalIdentity(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:enterprise-oidc-reuse?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&auth.User{}); err != nil {
		t.Fatalf("failed to migrate user table: %v", err)
	}
	service := NewService(db)
	if err := service.AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}

	issuer, _ := newFakeEnterpriseIssuer(t, fakeEnterpriseUser{Subject: "same-subject", Email: "first@example.com", EmailVerified: true, Name: "First"})
	manager, err := NewEnterpriseOIDCManager(config.IAMConfig{EnterpriseOIDC: []config.EnterpriseOIDCProviderConfig{{
		Slug:         "acme",
		Name:         "Acme",
		Issuer:       issuer.URL,
		ClientID:     "acme-client",
		ClientSecret: "acme-secret",
		RedirectURI:  "https://auth.example.com/api/enterprise/oidc/acme/callback",
	}}}, db, nil)
	if err != nil {
		t.Fatalf("failed to create enterprise oidc manager: %v", err)
	}

	first, err := manager.Authenticate(context.Background(), "acme", "valid-code", "expected-nonce")
	if err != nil {
		t.Fatalf("failed to authenticate first enterprise oidc user: %v", err)
	}
	second, err := manager.Authenticate(context.Background(), "acme", "valid-code", "expected-nonce")
	if err != nil {
		t.Fatalf("failed to authenticate second enterprise oidc user: %v", err)
	}
	if second.UserID != first.UserID {
		t.Fatalf("expected same internal user ID, got first=%s second=%s", first.UserID, second.UserID)
	}

	var count int64
	db.Model(&auth.User{}).Count(&count)
	if count != 1 {
		t.Fatalf("expected one user, got %d", count)
	}
}

func TestEnterpriseOIDCRejectsNonceMismatch(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:enterprise-oidc-nonce?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&auth.User{}); err != nil {
		t.Fatalf("failed to migrate user table: %v", err)
	}
	if err := NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}

	issuer, _ := newFakeEnterpriseIssuer(t, fakeEnterpriseUser{Subject: "nonce-user", Email: "nonce@example.com", EmailVerified: true})
	manager, err := NewEnterpriseOIDCManager(config.IAMConfig{EnterpriseOIDC: []config.EnterpriseOIDCProviderConfig{{
		Slug:         "acme",
		Name:         "Acme",
		Issuer:       issuer.URL,
		ClientID:     "acme-client",
		ClientSecret: "acme-secret",
		RedirectURI:  "https://auth.example.com/api/enterprise/oidc/acme/callback",
	}}}, db, nil)
	if err != nil {
		t.Fatalf("failed to create enterprise oidc manager: %v", err)
	}

	_, err = manager.Authenticate(context.Background(), "acme", "valid-code", "wrong-nonce")
	if err == nil {
		t.Fatalf("expected nonce mismatch to fail")
	}
}

type fakeEnterpriseUser struct {
	Subject           string
	Email             string
	EmailVerified     bool
	Name              string
	PreferredUsername string
}

func newFakeEnterpriseIssuer(t *testing.T, user fakeEnterpriseUser) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	const keyID = "enterprise-test-key"
	const clientID = "acme-client"

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, w, map[string]any{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
				"jwks_uri":               server.URL + "/jwks",
			})
		case "/jwks":
			writeJSON(t, w, map[string]any{"keys": []map[string]any{{
				"kty": "RSA",
				"kid": keyID,
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			}}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse token request: %v", err)
			}
			if r.PostForm.Get("code") != "valid-code" {
				http.Error(w, "invalid code", http.StatusBadRequest)
				return
			}
			now := time.Now()
			claims := enterpriseOIDCClaims{
				Email:             user.Email,
				EmailVerified:     user.EmailVerified,
				Name:              user.Name,
				PreferredUsername: user.PreferredUsername,
				Nonce:             "expected-nonce",
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    server.URL,
					Subject:   user.Subject,
					Audience:  jwt.ClaimStrings{clientID},
					IssuedAt:  jwt.NewNumericDate(now),
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
				},
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = keyID
			rawToken, err := token.SignedString(key)
			if err != nil {
				t.Fatalf("failed to sign id token: %v", err)
			}
			writeJSON(t, w, map[string]any{
				"access_token": "fake-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     rawToken,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, key
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("failed to write json: %v", err)
	}
}
