/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package oidcresource

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func TestValidateAccessToken(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)

	issuer, signer, cleanup := newTestIssuer(t)
	defer cleanup()

	validator, err := New(context.Background(), Config{
		Issuer:         issuer,
		Audience:       "demo-backend",
		RequiredScopes: []string{"profile"},
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	token := signTestAccessToken(t, signer, issuer, AccessTokenClaims{
		Scope:     "openid profile email",
		ClientID:  "demo-backend",
		TokenType: "access_token",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "user-001",
			Audience:  jwt.ClaimStrings{"demo-backend"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})

	claims, err := validator.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("expected token to validate: %v", err)
	}
	if claims.Subject != "user-001" {
		t.Fatalf("expected subject user-001, got %q", claims.Subject)
	}
	if claims.ClientID != "demo-backend" {
		t.Fatalf("expected client_id demo-backend, got %q", claims.ClientID)
	}
}

func TestValidateAccessTokenRejectsWrongTokenType(t *testing.T) {
	issuer, signer, cleanup := newTestIssuer(t)
	defer cleanup()

	validator, err := New(context.Background(), Config{
		Issuer:   issuer,
		Audience: "demo-backend",
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	token := signTestAccessToken(t, signer, issuer, AccessTokenClaims{
		Scope:     "openid profile",
		ClientID:  "demo-backend",
		TokenType: "id_token",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "user-001",
			Audience:  jwt.ClaimStrings{"demo-backend"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})

	_, err = validator.Validate(context.Background(), token)
	if err != ErrInvalidTokenType {
		t.Fatalf("expected ErrInvalidTokenType, got %v", err)
	}
}

func TestMiddlewareRejectsMissingScope(t *testing.T) {
	gin.SetMode(gin.TestMode)

	issuer, signer, cleanup := newTestIssuer(t)
	defer cleanup()

	validator, err := New(context.Background(), Config{
		Issuer:         issuer,
		Audience:       "demo-backend",
		RequiredScopes: []string{"read:users"},
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	router := gin.New()
	router.GET("/protected", validator.Middleware(), func(c *gin.Context) {
		claims, ok := ClaimsFromContext(c)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "claims missing"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"sub": claims.Subject})
	})

	token := signTestAccessToken(t, signer, issuer, AccessTokenClaims{
		Scope:     "openid profile",
		ClientID:  "demo-backend",
		TokenType: "access_token",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "user-001",
			Audience:  jwt.ClaimStrings{"demo-backend"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func newTestIssuer(t *testing.T) (string, *rsa.PrivateKey, func()) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                serverURL,
			"authorization_endpoint":                serverURL + "/oauth2/authorize",
			"token_endpoint":                        serverURL + "/oauth2/token",
			"userinfo_endpoint":                     serverURL + "/oauth2/userinfo",
			"jwks_uri":                              serverURL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"use": "sig",
					"alg": "RS256",
					"kid": "test-key",
					"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
				},
			},
		})
	})

	server := httptest.NewServer(mux)
	serverURL = server.URL
	return server.URL, privateKey, server.Close
}

func signTestAccessToken(t *testing.T, privateKey *rsa.PrivateKey, issuer string, claims AccessTokenClaims) string {
	t.Helper()

	if claims.Issuer == "" {
		claims.Issuer = issuer
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}
