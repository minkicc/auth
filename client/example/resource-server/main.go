/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"minki.cc/mkauth/client/oidcresource"
)

const (
	defaultIssuer           = "http://127.0.0.1:8080"
	defaultExpectedAudience = "demo-backend"
	defaultListenAddr       = ":8083"
)

type appConfig struct {
	Issuer           string
	ExpectedAudience string
	RequiredScope    string
	ListenAddr       string
}

type resourceServer struct {
	cfg       appConfig
	validator *oidcresource.Validator
}

func main() {
	cfg := loadConfig()
	server, err := newResourceServer(context.Background(), cfg)
	if err != nil {
		log.Fatalf("failed to initialize resource server: %v", err)
	}

	r := gin.Default()
	r.GET("/", server.index)
	r.GET("/public", server.public)
	r.GET("/protected", server.authRequired(), server.protected)

	log.Printf("MKAuth resource server example listening on %s", cfg.ListenAddr)
	log.Printf("Open %s or call %s/protected", displayBaseURL(cfg.ListenAddr), displayBaseURL(cfg.ListenAddr))
	if err := r.Run(cfg.ListenAddr); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func newResourceServer(ctx context.Context, cfg appConfig) (*resourceServer, error) {
	validator, err := oidcresource.New(ctx, oidcresource.Config{
		Issuer:         cfg.Issuer,
		Audience:       cfg.ExpectedAudience,
		RequiredScopes: splitOptionalScope(cfg.RequiredScope),
	})
	if err != nil {
		return nil, err
	}

	return &resourceServer{
		cfg:       cfg,
		validator: validator,
	}, nil
}

func (s *resourceServer) index(c *gin.Context) {
	baseURL := displayBaseURL(s.cfg.ListenAddr)
	c.JSON(http.StatusOK, gin.H{
		"message": "MKAuth OIDC resource server example",
		"what_it_checks": []string{
			"signature via discovery + jwks_uri",
			"issuer",
			"audience",
			"token_type=access_token",
			"optional required scope",
		},
		"config": gin.H{
			"issuer":            s.cfg.Issuer,
			"expected_audience": s.cfg.ExpectedAudience,
			"required_scope":    s.cfg.RequiredScope,
			"listen_addr":       s.cfg.ListenAddr,
		},
		"discovery": s.validator.Discovery(),
		"routes": gin.H{
			"public":    baseURL + "/public",
			"protected": baseURL + "/protected",
		},
		"how_to_try": []string{
			"1. Start quickstart: cd quickstart && docker compose up -d --build",
			"2. Start the backend callback example: cd client && go run ./example",
			"3. Log in at http://127.0.0.1:8082 and copy the access_token shown on the page",
			"4. Call the protected endpoint with that token",
		},
		"curl_example": fmt.Sprintf("curl -H 'Authorization: Bearer <access-token>' %s/protected", baseURL),
	})
}

func (s *resourceServer) public(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "public endpoint reached",
		"issuer":  s.cfg.Issuer,
	})
}

func (s *resourceServer) protected(c *gin.Context) {
	claims, _ := oidcresource.ClaimsFromContext(c)

	c.JSON(http.StatusOK, gin.H{
		"message": "access token accepted",
		"subject": claims.Subject,
		"aud":     claims.Audience,
		"scope":   strings.Fields(claims.Scope),
		"claims": gin.H{
			"client_id":  claims.ClientID,
			"token_type": claims.TokenType,
			"issuer":     claims.Issuer,
			"issued_at":  claims.IssuedAt,
			"expires_at": claims.ExpiresAt,
		},
	})
}

func (s *resourceServer) authRequired() gin.HandlerFunc {
	return s.validator.Middleware()
}

func loadConfig() appConfig {
	return appConfig{
		Issuer:           envOrDefault("MKAUTH_ISSUER", defaultIssuer),
		ExpectedAudience: envOrDefault("MKAUTH_EXPECTED_AUDIENCE", defaultExpectedAudience),
		RequiredScope:    strings.TrimSpace(os.Getenv("MKAUTH_REQUIRED_SCOPE")),
		ListenAddr:       envOrDefault("LISTEN_ADDR", defaultListenAddr),
	}
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func displayBaseURL(listenAddr string) string {
	if strings.HasPrefix(listenAddr, ":") {
		return "http://127.0.0.1" + listenAddr
	}
	if strings.HasPrefix(listenAddr, "http://") || strings.HasPrefix(listenAddr, "https://") {
		return listenAddr
	}
	return "http://" + listenAddr
}

func splitOptionalScope(scope string) []string {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return nil
	}
	return []string{scope}
}
