/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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

type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type accessTokenClaims struct {
	Scope     string `json:"scope"`
	ClientID  string `json:"client_id"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

type resourceServer struct {
	cfg       appConfig
	discovery discoveryDocument
	verifier  *oidc.IDTokenVerifier
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
	discovery, err := fetchDiscovery(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}

	return &resourceServer{
		cfg:       cfg,
		discovery: discovery,
		verifier: provider.Verifier(&oidc.Config{
			ClientID: cfg.ExpectedAudience,
		}),
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
		"discovery": s.discovery,
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
	claimsValue, _ := c.Get("access_token_claims")
	claims, _ := claimsValue.(*accessTokenClaims)

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
	return func(c *gin.Context) {
		raw := bearerToken(c.GetHeader("Authorization"))
		if raw == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			c.Abort()
			return
		}

		token, err := s.verifier.Verify(c.Request.Context(), raw)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid access token", "details": err.Error()})
			c.Abort()
			return
		}

		var claims accessTokenClaims
		if err := token.Claims(&claims); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to decode token claims", "details": err.Error()})
			c.Abort()
			return
		}

		if claims.TokenType != "access_token" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "token_type must be access_token"})
			c.Abort()
			return
		}
		if s.cfg.RequiredScope != "" && !hasScope(claims.Scope, s.cfg.RequiredScope) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":          "missing required scope",
				"required_scope": s.cfg.RequiredScope,
				"token_scope":    strings.Fields(claims.Scope),
			})
			c.Abort()
			return
		}

		c.Set("access_token_claims", &claims)
		c.Next()
	}
}

func fetchDiscovery(ctx context.Context, issuer string) (discoveryDocument, error) {
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return discoveryDocument{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return discoveryDocument{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return discoveryDocument{}, fmt.Errorf("discovery failed: %s", resp.Status)
	}

	var document discoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&document); err != nil {
		return discoveryDocument{}, err
	}
	return document, nil
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

func hasScope(scopeString string, target string) bool {
	for _, scope := range strings.Fields(scopeString) {
		if scope == target {
			return true
		}
	}
	return false
}

func bearerToken(header string) string {
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
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
