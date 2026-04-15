/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package oidcresource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const GinClaimsContextKey = "oidc_access_token_claims"

var (
	ErrIssuerRequired     = errors.New("oidcresource: issuer is required")
	ErrAudienceRequired   = errors.New("oidcresource: audience is required")
	ErrMissingBearerToken = errors.New("oidcresource: missing bearer token")
	ErrInvalidTokenType   = errors.New("oidcresource: token_type must be access_token")
)

type Config struct {
	Issuer         string
	Audience       string
	RequiredScopes []string
	HTTPClient     *http.Client
}

type DiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type AccessTokenClaims struct {
	Scope     string `json:"scope"`
	ClientID  string `json:"client_id"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

type ScopeError struct {
	RequiredScope string
	TokenScopes   []string
}

func (e *ScopeError) Error() string {
	return fmt.Sprintf("oidcresource: missing required scope %q", e.RequiredScope)
}

type Validator struct {
	cfg       Config
	discovery DiscoveryDocument
	verifier  *oidc.IDTokenVerifier
}

func New(ctx context.Context, cfg Config) (*Validator, error) {
	cfg.Issuer = strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	cfg.Audience = strings.TrimSpace(cfg.Audience)
	cfg.RequiredScopes = normalizeScopes(cfg.RequiredScopes)

	if cfg.Issuer == "" {
		return nil, ErrIssuerRequired
	}
	if cfg.Audience == "" {
		return nil, ErrAudienceRequired
	}

	if cfg.HTTPClient != nil {
		ctx = oidc.ClientContext(ctx, cfg.HTTPClient)
	}

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}

	var discovery DiscoveryDocument
	if err := provider.Claims(&discovery); err != nil {
		return nil, err
	}
	if discovery.Issuer == "" {
		discovery.Issuer = cfg.Issuer
	}

	return &Validator{
		cfg:       cfg,
		discovery: discovery,
		verifier: provider.VerifierContext(ctx, &oidc.Config{
			ClientID: cfg.Audience,
		}),
	}, nil
}

func (v *Validator) Discovery() DiscoveryDocument {
	return v.discovery
}

func (v *Validator) Validate(ctx context.Context, rawAccessToken string) (*AccessTokenClaims, error) {
	rawAccessToken = strings.TrimSpace(rawAccessToken)
	if rawAccessToken == "" {
		return nil, ErrMissingBearerToken
	}

	token, err := v.verifier.Verify(ctx, rawAccessToken)
	if err != nil {
		return nil, err
	}

	var claims AccessTokenClaims
	if err := token.Claims(&claims); err != nil {
		return nil, err
	}
	if claims.TokenType != "access_token" {
		return nil, ErrInvalidTokenType
	}

	tokenScopes := strings.Fields(claims.Scope)
	for _, requiredScope := range v.cfg.RequiredScopes {
		if !hasScope(tokenScopes, requiredScope) {
			return nil, &ScopeError{
				RequiredScope: requiredScope,
				TokenScopes:   tokenScopes,
			}
		}
	}

	return &claims, nil
}

func (v *Validator) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		rawAccessToken := BearerToken(c.GetHeader("Authorization"))
		if rawAccessToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": ErrMissingBearerToken.Error()})
			c.Abort()
			return
		}

		claims, err := v.Validate(c.Request.Context(), rawAccessToken)
		if err != nil {
			status := http.StatusUnauthorized
			body := gin.H{"error": err.Error()}

			var scopeErr *ScopeError
			if errors.As(err, &scopeErr) {
				status = http.StatusForbidden
				body["required_scope"] = scopeErr.RequiredScope
				body["token_scope"] = scopeErr.TokenScopes
			}

			c.JSON(status, body)
			c.Abort()
			return
		}

		c.Set(GinClaimsContextKey, claims)
		c.Set("user_id", claims.Subject)
		c.Set("authenticated", true)
		c.Set("access_token", rawAccessToken)
		c.Next()
	}
}

func ClaimsFromContext(c *gin.Context) (*AccessTokenClaims, bool) {
	value, ok := c.Get(GinClaimsContextKey)
	if !ok {
		return nil, false
	}
	claims, ok := value.(*AccessTokenClaims)
	return claims, ok
}

func BearerToken(header string) string {
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}

func normalizeScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return nil
	}
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			result = append(result, scope)
		}
	}
	return result
}

func hasScope(tokenScopes []string, target string) bool {
	for _, scope := range tokenScopes {
		if scope == target {
			return true
		}
	}
	return false
}
