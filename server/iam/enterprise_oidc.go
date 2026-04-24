/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package iam

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
)

const defaultEnterpriseOIDCTimeout = 10 * time.Second

var defaultEnterpriseOIDCScopes = []string{"openid", "profile", "email"}

var ErrInvalidEnterpriseOIDCEmail = errors.New("enterprise oidc discovery email is invalid")
var ErrInvalidEnterpriseOIDCDomain = errors.New("enterprise oidc discovery domain is invalid")

type EnterpriseOIDCDiscoveryStatus string

const (
	EnterpriseOIDCDiscoveryMatched              EnterpriseOIDCDiscoveryStatus = "matched"
	EnterpriseOIDCDiscoveryDomainNotFound       EnterpriseOIDCDiscoveryStatus = "domain_not_found"
	EnterpriseOIDCDiscoveryOrganizationNotFound EnterpriseOIDCDiscoveryStatus = "organization_not_found"
	EnterpriseOIDCDiscoveryOrganizationInactive EnterpriseOIDCDiscoveryStatus = "organization_inactive"
	EnterpriseOIDCDiscoveryNoProvider           EnterpriseOIDCDiscoveryStatus = "no_provider"
)

type EnterpriseOIDCManager struct {
	db            *gorm.DB
	service       *Service
	avatarService *auth.AvatarService
	staticConfigs []config.EnterpriseOIDCProviderConfig
	mu            sync.RWMutex
	providers     map[string]*EnterpriseOIDCProvider
}

type EnterpriseOIDCProvider struct {
	cfg        config.EnterpriseOIDCProviderConfig
	issuer     string
	oauth2     oauth2.Config
	httpClient *http.Client

	mu        sync.RWMutex
	discovery *enterpriseOIDCDiscovery
	jwks      map[string]*rsa.PublicKey
	jwksUntil time.Time
}

type EnterpriseOIDCProviderSummary struct {
	Slug           string `json:"slug"`
	Name           string `json:"name"`
	OrganizationID string `json:"organization_id,omitempty"`
	Priority       int    `json:"priority"`
	IsDefault      bool   `json:"is_default"`
	AutoRedirect   bool   `json:"auto_redirect"`
}

type EnterpriseOIDCDiscoveryResult struct {
	Status                  EnterpriseOIDCDiscoveryStatus   `json:"status"`
	Email                   string                          `json:"email,omitempty"`
	Domain                  string                          `json:"domain,omitempty"`
	OrganizationID          string                          `json:"organization_id,omitempty"`
	OrganizationSlug        string                          `json:"organization_slug,omitempty"`
	OrganizationName        string                          `json:"organization_name,omitempty"`
	OrganizationDisplayName string                          `json:"organization_display_name,omitempty"`
	PreferredProviderSlug   string                          `json:"preferred_provider_slug,omitempty"`
	AutoRedirect            bool                            `json:"auto_redirect"`
	Providers               []EnterpriseOIDCProviderSummary `json:"providers"`
}

type EnterpriseOIDCUserInfo struct {
	Subject           string
	Email             string
	EmailVerified     bool
	Name              string
	PreferredUsername string
	Picture           string
	Issuer            string
}

type enterpriseOIDCDiscovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKsURI               string   `json:"jwks_uri"`
	SupportedAlgs         []string `json:"id_token_signing_alg_values_supported"`
}

type enterpriseOIDCClaims struct {
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Picture           string `json:"picture"`
	Nonce             string `json:"nonce"`
	jwt.RegisteredClaims
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	KeyID   string   `json:"kid"`
	KeyType string   `json:"kty"`
	Use     string   `json:"use"`
	Alg     string   `json:"alg"`
	N       string   `json:"n"`
	E       string   `json:"e"`
	X5C     []string `json:"x5c"`
}

func NewEnterpriseOIDCManager(cfg config.IAMConfig, db *gorm.DB, avatarService *auth.AvatarService) (*EnterpriseOIDCManager, error) {
	if db == nil {
		return nil, fmt.Errorf("enterprise oidc requires database")
	}

	manager := &EnterpriseOIDCManager{
		db:            db,
		service:       NewService(db),
		avatarService: avatarService,
		staticConfigs: append([]config.EnterpriseOIDCProviderConfig(nil), cfg.EnterpriseOIDC...),
		providers:     map[string]*EnterpriseOIDCProvider{},
	}
	if err := manager.Reload(); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *EnterpriseOIDCManager) Reload() error {
	if m == nil {
		return nil
	}
	providers, err := m.buildProviders()
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.providers = providers
	m.mu.Unlock()
	return nil
}

func (m *EnterpriseOIDCManager) HasStaticProviderSlug(slug string) bool {
	if m == nil {
		return false
	}
	slug = strings.TrimSpace(strings.ToLower(slug))
	for _, provider := range m.staticConfigs {
		if strings.TrimSpace(strings.ToLower(provider.Slug)) == slug {
			return true
		}
	}
	return false
}

func (m *EnterpriseOIDCManager) buildProviders() (map[string]*EnterpriseOIDCProvider, error) {
	providers := make(map[string]*EnterpriseOIDCProvider, len(m.staticConfigs))
	for _, providerCfg := range m.staticConfigs {
		provider, err := NewEnterpriseOIDCProvider(providerCfg)
		if err != nil {
			return nil, err
		}
		if _, exists := providers[provider.cfg.Slug]; exists {
			return nil, fmt.Errorf("duplicate enterprise oidc provider slug %q", provider.cfg.Slug)
		}
		providers[provider.cfg.Slug] = provider
	}

	var records []OrganizationIdentityProvider
	if err := m.db.Where("provider_type = ? AND enabled = ?", IdentityProviderTypeOIDC, true).
		Order("created_at ASC").
		Find(&records).Error; err != nil {
		return nil, err
	}
	for _, record := range records {
		providerCfg, err := enterpriseOIDCProviderConfigFromRecord(record)
		if err != nil {
			return nil, fmt.Errorf("load enterprise oidc provider %q: %w", record.Slug, err)
		}
		provider, err := NewEnterpriseOIDCProvider(providerCfg)
		if err != nil {
			return nil, err
		}
		if _, exists := providers[provider.cfg.Slug]; exists {
			return nil, fmt.Errorf("duplicate enterprise oidc provider slug %q", provider.cfg.Slug)
		}
		providers[provider.cfg.Slug] = provider
	}

	return providers, nil
}

func enterpriseOIDCProviderConfigFromRecord(record OrganizationIdentityProvider) (config.EnterpriseOIDCProviderConfig, error) {
	var providerCfg config.EnterpriseOIDCProviderConfig
	if strings.TrimSpace(record.ConfigJSON) != "" {
		if err := json.Unmarshal([]byte(record.ConfigJSON), &providerCfg); err != nil {
			return config.EnterpriseOIDCProviderConfig{}, fmt.Errorf("decode provider config: %w", err)
		}
	}
	providerCfg.Slug = record.Slug
	providerCfg.Name = record.Name
	providerCfg.OrganizationID = record.OrganizationID
	providerCfg.Priority = record.Priority
	providerCfg.IsDefault = record.IsDefault
	providerCfg.AutoRedirect = record.AutoRedirect
	return providerCfg, nil
}

func NewEnterpriseOIDCProvider(cfg config.EnterpriseOIDCProviderConfig) (*EnterpriseOIDCProvider, error) {
	cfg.Slug = strings.TrimSpace(cfg.Slug)
	cfg.Name = strings.TrimSpace(cfg.Name)
	cfg.OrganizationID = strings.TrimSpace(cfg.OrganizationID)
	cfg.Issuer = normalizeIssuer(cfg.Issuer)
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.ClientSecret = strings.TrimSpace(cfg.ClientSecret)
	cfg.RedirectURI = strings.TrimSpace(cfg.RedirectURI)

	if cfg.Slug == "" || cfg.Name == "" || cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURI == "" {
		return nil, fmt.Errorf("enterprise oidc provider %q is missing required configuration", cfg.Slug)
	}
	if _, err := url.ParseRequestURI(cfg.Issuer); err != nil {
		return nil, fmt.Errorf("enterprise oidc provider %q has invalid issuer: %w", cfg.Slug, err)
	}
	if _, err := url.ParseRequestURI(cfg.RedirectURI); err != nil {
		return nil, fmt.Errorf("enterprise oidc provider %q has invalid redirect_uri: %w", cfg.Slug, err)
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = append([]string(nil), defaultEnterpriseOIDCScopes...)
	}

	return &EnterpriseOIDCProvider{
		cfg:    cfg,
		issuer: cfg.Issuer,
		oauth2: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       cfg.Scopes,
		},
		httpClient: &http.Client{Timeout: defaultEnterpriseOIDCTimeout},
	}, nil
}

func (m *EnterpriseOIDCManager) Providers() []EnterpriseOIDCProviderSummary {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	providers := make([]EnterpriseOIDCProviderSummary, 0, len(m.providers))
	for _, provider := range m.providers {
		providers = append(providers, enterpriseOIDCProviderSummaryFromProvider(provider))
	}
	sortEnterpriseOIDCProviderSummaries(providers)
	return providers
}

func (m *EnterpriseOIDCManager) HasProviders() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.providers) > 0
}

func (m *EnterpriseOIDCManager) DiscoverByEmail(email string) (EnterpriseOIDCDiscoveryResult, error) {
	result := EnterpriseOIDCDiscoveryResult{
		Email:     strings.TrimSpace(strings.ToLower(email)),
		Providers: []EnterpriseOIDCProviderSummary{},
	}

	domain, err := normalizeEnterpriseOIDCEmailDomain(result.Email)
	if err != nil {
		return result, err
	}
	return m.discoverByDomain(domain, result)
}

func (m *EnterpriseOIDCManager) DiscoverByDomain(domain string) (EnterpriseOIDCDiscoveryResult, error) {
	result := EnterpriseOIDCDiscoveryResult{
		Providers: []EnterpriseOIDCProviderSummary{},
	}
	normalizedDomain, err := normalizeEnterpriseOIDCDomain(domain)
	if err != nil {
		return result, err
	}
	return m.discoverByDomain(normalizedDomain, result)
}

func (m *EnterpriseOIDCManager) discoverByDomain(domain string, result EnterpriseOIDCDiscoveryResult) (EnterpriseOIDCDiscoveryResult, error) {
	result.Domain = domain
	if m == nil || m.db == nil {
		result.Status = EnterpriseOIDCDiscoveryNoProvider
		return result, nil
	}

	var organizationDomain OrganizationDomain
	if err := m.db.First(&organizationDomain, "domain = ? AND verified = ?", domain, true).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			result.Status = EnterpriseOIDCDiscoveryDomainNotFound
			return result, nil
		}
		return result, err
	}

	var organization Organization
	if err := m.db.First(&organization, "organization_id = ?", organizationDomain.OrganizationID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			result.Status = EnterpriseOIDCDiscoveryOrganizationNotFound
			return result, nil
		}
		return result, err
	}
	result.OrganizationID = organization.OrganizationID
	result.OrganizationSlug = organization.Slug
	result.OrganizationName = organization.Name
	result.OrganizationDisplayName = organization.DisplayName

	if organization.Status != OrganizationStatusActive {
		result.Status = EnterpriseOIDCDiscoveryOrganizationInactive
		return result, nil
	}

	result.Providers = m.providersForOrganization(organization.OrganizationID)
	if len(result.Providers) == 0 {
		result.Status = EnterpriseOIDCDiscoveryNoProvider
		return result, nil
	}
	preferred, hasPreferred := preferredEnterpriseOIDCProvider(result.Providers)
	if hasPreferred {
		result.PreferredProviderSlug = preferred.Slug
		result.AutoRedirect = len(result.Providers) == 1 || preferred.AutoRedirect
	} else if len(result.Providers) == 1 {
		result.PreferredProviderSlug = result.Providers[0].Slug
		result.AutoRedirect = true
	}
	result.Status = EnterpriseOIDCDiscoveryMatched
	return result, nil
}

func (m *EnterpriseOIDCManager) AuthCodeURL(ctx context.Context, slug, state, nonce string) (string, error) {
	provider, ok := m.provider(slug)
	if !ok {
		return "", fmt.Errorf("enterprise oidc provider %q not found", slug)
	}
	return provider.AuthCodeURL(ctx, state, nonce)
}

func (m *EnterpriseOIDCManager) Authenticate(ctx context.Context, slug, code, nonce string) (*auth.User, error) {
	provider, ok := m.provider(slug)
	if !ok {
		return nil, fmt.Errorf("enterprise oidc provider %q not found", slug)
	}
	userInfo, err := provider.ExchangeAndVerify(ctx, code, nonce)
	if err != nil {
		return nil, err
	}
	return m.findOrCreateUser(provider, userInfo)
}

func (m *EnterpriseOIDCManager) provider(slug string) (*EnterpriseOIDCProvider, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	provider, ok := m.providers[strings.TrimSpace(slug)]
	return provider, ok
}

func (m *EnterpriseOIDCManager) providersForOrganization(organizationID string) []EnterpriseOIDCProviderSummary {
	if m == nil {
		return nil
	}
	organizationID = strings.TrimSpace(organizationID)
	if organizationID == "" {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	providers := make([]EnterpriseOIDCProviderSummary, 0, len(m.providers))
	for _, provider := range m.providers {
		if provider.cfg.OrganizationID != organizationID {
			continue
		}
		providers = append(providers, enterpriseOIDCProviderSummaryFromProvider(provider))
	}
	sortEnterpriseOIDCProviderSummaries(providers)
	return providers
}

func enterpriseOIDCProviderSummaryFromProvider(provider *EnterpriseOIDCProvider) EnterpriseOIDCProviderSummary {
	return EnterpriseOIDCProviderSummary{
		Slug:           provider.cfg.Slug,
		Name:           provider.cfg.Name,
		OrganizationID: provider.cfg.OrganizationID,
		Priority:       provider.cfg.Priority,
		IsDefault:      provider.cfg.IsDefault,
		AutoRedirect:   provider.cfg.AutoRedirect,
	}
}

func sortEnterpriseOIDCProviderSummaries(providers []EnterpriseOIDCProviderSummary) {
	sort.Slice(providers, func(i, j int) bool {
		left := providers[i]
		right := providers[j]
		if left.IsDefault != right.IsDefault {
			return left.IsDefault
		}
		if left.AutoRedirect != right.AutoRedirect {
			return left.AutoRedirect
		}
		if left.Priority != right.Priority {
			return left.Priority < right.Priority
		}
		leftName := strings.TrimSpace(strings.ToLower(left.Name))
		rightName := strings.TrimSpace(strings.ToLower(right.Name))
		if leftName != rightName {
			return leftName < rightName
		}
		return left.Slug < right.Slug
	})
}

func preferredEnterpriseOIDCProvider(providers []EnterpriseOIDCProviderSummary) (EnterpriseOIDCProviderSummary, bool) {
	if len(providers) == 0 {
		return EnterpriseOIDCProviderSummary{}, false
	}
	if len(providers) == 1 {
		return providers[0], true
	}

	first := providers[0]
	second := providers[1]
	switch {
	case first.AutoRedirect:
		return first, true
	case first.IsDefault:
		return first, true
	case first.Priority != second.Priority:
		return first, true
	default:
		return EnterpriseOIDCProviderSummary{}, false
	}
}

func (p *EnterpriseOIDCProvider) AuthCodeURL(ctx context.Context, state, nonce string) (string, error) {
	discovery, err := p.ensureDiscovery(ctx)
	if err != nil {
		return "", err
	}
	cfg := p.oauth2
	cfg.Endpoint = oauth2.Endpoint{
		AuthURL:  discovery.AuthorizationEndpoint,
		TokenURL: discovery.TokenEndpoint,
	}
	return cfg.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.SetAuthURLParam("nonce", nonce)), nil
}

func (p *EnterpriseOIDCProvider) ExchangeAndVerify(ctx context.Context, code, expectedNonce string) (*EnterpriseOIDCUserInfo, error) {
	if strings.TrimSpace(code) == "" {
		return nil, fmt.Errorf("missing enterprise oidc code")
	}
	discovery, err := p.ensureDiscovery(ctx)
	if err != nil {
		return nil, err
	}

	cfg := p.oauth2
	cfg.Endpoint = oauth2.Endpoint{
		AuthURL:  discovery.AuthorizationEndpoint,
		TokenURL: discovery.TokenEndpoint,
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("enterprise oidc code exchange failed: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || strings.TrimSpace(rawIDToken) == "" {
		return nil, fmt.Errorf("enterprise oidc token response missing id_token")
	}
	return p.VerifyIDToken(ctx, rawIDToken, expectedNonce)
}

func (p *EnterpriseOIDCProvider) VerifyIDToken(ctx context.Context, rawIDToken, expectedNonce string) (*EnterpriseOIDCUserInfo, error) {
	if strings.TrimSpace(rawIDToken) == "" {
		return nil, fmt.Errorf("missing enterprise oidc id_token")
	}

	claims := &enterpriseOIDCClaims{}
	token, err := jwt.ParseWithClaims(rawIDToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		kid, _ := token.Header["kid"].(string)
		return p.publicKey(ctx, kid)
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg(), jwt.SigningMethodRS384.Alg(), jwt.SigningMethodRS512.Alg()}),
		jwt.WithAudience(p.cfg.ClientID),
		jwt.WithIssuer(p.issuer),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid enterprise oidc id_token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid enterprise oidc id_token")
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return nil, fmt.Errorf("enterprise oidc id_token missing subject")
	}
	if expectedNonce != "" && claims.Nonce != expectedNonce {
		return nil, fmt.Errorf("enterprise oidc nonce mismatch")
	}

	return &EnterpriseOIDCUserInfo{
		Subject:           claims.Subject,
		Email:             strings.TrimSpace(strings.ToLower(claims.Email)),
		EmailVerified:     claims.EmailVerified,
		Name:              claims.Name,
		PreferredUsername: claims.PreferredUsername,
		Picture:           claims.Picture,
		Issuer:            claims.Issuer,
	}, nil
}

func (p *EnterpriseOIDCProvider) ensureDiscovery(ctx context.Context) (*enterpriseOIDCDiscovery, error) {
	p.mu.RLock()
	if p.discovery != nil {
		discovery := p.discovery
		p.mu.RUnlock()
		return discovery, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.discovery != nil {
		return p.discovery, nil
	}

	discoveryURL := strings.TrimRight(p.issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create enterprise oidc discovery request: %w", err)
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch enterprise oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch enterprise oidc discovery: status=%d", resp.StatusCode)
	}

	var discovery enterpriseOIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("decode enterprise oidc discovery: %w", err)
	}
	discovery.Issuer = normalizeIssuer(discovery.Issuer)
	if discovery.Issuer != p.issuer {
		return nil, fmt.Errorf("enterprise oidc discovery issuer mismatch")
	}
	if discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" || discovery.JWKsURI == "" {
		return nil, fmt.Errorf("enterprise oidc discovery missing required endpoints")
	}
	p.discovery = &discovery
	return p.discovery, nil
}

func (p *EnterpriseOIDCProvider) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if strings.TrimSpace(kid) == "" {
		return nil, fmt.Errorf("missing enterprise oidc key id")
	}
	if _, err := p.ensureDiscovery(ctx); err != nil {
		return nil, err
	}

	p.mu.RLock()
	if len(p.jwks) > 0 && time.Now().Before(p.jwksUntil) {
		if key := p.jwks[kid]; key != nil {
			p.mu.RUnlock()
			return key, nil
		}
	}
	p.mu.RUnlock()

	return p.refreshJWKS(ctx, kid)
}

func (p *EnterpriseOIDCProvider) refreshJWKS(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.jwks) > 0 && time.Now().Before(p.jwksUntil) {
		if key := p.jwks[kid]; key != nil {
			return key, nil
		}
	}
	if p.discovery == nil {
		return nil, fmt.Errorf("enterprise oidc discovery is not loaded")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.discovery.JWKsURI, nil)
	if err != nil {
		return nil, fmt.Errorf("create enterprise oidc jwks request: %w", err)
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch enterprise oidc jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch enterprise oidc jwks: status=%d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode enterprise oidc jwks: %w", err)
	}

	parsed := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, key := range jwks.Keys {
		if key.KeyType != "RSA" || key.KeyID == "" {
			continue
		}
		publicKey, err := parseEnterpriseOIDCJWK(key)
		if err != nil {
			return nil, fmt.Errorf("parse enterprise oidc jwk %s: %w", key.KeyID, err)
		}
		parsed[key.KeyID] = publicKey
	}
	p.jwks = parsed
	p.jwksUntil = time.Now().Add(parseCacheMaxAge(resp.Header.Get("Cache-Control")))

	if key := p.jwks[kid]; key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("enterprise oidc signing key not found")
}

func (m *EnterpriseOIDCManager) findOrCreateUser(provider *EnterpriseOIDCProvider, info *EnterpriseOIDCUserInfo) (*auth.User, error) {
	var identity ExternalIdentity
	err := m.db.Where("provider_type = ? AND provider_id = ? AND subject = ?", IdentityProviderTypeOIDC, provider.cfg.Slug, info.Subject).First(&identity).Error
	switch err {
	case nil:
		return m.updateExistingIdentity(provider, &identity, info)
	case gorm.ErrRecordNotFound:
		return m.createIdentityUser(provider, info)
	default:
		return nil, err
	}
}

func (m *EnterpriseOIDCManager) updateExistingIdentity(provider *EnterpriseOIDCProvider, identity *ExternalIdentity, info *EnterpriseOIDCUserInfo) (*auth.User, error) {
	now := time.Now()
	updates := map[string]any{
		"email":          info.Email,
		"email_verified": info.EmailVerified,
		"display_name":   displayName(info),
		"profile_json":   profileJSON(info),
		"last_login_at":  &now,
		"updated_at":     now,
	}
	if err := m.db.Model(identity).Updates(updates).Error; err != nil {
		return nil, err
	}
	var user auth.User
	if err := m.db.First(&user, "user_id = ?", identity.UserID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (m *EnterpriseOIDCManager) createIdentityUser(provider *EnterpriseOIDCProvider, info *EnterpriseOIDCUserInfo) (*auth.User, error) {
	if existingUserID, err := m.lookupVerifiedEmailUserID(info); err != nil {
		return nil, err
	} else if existingUserID != "" {
		return m.linkExistingUser(provider, existingUserID, info)
	}
	return m.createNewUser(provider, info)
}

func (m *EnterpriseOIDCManager) linkExistingUser(provider *EnterpriseOIDCProvider, userID string, info *EnterpriseOIDCUserInfo) (*auth.User, error) {
	identityID, err := m.service.GenerateExternalIdentityID()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	identity := ExternalIdentity{
		ExternalIdentityID: identityID,
		ProviderType:       IdentityProviderTypeOIDC,
		ProviderID:         provider.cfg.Slug,
		Subject:            info.Subject,
		UserID:             userID,
		OrganizationID:     provider.cfg.OrganizationID,
		Email:              info.Email,
		EmailVerified:      info.EmailVerified,
		DisplayName:        displayName(info),
		ProfileJSON:        profileJSON(info),
		LastLoginAt:        &now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := m.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&identity).Error; err != nil {
			return err
		}
		return upsertMembership(tx, provider.cfg.OrganizationID, userID)
	}); err != nil {
		return nil, err
	}

	var user auth.User
	if err := m.db.First(&user, "user_id = ?", userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (m *EnterpriseOIDCManager) createNewUser(provider *EnterpriseOIDCProvider, info *EnterpriseOIDCUserInfo) (*auth.User, error) {
	userID, err := auth.GenerateUserID(m.db)
	if err != nil {
		return nil, err
	}
	identityID, err := m.service.GenerateExternalIdentityID()
	if err != nil {
		return nil, err
	}

	randomPassword := make([]byte, 32)
	if _, err := rand.Read(randomPassword); err != nil {
		return nil, fmt.Errorf("generate enterprise oidc user password: %w", err)
	}
	hashedPassword, err := bcrypt.GenerateFromPassword(randomPassword, bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash enterprise oidc user password: %w", err)
	}

	now := time.Now()
	avatar := ""
	if m.avatarService != nil && strings.TrimSpace(info.Picture) != "" {
		if uploaded, err := m.avatarService.DownloadAndUploadAvatar(userID, info.Picture); err == nil {
			avatar = uploaded
		}
	}
	user := auth.User{
		UserID:       userID,
		Password:     string(hashedPassword),
		TokenVersion: auth.DefaultTokenVersion,
		Status:       auth.UserStatusActive,
		Nickname:     fallbackNickname(info, userID),
		Avatar:       avatar,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	identity := ExternalIdentity{
		ExternalIdentityID: identityID,
		ProviderType:       IdentityProviderTypeOIDC,
		ProviderID:         provider.cfg.Slug,
		Subject:            info.Subject,
		UserID:             userID,
		OrganizationID:     provider.cfg.OrganizationID,
		Email:              info.Email,
		EmailVerified:      info.EmailVerified,
		DisplayName:        displayName(info),
		ProfileJSON:        profileJSON(info),
		LastLoginAt:        &now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	if err := m.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&user).Error; err != nil {
			return err
		}
		if err := tx.Create(&identity).Error; err != nil {
			return err
		}
		return upsertMembership(tx, provider.cfg.OrganizationID, userID)
	}); err != nil {
		return nil, err
	}
	return &user, nil
}

func (m *EnterpriseOIDCManager) lookupVerifiedEmailUserID(info *EnterpriseOIDCUserInfo) (string, error) {
	if info == nil || !info.EmailVerified || strings.TrimSpace(info.Email) == "" {
		return "", nil
	}
	if !m.db.Migrator().HasTable(&auth.EmailUser{}) {
		return "", nil
	}
	var emailUser auth.EmailUser
	if err := m.db.First(&emailUser, "email = ?", strings.TrimSpace(strings.ToLower(info.Email))).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", nil
		}
		return "", err
	}
	return emailUser.UserID, nil
}

func upsertMembership(tx *gorm.DB, organizationID, userID string) error {
	organizationID = strings.TrimSpace(organizationID)
	if organizationID == "" {
		return nil
	}
	now := time.Now()
	membership := OrganizationMembership{
		OrganizationID: organizationID,
		UserID:         userID,
		Status:         MembershipStatusActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "organization_id"}, {Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"status", "updated_at"}),
	}).Create(&membership).Error
}

func parseEnterpriseOIDCJWK(key jwkKey) (*rsa.PublicKey, error) {
	if key.N != "" && key.E != "" {
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return nil, err
		}
		n := new(big.Int).SetBytes(nBytes)
		e := int(new(big.Int).SetBytes(eBytes).Int64())
		if n.Sign() <= 0 || e <= 0 {
			return nil, fmt.Errorf("invalid rsa public key")
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	}
	if len(key.X5C) > 0 {
		der, err := base64.StdEncoding.DecodeString(key.X5C[0])
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("certificate does not contain rsa public key")
		}
		return publicKey, nil
	}
	return nil, fmt.Errorf("jwk missing rsa modulus/exponent")
}

func normalizeEnterpriseOIDCEmailDomain(raw string) (string, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	at := strings.LastIndex(raw, "@")
	if at <= 0 || at == len(raw)-1 {
		return "", ErrInvalidEnterpriseOIDCEmail
	}
	domain, err := normalizeEnterpriseOIDCDomain(raw[at+1:])
	if err != nil {
		return "", ErrInvalidEnterpriseOIDCEmail
	}
	return domain, nil
}

func normalizeEnterpriseOIDCDomain(raw string) (string, error) {
	domain := strings.TrimSpace(strings.ToLower(raw))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", ErrInvalidEnterpriseOIDCDomain
	}
	if strings.Contains(domain, "://") || strings.ContainsAny(domain, "/@") || len(domain) > 253 || !strings.Contains(domain, ".") {
		return "", ErrInvalidEnterpriseOIDCDomain
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", ErrInvalidEnterpriseOIDCDomain
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return "", ErrInvalidEnterpriseOIDCDomain
			}
		}
	}
	return domain, nil
}

func parseCacheMaxAge(cacheControl string) time.Duration {
	const defaultTTL = time.Hour
	for _, directive := range strings.Split(cacheControl, ",") {
		directive = strings.TrimSpace(directive)
		if !strings.HasPrefix(strings.ToLower(directive), "max-age=") {
			continue
		}
		seconds, ok := new(big.Int).SetString(strings.TrimPrefix(directive, "max-age="), 10)
		if !ok || seconds.Sign() <= 0 {
			return defaultTTL
		}
		return time.Duration(seconds.Int64()) * time.Second
	}
	return defaultTTL
}

func normalizeIssuer(issuer string) string {
	return strings.TrimRight(strings.TrimSpace(issuer), "/")
}

func displayName(info *EnterpriseOIDCUserInfo) string {
	if info == nil {
		return ""
	}
	if strings.TrimSpace(info.Name) != "" {
		return strings.TrimSpace(info.Name)
	}
	if strings.TrimSpace(info.PreferredUsername) != "" {
		return strings.TrimSpace(info.PreferredUsername)
	}
	return strings.TrimSpace(info.Email)
}

func fallbackNickname(info *EnterpriseOIDCUserInfo, fallback string) string {
	if name := displayName(info); name != "" {
		return name
	}
	if info != nil && strings.Contains(info.Email, "@") {
		return strings.Split(info.Email, "@")[0]
	}
	return fallback
}

func profileJSON(info *EnterpriseOIDCUserInfo) string {
	if info == nil {
		return ""
	}
	data, err := json.Marshal(map[string]any{
		"iss":                info.Issuer,
		"sub":                info.Subject,
		"email":              info.Email,
		"email_verified":     info.EmailVerified,
		"name":               info.Name,
		"preferred_username": info.PreferredUsername,
		"picture":            info.Picture,
	})
	if err != nil {
		return ""
	}
	return string(data)
}
