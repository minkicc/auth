/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package iam

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
)

const defaultEnterpriseSAMLTimeout = 10 * time.Second

var defaultEnterpriseSAMLDisplayNameAttributes = []string{
	"displayName",
	"name",
	"cn",
	"urn:oid:2.16.840.1.113730.3.1.241",
}

var defaultEnterpriseSAMLEmailAttributes = []string{
	"email",
	"mail",
	"urn:oid:0.9.2342.19200300.100.1.3",
}

var defaultEnterpriseSAMLUsernameAttributes = []string{
	"uid",
	"username",
	"preferred_username",
	"urn:oid:0.9.2342.19200300.100.1.1",
}

type EnterpriseSAMLManager struct {
	baseURL       string
	db            *gorm.DB
	service       *Service
	avatarService *auth.AvatarService
	staticConfigs []config.EnterpriseSAMLProviderConfig
	mu            sync.RWMutex
	providers     map[string]*EnterpriseSAMLProvider
}

type EnterpriseSAMLProvider struct {
	cfg        config.EnterpriseSAMLProviderConfig
	httpClient *http.Client
	sp         saml.ServiceProvider
}

type EnterpriseSAMLAuthFlow struct {
	RequestID   string
	Binding     string
	RedirectURL string
	PostForm    string
}

type EnterpriseSAMLUserInfo struct {
	Subject           string
	Email             string
	EmailVerified     bool
	Name              string
	PreferredUsername string
	ProfileJSON       string
}

func NewEnterpriseSAMLManager(iamCfg config.IAMConfig, baseURL string, db *gorm.DB, avatarService *auth.AvatarService) (*EnterpriseSAMLManager, error) {
	if db == nil {
		return nil, fmt.Errorf("enterprise saml requires database")
	}

	manager := &EnterpriseSAMLManager{
		baseURL:       strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		db:            db,
		service:       NewService(db),
		avatarService: avatarService,
		staticConfigs: append([]config.EnterpriseSAMLProviderConfig(nil), iamCfg.EnterpriseSAML...),
		providers:     map[string]*EnterpriseSAMLProvider{},
	}
	if err := manager.Reload(); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *EnterpriseSAMLManager) Reload() error {
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

func (m *EnterpriseSAMLManager) HasStaticProviderSlug(slug string) bool {
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

func (m *EnterpriseSAMLManager) HasProviders() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.providers) > 0
}

func (m *EnterpriseSAMLManager) DB() *gorm.DB {
	if m == nil {
		return nil
	}
	return m.db
}

func (m *EnterpriseSAMLManager) Providers() []EnterpriseOIDCProviderSummary {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	providers := make([]EnterpriseOIDCProviderSummary, 0, len(m.providers))
	for _, provider := range m.providers {
		providers = append(providers, enterpriseSAMLProviderSummary(provider))
	}
	sortEnterpriseOIDCProviderSummaries(providers)
	return providers
}

func (m *EnterpriseSAMLManager) ProvidersForOrganization(organizationID string) []EnterpriseOIDCProviderSummary {
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
		providers = append(providers, enterpriseSAMLProviderSummary(provider))
	}
	sortEnterpriseOIDCProviderSummaries(providers)
	return providers
}

func (m *EnterpriseSAMLManager) buildProviders() (map[string]*EnterpriseSAMLProvider, error) {
	providers := make(map[string]*EnterpriseSAMLProvider, len(m.staticConfigs))
	for _, providerCfg := range m.staticConfigs {
		provider, err := NewEnterpriseSAMLProvider(providerCfg, m.baseURL)
		if err != nil {
			return nil, err
		}
		if _, exists := providers[provider.cfg.Slug]; exists {
			return nil, fmt.Errorf("duplicate enterprise saml provider slug %q", provider.cfg.Slug)
		}
		providers[provider.cfg.Slug] = provider
	}

	var records []OrganizationIdentityProvider
	if err := m.db.Where("provider_type = ? AND enabled = ?", IdentityProviderTypeSAML, true).
		Order("is_default DESC").
		Order("auto_redirect DESC").
		Order("priority ASC").
		Order("created_at ASC").
		Find(&records).Error; err != nil {
		return nil, err
	}
	for _, record := range records {
		providerCfg, err := enterpriseSAMLProviderConfigFromRecord(record)
		if err != nil {
			return nil, fmt.Errorf("load enterprise saml provider %q: %w", record.Slug, err)
		}
		provider, err := NewEnterpriseSAMLProvider(providerCfg, m.baseURL)
		if err != nil {
			return nil, err
		}
		if _, exists := providers[provider.cfg.Slug]; exists {
			return nil, fmt.Errorf("duplicate enterprise saml provider slug %q", provider.cfg.Slug)
		}
		providers[provider.cfg.Slug] = provider
	}

	return providers, nil
}

func enterpriseSAMLProviderConfigFromRecord(record OrganizationIdentityProvider) (config.EnterpriseSAMLProviderConfig, error) {
	var providerCfg config.EnterpriseSAMLProviderConfig
	if strings.TrimSpace(record.ConfigJSON) != "" {
		if err := json.Unmarshal([]byte(record.ConfigJSON), &providerCfg); err != nil {
			return config.EnterpriseSAMLProviderConfig{}, fmt.Errorf("decode provider config: %w", err)
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

func NewEnterpriseSAMLProvider(cfg config.EnterpriseSAMLProviderConfig, baseURL string) (*EnterpriseSAMLProvider, error) {
	cfg.Slug = strings.TrimSpace(cfg.Slug)
	cfg.Name = strings.TrimSpace(cfg.Name)
	cfg.OrganizationID = strings.TrimSpace(cfg.OrganizationID)
	cfg.IDPMetadataURL = strings.TrimSpace(cfg.IDPMetadataURL)
	cfg.IDPMetadataXML = strings.TrimSpace(cfg.IDPMetadataXML)
	cfg.EntityID = strings.TrimSpace(cfg.EntityID)
	cfg.ACSURL = strings.TrimSpace(cfg.ACSURL)
	cfg.NameIDFormat = strings.TrimSpace(cfg.NameIDFormat)
	cfg.EmailAttribute = strings.TrimSpace(cfg.EmailAttribute)
	cfg.UsernameAttribute = strings.TrimSpace(cfg.UsernameAttribute)
	cfg.DisplayNameAttribute = strings.TrimSpace(cfg.DisplayNameAttribute)
	cfg.DefaultRedirectURI = strings.TrimSpace(cfg.DefaultRedirectURI)
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")

	if cfg.Slug == "" || cfg.Name == "" {
		return nil, fmt.Errorf("enterprise saml provider is missing slug or name")
	}
	if cfg.IDPMetadataURL == "" && cfg.IDPMetadataXML == "" {
		return nil, fmt.Errorf("enterprise saml provider %q requires idp_metadata_url or idp_metadata_xml", cfg.Slug)
	}
	if baseURL == "" && (cfg.ACSURL == "" || cfg.EntityID == "") {
		return nil, fmt.Errorf("enterprise saml provider %q requires base url or explicit acs_url and entity_id", cfg.Slug)
	}

	if cfg.ACSURL == "" {
		cfg.ACSURL = baseURL + config.API_ROUTER_PATH + "/enterprise/saml/" + cfg.Slug + "/acs"
	}
	metadataURL := baseURL + config.API_ROUTER_PATH + "/enterprise/saml/" + cfg.Slug + "/metadata"
	if cfg.EntityID == "" {
		cfg.EntityID = metadataURL
	}
	if cfg.NameIDFormat == "" {
		cfg.NameIDFormat = string(saml.UnspecifiedNameIDFormat)
	}
	if cfg.DefaultRedirectURI == "" {
		cfg.DefaultRedirectURI = "/profile"
	}

	acsURL, err := url.Parse(cfg.ACSURL)
	if err != nil || acsURL.Scheme == "" || acsURL.Host == "" {
		return nil, fmt.Errorf("enterprise saml provider %q has invalid acs_url", cfg.Slug)
	}
	metadataParsedURL, err := url.Parse(metadataURL)
	if err != nil || metadataParsedURL.Scheme == "" || metadataParsedURL.Host == "" {
		return nil, fmt.Errorf("enterprise saml provider %q has invalid metadata url", cfg.Slug)
	}

	httpClient := &http.Client{Timeout: defaultEnterpriseSAMLTimeout}
	idpMetadata, err := enterpriseSAMLMetadata(context.Background(), httpClient, cfg)
	if err != nil {
		return nil, err
	}

	provider := &EnterpriseSAMLProvider{
		cfg:        cfg,
		httpClient: httpClient,
		sp: saml.ServiceProvider{
			EntityID:           cfg.EntityID,
			MetadataURL:        *metadataParsedURL,
			AcsURL:             *acsURL,
			IDPMetadata:        idpMetadata,
			AuthnNameIDFormat:  saml.NameIDFormat(cfg.NameIDFormat),
			AllowIDPInitiated:  cfg.AllowIDPInitiated,
			DefaultRedirectURI: cfg.DefaultRedirectURI,
			HTTPClient:         httpClient,
		},
	}
	return provider, nil
}

func enterpriseSAMLMetadata(ctx context.Context, httpClient *http.Client, cfg config.EnterpriseSAMLProviderConfig) (*saml.EntityDescriptor, error) {
	if strings.TrimSpace(cfg.IDPMetadataXML) != "" {
		entity, err := samlsp.ParseMetadata([]byte(cfg.IDPMetadataXML))
		if err != nil {
			return nil, fmt.Errorf("parse enterprise saml metadata xml for %q: %w", cfg.Slug, err)
		}
		return entity, nil
	}
	metadataURL, err := url.Parse(cfg.IDPMetadataURL)
	if err != nil || metadataURL.Scheme == "" || metadataURL.Host == "" {
		return nil, fmt.Errorf("enterprise saml provider %q has invalid idp_metadata_url", cfg.Slug)
	}
	entity, err := samlsp.FetchMetadata(ctx, httpClient, *metadataURL)
	if err != nil {
		return nil, fmt.Errorf("fetch enterprise saml metadata for %q: %w", cfg.Slug, err)
	}
	return entity, nil
}

func (m *EnterpriseSAMLManager) StartAuthFlow(slug, relayState string) (*EnterpriseSAMLAuthFlow, error) {
	provider, ok := m.provider(slug)
	if !ok {
		return nil, fmt.Errorf("enterprise saml provider %q not found", slug)
	}

	binding := saml.HTTPRedirectBinding
	bindingLocation := provider.sp.GetSSOBindingLocation(binding)
	if bindingLocation == "" {
		binding = saml.HTTPPostBinding
		bindingLocation = provider.sp.GetSSOBindingLocation(binding)
	}
	if bindingLocation == "" {
		return nil, fmt.Errorf("enterprise saml provider %q does not publish a supported SSO binding", slug)
	}

	authReq, err := provider.sp.MakeAuthenticationRequest(bindingLocation, binding, saml.HTTPPostBinding)
	if err != nil {
		return nil, err
	}

	flow := &EnterpriseSAMLAuthFlow{
		RequestID: authReq.ID,
		Binding:   binding,
	}
	if binding == saml.HTTPRedirectBinding {
		redirectURL, err := authReq.Redirect(relayState, &provider.sp)
		if err != nil {
			return nil, err
		}
		flow.RedirectURL = redirectURL.String()
		return flow, nil
	}
	flow.PostForm = string(authReq.Post(relayState))
	return flow, nil
}

func (m *EnterpriseSAMLManager) MetadataXML(slug string) ([]byte, error) {
	provider, ok := m.provider(slug)
	if !ok {
		return nil, fmt.Errorf("enterprise saml provider %q not found", slug)
	}
	return xml.MarshalIndent(provider.sp.Metadata(), "", "  ")
}

func (m *EnterpriseSAMLManager) Authenticate(req *http.Request, slug string, possibleRequestIDs []string) (*auth.User, error) {
	provider, ok := m.provider(slug)
	if !ok {
		return nil, fmt.Errorf("enterprise saml provider %q not found", slug)
	}
	if req == nil {
		return nil, fmt.Errorf("missing enterprise saml request")
	}
	if err := req.ParseForm(); err != nil {
		return nil, fmt.Errorf("parse enterprise saml response: %w", err)
	}
	assertion, err := provider.sp.ParseResponse(req, possibleRequestIDs)
	if err != nil {
		return nil, err
	}
	info, err := enterpriseSAMLUserInfoFromAssertion(provider, assertion)
	if err != nil {
		return nil, err
	}
	return m.findOrCreateUser(provider, info)
}

func (m *EnterpriseSAMLManager) provider(slug string) (*EnterpriseSAMLProvider, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	provider, ok := m.providers[strings.TrimSpace(slug)]
	return provider, ok
}

func enterpriseSAMLProviderSummary(provider *EnterpriseSAMLProvider) EnterpriseOIDCProviderSummary {
	return EnterpriseOIDCProviderSummary{
		Slug:           provider.cfg.Slug,
		Name:           provider.cfg.Name,
		OrganizationID: provider.cfg.OrganizationID,
		ProviderType:   string(IdentityProviderTypeSAML),
		Priority:       provider.cfg.Priority,
		IsDefault:      provider.cfg.IsDefault,
		AutoRedirect:   provider.cfg.AutoRedirect,
	}
}

func enterpriseSAMLUserInfoFromAssertion(provider *EnterpriseSAMLProvider, assertion *saml.Assertion) (*EnterpriseSAMLUserInfo, error) {
	if provider == nil || assertion == nil {
		return nil, fmt.Errorf("enterprise saml assertion is missing")
	}

	attributes := map[string][]string{}
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			keyNames := []string{strings.TrimSpace(attribute.Name), strings.TrimSpace(attribute.FriendlyName)}
			values := make([]string, 0, len(attribute.Values))
			for _, value := range attribute.Values {
				text := strings.TrimSpace(value.Value)
				if text == "" {
					continue
				}
				values = append(values, text)
			}
			if len(values) == 0 {
				continue
			}
			for _, key := range keyNames {
				if key == "" {
					continue
				}
				attributes[key] = append(attributes[key], values...)
			}
		}
	}

	email := firstEnterpriseSAMLAttribute(attributes, provider.cfg.EmailAttribute, defaultEnterpriseSAMLEmailAttributes)
	email = strings.TrimSpace(strings.ToLower(email))
	displayName := firstEnterpriseSAMLAttribute(attributes, provider.cfg.DisplayNameAttribute, defaultEnterpriseSAMLDisplayNameAttributes)
	username := firstEnterpriseSAMLAttribute(attributes, provider.cfg.UsernameAttribute, defaultEnterpriseSAMLUsernameAttributes)

	subject := ""
	if assertion.Subject.NameID != nil {
		subject = strings.TrimSpace(assertion.Subject.NameID.Value)
	}
	if subject == "" {
		subject = email
	}
	if subject == "" {
		subject = username
	}
	if subject == "" {
		return nil, fmt.Errorf("enterprise saml assertion is missing a usable subject")
	}

	profileJSON, _ := json.Marshal(attributes)
	return &EnterpriseSAMLUserInfo{
		Subject:           subject,
		Email:             email,
		EmailVerified:     email != "",
		Name:              displayName,
		PreferredUsername: username,
		ProfileJSON:       string(profileJSON),
	}, nil
}

func firstEnterpriseSAMLAttribute(attributes map[string][]string, preferred string, defaults []string) string {
	keys := make([]string, 0, len(defaults)+1)
	if preferred = strings.TrimSpace(preferred); preferred != "" {
		keys = append(keys, preferred)
	}
	keys = append(keys, defaults...)
	for _, key := range keys {
		values := attributes[key]
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return value
			}
		}
	}
	return ""
}

func (m *EnterpriseSAMLManager) findOrCreateUser(provider *EnterpriseSAMLProvider, info *EnterpriseSAMLUserInfo) (*auth.User, error) {
	var identity ExternalIdentity
	err := m.db.Where("provider_type = ? AND provider_id = ? AND subject = ?", IdentityProviderTypeSAML, provider.cfg.Slug, info.Subject).First(&identity).Error
	switch err {
	case nil:
		return m.updateExistingIdentity(provider, &identity, info)
	case gorm.ErrRecordNotFound:
		return m.createIdentityUser(provider, info)
	default:
		return nil, err
	}
}

func (m *EnterpriseSAMLManager) updateExistingIdentity(provider *EnterpriseSAMLProvider, identity *ExternalIdentity, info *EnterpriseSAMLUserInfo) (*auth.User, error) {
	now := time.Now()
	updates := map[string]any{
		"email":          info.Email,
		"email_verified": info.EmailVerified,
		"display_name":   enterpriseSAMLDisplayName(info),
		"profile_json":   info.ProfileJSON,
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

func (m *EnterpriseSAMLManager) createIdentityUser(provider *EnterpriseSAMLProvider, info *EnterpriseSAMLUserInfo) (*auth.User, error) {
	if existingUserID, err := m.lookupVerifiedEmailUserID(info); err != nil {
		return nil, err
	} else if existingUserID != "" {
		return m.linkExistingUser(provider, existingUserID, info)
	}
	return m.createNewUser(provider, info)
}

func (m *EnterpriseSAMLManager) linkExistingUser(provider *EnterpriseSAMLProvider, userID string, info *EnterpriseSAMLUserInfo) (*auth.User, error) {
	identityID, err := m.service.GenerateExternalIdentityID()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	identity := ExternalIdentity{
		ExternalIdentityID: identityID,
		ProviderType:       IdentityProviderTypeSAML,
		ProviderID:         provider.cfg.Slug,
		Subject:            info.Subject,
		UserID:             userID,
		OrganizationID:     provider.cfg.OrganizationID,
		Email:              info.Email,
		EmailVerified:      info.EmailVerified,
		DisplayName:        enterpriseSAMLDisplayName(info),
		ProfileJSON:        info.ProfileJSON,
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

func (m *EnterpriseSAMLManager) createNewUser(provider *EnterpriseSAMLProvider, info *EnterpriseSAMLUserInfo) (*auth.User, error) {
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
		return nil, fmt.Errorf("generate enterprise saml user password: %w", err)
	}
	hashedPassword, err := bcrypt.GenerateFromPassword(randomPassword, bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash enterprise saml user password: %w", err)
	}

	now := time.Now()
	user := auth.User{
		UserID:       userID,
		Password:     string(hashedPassword),
		TokenVersion: auth.DefaultTokenVersion,
		Status:       auth.UserStatusActive,
		Nickname:     enterpriseSAMLFallbackNickname(info, userID),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	identity := ExternalIdentity{
		ExternalIdentityID: identityID,
		ProviderType:       IdentityProviderTypeSAML,
		ProviderID:         provider.cfg.Slug,
		Subject:            info.Subject,
		UserID:             userID,
		OrganizationID:     provider.cfg.OrganizationID,
		Email:              info.Email,
		EmailVerified:      info.EmailVerified,
		DisplayName:        enterpriseSAMLDisplayName(info),
		ProfileJSON:        info.ProfileJSON,
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

func (m *EnterpriseSAMLManager) lookupVerifiedEmailUserID(info *EnterpriseSAMLUserInfo) (string, error) {
	if info == nil || !info.EmailVerified || strings.TrimSpace(info.Email) == "" {
		return "", nil
	}
	var emailUser auth.EmailUser
	err := m.db.First(&emailUser, "LOWER(email) = ?", strings.ToLower(info.Email)).Error
	switch err {
	case nil:
		return emailUser.UserID, nil
	case gorm.ErrRecordNotFound:
		return "", nil
	default:
		return "", err
	}
}

func enterpriseSAMLDisplayName(info *EnterpriseSAMLUserInfo) string {
	if info == nil {
		return ""
	}
	if value := strings.TrimSpace(info.Name); value != "" {
		return value
	}
	if value := strings.TrimSpace(info.PreferredUsername); value != "" {
		return value
	}
	if value := strings.TrimSpace(info.Email); value != "" {
		return value
	}
	return ""
}

func enterpriseSAMLFallbackNickname(info *EnterpriseSAMLUserInfo, fallback string) string {
	if name := enterpriseSAMLDisplayName(info); name != "" {
		return name
	}
	return fallback
}
