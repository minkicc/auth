/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package iam

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	neturl "net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/secureconfig"
)

const (
	defaultEnterpriseLDAPTimeout    = 10 * time.Second
	defaultEnterpriseLDAPUserFilter = "(|(uid={username})(mail={username})(cn={username})(sAMAccountName={username})(userPrincipalName={username}))"
)

var defaultEnterpriseLDAPSubjectAttributes = []string{
	"entryUUID",
	"objectGUID",
	"uidNumber",
	"uid",
	"sAMAccountName",
	"userPrincipalName",
}

var defaultEnterpriseLDAPEmailAttributes = []string{
	"mail",
	"email",
	"userPrincipalName",
}

var defaultEnterpriseLDAPUsernameAttributes = []string{
	"uid",
	"sAMAccountName",
	"userPrincipalName",
	"cn",
}

var defaultEnterpriseLDAPDisplayNameAttributes = []string{
	"displayName",
	"cn",
	"name",
	"givenName",
}

type EnterpriseLDAPAuthenticator interface {
	Authenticate(ctx context.Context, cfg config.EnterpriseLDAPProviderConfig, username, password string) (*EnterpriseLDAPUserInfo, error)
}

type EnterpriseLDAPManager struct {
	db            *gorm.DB
	service       *Service
	avatarService *auth.AvatarService
	staticConfigs []config.EnterpriseLDAPProviderConfig
	authenticator EnterpriseLDAPAuthenticator
	mu            sync.RWMutex
	providers     map[string]*EnterpriseLDAPProvider
}

type EnterpriseLDAPProvider struct {
	cfg           config.EnterpriseLDAPProviderConfig
	authenticator EnterpriseLDAPAuthenticator
}

type EnterpriseLDAPUserInfo struct {
	Subject           string
	Email             string
	EmailVerified     bool
	Name              string
	PreferredUsername string
	DN                string
	Groups            []EnterpriseLDAPGroupInfo
	ProfileJSON       string
}

type networkEnterpriseLDAPAuthenticator struct{}

func NewEnterpriseLDAPManager(iamCfg config.IAMConfig, db *gorm.DB, avatarService *auth.AvatarService) (*EnterpriseLDAPManager, error) {
	return NewEnterpriseLDAPManagerWithAuthenticator(iamCfg, db, avatarService, networkEnterpriseLDAPAuthenticator{})
}

func NewEnterpriseLDAPManagerWithAuthenticator(iamCfg config.IAMConfig, db *gorm.DB, avatarService *auth.AvatarService, authenticator EnterpriseLDAPAuthenticator) (*EnterpriseLDAPManager, error) {
	if db == nil {
		return nil, fmt.Errorf("enterprise ldap requires database")
	}
	if authenticator == nil {
		authenticator = networkEnterpriseLDAPAuthenticator{}
	}

	manager := &EnterpriseLDAPManager{
		db:            db,
		service:       NewService(db),
		avatarService: avatarService,
		staticConfigs: append([]config.EnterpriseLDAPProviderConfig(nil), iamCfg.EnterpriseLDAP...),
		authenticator: authenticator,
		providers:     map[string]*EnterpriseLDAPProvider{},
	}
	if err := manager.Reload(); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *EnterpriseLDAPManager) Reload() error {
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

func (m *EnterpriseLDAPManager) HasStaticProviderSlug(slug string) bool {
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

func (m *EnterpriseLDAPManager) HasProviders() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.providers) > 0
}

func (m *EnterpriseLDAPManager) DB() *gorm.DB {
	if m == nil {
		return nil
	}
	return m.db
}

func (m *EnterpriseLDAPManager) Providers() []EnterpriseOIDCProviderSummary {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	providers := make([]EnterpriseOIDCProviderSummary, 0, len(m.providers))
	for _, provider := range m.providers {
		providers = append(providers, enterpriseLDAPProviderSummary(provider))
	}
	sortEnterpriseOIDCProviderSummaries(providers)
	return providers
}

func (m *EnterpriseLDAPManager) ProvidersForOrganization(organizationID string) []EnterpriseOIDCProviderSummary {
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
		providers = append(providers, enterpriseLDAPProviderSummary(provider))
	}
	sortEnterpriseOIDCProviderSummaries(providers)
	return providers
}

func (m *EnterpriseLDAPManager) Authenticate(ctx context.Context, slug, username, password string) (*auth.User, error) {
	result, err := m.AuthenticateWithResult(ctx, slug, username, password)
	if err != nil {
		return nil, err
	}
	return result.User, nil
}

func (m *EnterpriseLDAPManager) AuthenticateWithResult(ctx context.Context, slug, username, password string) (*EnterpriseAuthenticationResult, error) {
	provider, ok := m.provider(slug)
	if !ok {
		return nil, fmt.Errorf("enterprise ldap provider %q not found", slug)
	}
	info, err := provider.Authenticate(ctx, username, password)
	if err != nil {
		return nil, err
	}
	return m.findOrCreateUserWithResult(provider, info)
}

func (m *EnterpriseLDAPManager) provider(slug string) (*EnterpriseLDAPProvider, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	provider, ok := m.providers[strings.TrimSpace(slug)]
	return provider, ok
}

func (m *EnterpriseLDAPManager) buildProviders() (map[string]*EnterpriseLDAPProvider, error) {
	providers := make(map[string]*EnterpriseLDAPProvider, len(m.staticConfigs))
	for _, providerCfg := range m.staticConfigs {
		provider, err := NewEnterpriseLDAPProvider(providerCfg, m.authenticator)
		if err != nil {
			return nil, err
		}
		if _, exists := providers[provider.cfg.Slug]; exists {
			return nil, fmt.Errorf("duplicate enterprise ldap provider slug %q", provider.cfg.Slug)
		}
		providers[provider.cfg.Slug] = provider
	}

	var records []OrganizationIdentityProvider
	if err := m.db.Where("provider_type = ? AND enabled = ?", IdentityProviderTypeLDAP, true).
		Order("is_default DESC").
		Order("auto_redirect DESC").
		Order("priority ASC").
		Order("created_at ASC").
		Find(&records).Error; err != nil {
		return nil, err
	}
	for _, record := range records {
		providerCfg, err := enterpriseLDAPProviderConfigFromRecord(record)
		if err != nil {
			return nil, fmt.Errorf("load enterprise ldap provider %q: %w", record.Slug, err)
		}
		provider, err := NewEnterpriseLDAPProvider(providerCfg, m.authenticator)
		if err != nil {
			return nil, err
		}
		if _, exists := providers[provider.cfg.Slug]; exists {
			return nil, fmt.Errorf("duplicate enterprise ldap provider slug %q", provider.cfg.Slug)
		}
		providers[provider.cfg.Slug] = provider
	}

	return providers, nil
}

func enterpriseLDAPProviderConfigFromRecord(record OrganizationIdentityProvider) (config.EnterpriseLDAPProviderConfig, error) {
	var providerCfg config.EnterpriseLDAPProviderConfig
	if strings.TrimSpace(record.ConfigJSON) != "" {
		if err := secureconfig.OpenJSON(record.ConfigJSON, &providerCfg); err != nil {
			return config.EnterpriseLDAPProviderConfig{}, fmt.Errorf("decode provider config: %w", err)
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

func NewEnterpriseLDAPProvider(cfg config.EnterpriseLDAPProviderConfig, authenticator EnterpriseLDAPAuthenticator) (*EnterpriseLDAPProvider, error) {
	cfg.Slug = strings.TrimSpace(cfg.Slug)
	cfg.Name = strings.TrimSpace(cfg.Name)
	cfg.OrganizationID = strings.TrimSpace(cfg.OrganizationID)
	cfg.URL = strings.TrimSpace(cfg.URL)
	cfg.BaseDN = strings.TrimSpace(cfg.BaseDN)
	cfg.BindDN = strings.TrimSpace(cfg.BindDN)
	cfg.BindPassword = strings.TrimSpace(cfg.BindPassword)
	cfg.UserFilter = strings.TrimSpace(cfg.UserFilter)
	cfg.GroupBaseDN = strings.TrimSpace(cfg.GroupBaseDN)
	cfg.GroupFilter = strings.TrimSpace(cfg.GroupFilter)
	cfg.GroupMemberAttribute = strings.TrimSpace(cfg.GroupMemberAttribute)
	cfg.GroupIdentifierAttr = strings.TrimSpace(cfg.GroupIdentifierAttr)
	cfg.GroupNameAttribute = strings.TrimSpace(cfg.GroupNameAttribute)
	cfg.SubjectAttribute = strings.TrimSpace(cfg.SubjectAttribute)
	cfg.EmailAttribute = strings.TrimSpace(cfg.EmailAttribute)
	cfg.UsernameAttribute = strings.TrimSpace(cfg.UsernameAttribute)
	cfg.DisplayNameAttribute = strings.TrimSpace(cfg.DisplayNameAttribute)
	if cfg.UserFilter == "" {
		cfg.UserFilter = defaultEnterpriseLDAPUserFilter
	}
	if authenticator == nil {
		authenticator = networkEnterpriseLDAPAuthenticator{}
	}

	if cfg.Slug == "" || cfg.Name == "" || cfg.URL == "" || cfg.BaseDN == "" {
		return nil, fmt.Errorf("enterprise ldap provider %q is missing required configuration", cfg.Slug)
	}
	parsedURL, err := neturl.Parse(cfg.URL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("enterprise ldap provider %q has invalid url", cfg.Slug)
	}
	if parsedURL.Scheme != "ldap" && parsedURL.Scheme != "ldaps" {
		return nil, fmt.Errorf("enterprise ldap provider %q must use ldap:// or ldaps://", cfg.Slug)
	}
	if cfg.BindPassword != "" && cfg.BindDN == "" {
		return nil, fmt.Errorf("enterprise ldap provider %q requires bind_dn when bind_password is set", cfg.Slug)
	}

	return &EnterpriseLDAPProvider{
		cfg:           cfg,
		authenticator: authenticator,
	}, nil
}

func (p *EnterpriseLDAPProvider) Authenticate(ctx context.Context, username, password string) (*EnterpriseLDAPUserInfo, error) {
	if p == nil {
		return nil, fmt.Errorf("enterprise ldap provider is missing")
	}
	return p.authenticator.Authenticate(ctx, p.cfg, username, password)
}

func enterpriseLDAPProviderSummary(provider *EnterpriseLDAPProvider) EnterpriseOIDCProviderSummary {
	return EnterpriseOIDCProviderSummary{
		Slug:           provider.cfg.Slug,
		Name:           provider.cfg.Name,
		OrganizationID: provider.cfg.OrganizationID,
		ProviderType:   string(IdentityProviderTypeLDAP),
		Priority:       provider.cfg.Priority,
		IsDefault:      provider.cfg.IsDefault,
		AutoRedirect:   provider.cfg.AutoRedirect,
	}
}

func (networkEnterpriseLDAPAuthenticator) Authenticate(_ context.Context, cfg config.EnterpriseLDAPProviderConfig, username, password string) (*EnterpriseLDAPUserInfo, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, fmt.Errorf("enterprise ldap username and password are required")
	}

	parsedURL, err := neturl.Parse(strings.TrimSpace(cfg.URL))
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("enterprise ldap provider %q has invalid url", cfg.Slug)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec
		ServerName:         parsedURL.Hostname(),
	}
	options := []ldap.DialOpt{
		ldap.DialWithDialer(&net.Dialer{Timeout: defaultEnterpriseLDAPTimeout}),
	}
	if parsedURL.Scheme == "ldaps" {
		options = append(options, ldap.DialWithTLSConfig(tlsConfig))
	}

	conn, err := ldap.DialURL(cfg.URL, options...)
	if err != nil {
		return nil, fmt.Errorf("enterprise ldap connect failed: %w", err)
	}
	defer conn.Close()
	conn.SetTimeout(defaultEnterpriseLDAPTimeout)

	if parsedURL.Scheme == "ldap" && cfg.StartTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			return nil, fmt.Errorf("enterprise ldap starttls failed: %w", err)
		}
	}

	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("enterprise ldap service bind failed: %w", err)
		}
	}

	filter := strings.ReplaceAll(defaultEnterpriseLDAPUserFilter, "{username}", ldap.EscapeFilter(username))
	if strings.TrimSpace(cfg.UserFilter) != "" {
		filter = strings.ReplaceAll(cfg.UserFilter, "{username}", ldap.EscapeFilter(username))
	}

	searchResult, err := conn.Search(ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		0,
		false,
		filter,
		[]string{"*", "+"},
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("enterprise ldap search failed: %w", err)
	}
	if len(searchResult.Entries) != 1 {
		return nil, fmt.Errorf("enterprise ldap search returned %d users", len(searchResult.Entries))
	}

	entry := searchResult.Entries[0]
	if strings.TrimSpace(entry.DN) == "" {
		return nil, fmt.Errorf("enterprise ldap user entry is missing dn")
	}
	groups, err := resolveEnterpriseLDAPGroups(conn, cfg, entry, username)
	if err != nil {
		return nil, err
	}
	if err := conn.Bind(entry.DN, password); err != nil {
		return nil, fmt.Errorf("enterprise ldap invalid credentials")
	}

	info, err := enterpriseLDAPUserInfoFromEntry(cfg, entry)
	if err != nil {
		return nil, err
	}
	info.Groups = groups
	return info, nil
}

func enterpriseLDAPUserInfoFromEntry(cfg config.EnterpriseLDAPProviderConfig, entry *ldap.Entry) (*EnterpriseLDAPUserInfo, error) {
	if entry == nil {
		return nil, fmt.Errorf("enterprise ldap user entry is missing")
	}

	attributes := map[string][]string{}
	for _, attribute := range entry.Attributes {
		values := make([]string, 0, len(attribute.Values))
		for _, value := range attribute.Values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			values = append(values, value)
		}
		if len(values) > 0 {
			attributes[attribute.Name] = append(attributes[attribute.Name], values...)
		}
	}

	subject := firstEnterpriseLDAPAttribute(entry, cfg.SubjectAttribute, defaultEnterpriseLDAPSubjectAttributes)
	if subject == "" {
		subject = strings.TrimSpace(entry.DN)
	}
	email := strings.TrimSpace(strings.ToLower(firstEnterpriseLDAPAttribute(entry, cfg.EmailAttribute, defaultEnterpriseLDAPEmailAttributes)))
	displayName := firstEnterpriseLDAPAttribute(entry, cfg.DisplayNameAttribute, defaultEnterpriseLDAPDisplayNameAttributes)
	username := firstEnterpriseLDAPAttribute(entry, cfg.UsernameAttribute, defaultEnterpriseLDAPUsernameAttributes)

	profilePayload := map[string]any{
		"dn":         strings.TrimSpace(entry.DN),
		"attributes": attributes,
	}
	profileJSON, _ := json.Marshal(profilePayload)

	return &EnterpriseLDAPUserInfo{
		Subject:           subject,
		Email:             email,
		EmailVerified:     email != "",
		Name:              displayName,
		PreferredUsername: username,
		DN:                strings.TrimSpace(entry.DN),
		ProfileJSON:       string(profileJSON),
	}, nil
}

func firstEnterpriseLDAPAttribute(entry *ldap.Entry, preferred string, defaults []string) string {
	keys := make([]string, 0, len(defaults)+1)
	if preferred = strings.TrimSpace(preferred); preferred != "" {
		keys = append(keys, preferred)
	}
	keys = append(keys, defaults...)
	for _, key := range keys {
		if value := ldapEntryAttributeValue(entry, key); value != "" {
			return value
		}
	}
	return ""
}

func ldapEntryAttributeValue(entry *ldap.Entry, attr string) string {
	if entry == nil {
		return ""
	}
	attr = strings.TrimSpace(attr)
	if attr == "" {
		return ""
	}
	raw := entry.GetRawAttributeValue(attr)
	if len(raw) == 0 {
		return ""
	}
	if utf8.Valid(raw) {
		return strings.TrimSpace(string(raw))
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (m *EnterpriseLDAPManager) findOrCreateUser(provider *EnterpriseLDAPProvider, info *EnterpriseLDAPUserInfo) (*auth.User, error) {
	result, err := m.findOrCreateUserWithResult(provider, info)
	if err != nil {
		return nil, err
	}
	return result.User, nil
}

func (m *EnterpriseLDAPManager) findOrCreateUserWithResult(provider *EnterpriseLDAPProvider, info *EnterpriseLDAPUserInfo) (*EnterpriseAuthenticationResult, error) {
	var identity ExternalIdentity
	err := m.db.Where("provider_type = ? AND provider_id = ? AND subject = ?", IdentityProviderTypeLDAP, provider.cfg.Slug, info.Subject).First(&identity).Error
	switch err {
	case nil:
		user, err := m.updateExistingIdentity(provider, &identity, info)
		return &EnterpriseAuthenticationResult{User: user}, err
	case gorm.ErrRecordNotFound:
		return m.createIdentityUserWithResult(provider, info)
	default:
		return nil, err
	}
}

func (m *EnterpriseLDAPManager) updateExistingIdentity(provider *EnterpriseLDAPProvider, identity *ExternalIdentity, info *EnterpriseLDAPUserInfo) (*auth.User, error) {
	now := time.Now()
	updates := map[string]any{
		"email":          info.Email,
		"email_verified": info.EmailVerified,
		"display_name":   enterpriseLDAPDisplayName(info),
		"profile_json":   info.ProfileJSON,
		"last_login_at":  &now,
		"updated_at":     now,
	}
	var user auth.User
	if err := m.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(identity).Updates(updates).Error; err != nil {
			return err
		}
		if err := upsertMembership(tx, provider.cfg.OrganizationID, identity.UserID); err != nil {
			return err
		}
		if err := m.syncEnterpriseLDAPGroups(tx, provider, identity.UserID, info.Groups, now); err != nil {
			return err
		}
		return tx.First(&user, "user_id = ?", identity.UserID).Error
	}); err != nil {
		return nil, err
	}
	return &user, nil
}

func (m *EnterpriseLDAPManager) createIdentityUser(provider *EnterpriseLDAPProvider, info *EnterpriseLDAPUserInfo) (*auth.User, error) {
	result, err := m.createIdentityUserWithResult(provider, info)
	if err != nil {
		return nil, err
	}
	return result.User, nil
}

func (m *EnterpriseLDAPManager) createIdentityUserWithResult(provider *EnterpriseLDAPProvider, info *EnterpriseLDAPUserInfo) (*EnterpriseAuthenticationResult, error) {
	if existingUserID, err := m.lookupVerifiedEmailUserID(info); err != nil {
		return nil, err
	} else if existingUserID != "" {
		user, err := m.linkExistingUser(provider, existingUserID, info)
		return &EnterpriseAuthenticationResult{User: user}, err
	}
	user, err := m.createNewUser(provider, info)
	return &EnterpriseAuthenticationResult{User: user, Created: true}, err
}

func (m *EnterpriseLDAPManager) linkExistingUser(provider *EnterpriseLDAPProvider, userID string, info *EnterpriseLDAPUserInfo) (*auth.User, error) {
	identityID, err := m.service.GenerateExternalIdentityID()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	identity := ExternalIdentity{
		ExternalIdentityID: identityID,
		ProviderType:       IdentityProviderTypeLDAP,
		ProviderID:         provider.cfg.Slug,
		Subject:            info.Subject,
		UserID:             userID,
		OrganizationID:     provider.cfg.OrganizationID,
		Email:              info.Email,
		EmailVerified:      info.EmailVerified,
		DisplayName:        enterpriseLDAPDisplayName(info),
		ProfileJSON:        info.ProfileJSON,
		LastLoginAt:        &now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := m.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&identity).Error; err != nil {
			return err
		}
		if err := upsertMembership(tx, provider.cfg.OrganizationID, userID); err != nil {
			return err
		}
		return m.syncEnterpriseLDAPGroups(tx, provider, userID, info.Groups, now)
	}); err != nil {
		return nil, err
	}

	var user auth.User
	if err := m.db.First(&user, "user_id = ?", userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (m *EnterpriseLDAPManager) createNewUser(provider *EnterpriseLDAPProvider, info *EnterpriseLDAPUserInfo) (*auth.User, error) {
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
		return nil, fmt.Errorf("generate enterprise ldap user password: %w", err)
	}
	hashedPassword, err := bcrypt.GenerateFromPassword(randomPassword, bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash enterprise ldap user password: %w", err)
	}

	now := time.Now()
	user := auth.User{
		UserID:       userID,
		Password:     string(hashedPassword),
		TokenVersion: auth.DefaultTokenVersion,
		Status:       auth.UserStatusActive,
		Nickname:     enterpriseLDAPFallbackNickname(info, userID),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	identity := ExternalIdentity{
		ExternalIdentityID: identityID,
		ProviderType:       IdentityProviderTypeLDAP,
		ProviderID:         provider.cfg.Slug,
		Subject:            info.Subject,
		UserID:             userID,
		OrganizationID:     provider.cfg.OrganizationID,
		Email:              info.Email,
		EmailVerified:      info.EmailVerified,
		DisplayName:        enterpriseLDAPDisplayName(info),
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
		if err := upsertMembership(tx, provider.cfg.OrganizationID, userID); err != nil {
			return err
		}
		return m.syncEnterpriseLDAPGroups(tx, provider, userID, info.Groups, now)
	}); err != nil {
		return nil, err
	}
	return &user, nil
}

func (m *EnterpriseLDAPManager) lookupVerifiedEmailUserID(info *EnterpriseLDAPUserInfo) (string, error) {
	if info == nil || !info.EmailVerified || strings.TrimSpace(info.Email) == "" {
		return "", nil
	}
	if !m.db.Migrator().HasTable(&auth.EmailUser{}) {
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

func enterpriseLDAPDisplayName(info *EnterpriseLDAPUserInfo) string {
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
	if value := strings.TrimSpace(info.DN); value != "" {
		return value
	}
	return ""
}

func enterpriseLDAPFallbackNickname(info *EnterpriseLDAPUserInfo, fallback string) string {
	if name := enterpriseLDAPDisplayName(info); name != "" {
		return name
	}
	return fallback
}
