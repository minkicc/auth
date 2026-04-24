package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

var defaultAdminOIDCScopes = []string{"openid", "profile", "email"}

type organizationIdentityProviderPayload struct {
	ProviderType string   `json:"provider_type"`
	Name         string   `json:"name"`
	Slug         string   `json:"slug"`
	Enabled      *bool    `json:"enabled"`
	Priority     *int     `json:"priority"`
	IsDefault    *bool    `json:"is_default"`
	AutoRedirect *bool    `json:"auto_redirect"`
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURI  string   `json:"redirect_uri"`
	Scopes       []string `json:"scopes"`
}

type organizationIdentityProviderConfigView struct {
	Issuer                 string   `json:"issuer"`
	ClientID               string   `json:"client_id"`
	RedirectURI            string   `json:"redirect_uri"`
	Scopes                 []string `json:"scopes"`
	ClientSecretConfigured bool     `json:"client_secret_configured"`
}

type organizationIdentityProviderView struct {
	IdentityProviderID string                                 `json:"identity_provider_id"`
	OrganizationID     string                                 `json:"organization_id"`
	ProviderType       string                                 `json:"provider_type"`
	Name               string                                 `json:"name"`
	Slug               string                                 `json:"slug"`
	Enabled            bool                                   `json:"enabled"`
	Priority           int                                    `json:"priority"`
	IsDefault          bool                                   `json:"is_default"`
	AutoRedirect       bool                                   `json:"auto_redirect"`
	Config             organizationIdentityProviderConfigView `json:"config"`
	CreatedAt          time.Time                              `json:"created_at"`
	UpdatedAt          time.Time                              `json:"updated_at"`
}

func (s *AdminServer) handleListOrganizationIdentityProviders(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	var providers []iam.OrganizationIdentityProvider
	if err := s.db.Where("organization_id = ?", org.OrganizationID).
		Order("is_default DESC").
		Order("auto_redirect DESC").
		Order("priority ASC").
		Order("created_at DESC").
		Find(&providers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	views := make([]organizationIdentityProviderView, 0, len(providers))
	for _, provider := range providers {
		view, err := organizationIdentityProviderToView(provider)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		views = append(views, view)
	}
	c.JSON(http.StatusOK, gin.H{"identity_providers": views})
}

func (s *AdminServer) handleCreateOrganizationIdentityProvider(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	var req organizationIdentityProviderPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity provider payload"})
		return
	}
	record, err := s.organizationIdentityProviderFromPayload(org.OrganizationID, req, nil)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	record.IdentityProviderID, err = iam.NewService(s.db).GenerateIdentityProviderID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.Create(&record).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.reloadEnterpriseOIDC(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	view, err := organizationIdentityProviderToView(record)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"identity_provider": view})
}

func (s *AdminServer) handleUpdateOrganizationIdentityProvider(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	current, ok := s.loadOrganizationIdentityProvider(c, org.OrganizationID, c.Param("provider_id"))
	if !ok {
		return
	}
	var req organizationIdentityProviderPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity provider payload"})
		return
	}
	updated, err := s.organizationIdentityProviderFromPayload(org.OrganizationID, req, &current)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.Save(&updated).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.reloadEnterpriseOIDC(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	view, err := organizationIdentityProviderToView(updated)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"identity_provider": view})
}

func (s *AdminServer) handleDeleteOrganizationIdentityProvider(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	record, ok := s.loadOrganizationIdentityProvider(c, org.OrganizationID, c.Param("provider_id"))
	if !ok {
		return
	}
	if err := s.db.Delete(&iam.OrganizationIdentityProvider{}, "identity_provider_id = ?", record.IdentityProviderID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.reloadEnterpriseOIDC(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "organization identity provider deleted successfully"})
}

func (s *AdminServer) organizationIdentityProviderFromPayload(organizationID string, req organizationIdentityProviderPayload, current *iam.OrganizationIdentityProvider) (iam.OrganizationIdentityProvider, error) {
	providerType := strings.TrimSpace(strings.ToLower(req.ProviderType))
	if providerType == "" {
		providerType = string(iam.IdentityProviderTypeOIDC)
	}
	if providerType != string(iam.IdentityProviderTypeOIDC) {
		return iam.OrganizationIdentityProvider{}, fmt.Errorf("unsupported identity provider type %q", providerType)
	}

	slug := normalizeIdentityProviderSlug(req.Slug)
	if !organizationSlugPattern.MatchString(slug) {
		return iam.OrganizationIdentityProvider{}, fmt.Errorf("slug must use lowercase letters, numbers, and hyphens")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return iam.OrganizationIdentityProvider{}, fmt.Errorf("name is required")
	}

	currentID := ""
	existingConfig := config.EnterpriseOIDCProviderConfig{}
	if current != nil {
		currentID = current.IdentityProviderID
		decoded, err := decodeStoredEnterpriseOIDCConfig(*current)
		if err != nil {
			return iam.OrganizationIdentityProvider{}, err
		}
		existingConfig = decoded
	}
	if err := s.ensureIdentityProviderSlugAvailable(slug, currentID); err != nil {
		return iam.OrganizationIdentityProvider{}, err
	}

	clientSecret := strings.TrimSpace(req.ClientSecret)
	if clientSecret == "" {
		clientSecret = strings.TrimSpace(existingConfig.ClientSecret)
	}

	providerConfig := config.EnterpriseOIDCProviderConfig{
		Slug:           slug,
		Name:           name,
		OrganizationID: organizationID,
		Issuer:         strings.TrimSpace(req.Issuer),
		ClientID:       strings.TrimSpace(req.ClientID),
		ClientSecret:   clientSecret,
		RedirectURI:    strings.TrimSpace(req.RedirectURI),
		Scopes:         normalizeIdentityProviderScopes(req.Scopes),
	}
	if _, err := iam.NewEnterpriseOIDCProvider(providerConfig); err != nil {
		return iam.OrganizationIdentityProvider{}, err
	}

	storedConfig := config.EnterpriseOIDCProviderConfig{
		Issuer:       providerConfig.Issuer,
		ClientID:     providerConfig.ClientID,
		ClientSecret: providerConfig.ClientSecret,
		RedirectURI:  providerConfig.RedirectURI,
		Scopes:       providerConfig.Scopes,
	}
	configJSON, err := json.Marshal(storedConfig)
	if err != nil {
		return iam.OrganizationIdentityProvider{}, err
	}

	enabled := true
	if current != nil {
		enabled = current.Enabled
	}
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	priority := iam.DefaultIdentityProviderPriority
	if current != nil {
		priority = current.Priority
	}
	if req.Priority != nil {
		priority = *req.Priority
	}
	if priority < 0 {
		return iam.OrganizationIdentityProvider{}, fmt.Errorf("priority must be greater than or equal to 0")
	}

	isDefault := false
	if current != nil {
		isDefault = current.IsDefault
	}
	if req.IsDefault != nil {
		isDefault = *req.IsDefault
	}

	autoRedirect := false
	if current != nil {
		autoRedirect = current.AutoRedirect
	}
	if req.AutoRedirect != nil {
		autoRedirect = *req.AutoRedirect
	}

	if current != nil {
		current.OrganizationID = organizationID
		current.ProviderType = iam.IdentityProviderType(providerType)
		current.Name = name
		current.Slug = slug
		current.Enabled = enabled
		current.Priority = priority
		current.IsDefault = isDefault
		current.AutoRedirect = autoRedirect
		current.ConfigJSON = string(configJSON)
		return *current, nil
	}

	return iam.OrganizationIdentityProvider{
		OrganizationID: organizationID,
		ProviderType:   iam.IdentityProviderType(providerType),
		Name:           name,
		Slug:           slug,
		Enabled:        enabled,
		Priority:       priority,
		IsDefault:      isDefault,
		AutoRedirect:   autoRedirect,
		ConfigJSON:     string(configJSON),
	}, nil
}

func (s *AdminServer) ensureIdentityProviderSlugAvailable(slug, currentID string) error {
	if s.enterpriseOIDC != nil && s.enterpriseOIDC.HasStaticProviderSlug(slug) {
		return fmt.Errorf("slug %q is reserved by static enterprise oidc configuration", slug)
	}
	query := s.db.Model(&iam.OrganizationIdentityProvider{}).Where("slug = ?", slug)
	if currentID != "" {
		query = query.Where("identity_provider_id <> ?", currentID)
	}
	var count int64
	if err := query.Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("slug %q already exists", slug)
	}
	return nil
}

func (s *AdminServer) loadOrganizationIdentityProvider(c *gin.Context, organizationID, idOrSlug string) (iam.OrganizationIdentityProvider, bool) {
	key := strings.TrimSpace(idOrSlug)
	var record iam.OrganizationIdentityProvider
	err := s.db.First(&record, "(identity_provider_id = ? OR slug = ?) AND organization_id = ?", key, strings.ToLower(key), organizationID).Error
	if err != nil {
		writeNotFoundOrError(c, err, "organization identity provider was not found")
		return iam.OrganizationIdentityProvider{}, false
	}
	return record, true
}

func (s *AdminServer) reloadEnterpriseOIDC() error {
	if s.enterpriseOIDC == nil {
		return nil
	}
	return s.enterpriseOIDC.Reload()
}

func organizationIdentityProviderToView(record iam.OrganizationIdentityProvider) (organizationIdentityProviderView, error) {
	storedConfig, err := decodeStoredEnterpriseOIDCConfig(record)
	if err != nil {
		return organizationIdentityProviderView{}, err
	}
	scopes := normalizeIdentityProviderScopes(storedConfig.Scopes)
	return organizationIdentityProviderView{
		IdentityProviderID: record.IdentityProviderID,
		OrganizationID:     record.OrganizationID,
		ProviderType:       string(record.ProviderType),
		Name:               record.Name,
		Slug:               record.Slug,
		Enabled:            record.Enabled,
		Priority:           record.Priority,
		IsDefault:          record.IsDefault,
		AutoRedirect:       record.AutoRedirect,
		Config: organizationIdentityProviderConfigView{
			Issuer:                 strings.TrimSpace(storedConfig.Issuer),
			ClientID:               strings.TrimSpace(storedConfig.ClientID),
			RedirectURI:            strings.TrimSpace(storedConfig.RedirectURI),
			Scopes:                 scopes,
			ClientSecretConfigured: strings.TrimSpace(storedConfig.ClientSecret) != "",
		},
		CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt,
	}, nil
}

func decodeStoredEnterpriseOIDCConfig(record iam.OrganizationIdentityProvider) (config.EnterpriseOIDCProviderConfig, error) {
	if strings.TrimSpace(record.ConfigJSON) == "" {
		return config.EnterpriseOIDCProviderConfig{}, fmt.Errorf("identity provider %q is missing config", record.Slug)
	}
	var providerConfig config.EnterpriseOIDCProviderConfig
	if err := json.Unmarshal([]byte(record.ConfigJSON), &providerConfig); err != nil {
		return config.EnterpriseOIDCProviderConfig{}, fmt.Errorf("decode identity provider %q config: %w", record.Slug, err)
	}
	return providerConfig, nil
}

func normalizeIdentityProviderSlug(raw string) string {
	return strings.TrimSpace(strings.ToLower(raw))
}

func normalizeIdentityProviderScopes(raw []string) []string {
	seen := map[string]struct{}{}
	scopes := make([]string, 0, len(raw))
	for _, scope := range raw {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		key := strings.ToLower(scope)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		scopes = append(scopes, scope)
	}
	if len(scopes) == 0 {
		scopes = append(scopes, defaultAdminOIDCScopes...)
	}
	sort.Strings(scopes)
	return scopes
}
