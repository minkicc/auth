package admin

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
	"minki.cc/mkauth/server/secureconfig"
)

var defaultAdminOIDCScopes = []string{"openid", "profile", "email"}

type organizationIdentityProviderPayload struct {
	ProviderType         string   `json:"provider_type"`
	Name                 string   `json:"name"`
	Slug                 string   `json:"slug"`
	Enabled              *bool    `json:"enabled"`
	Priority             *int     `json:"priority"`
	IsDefault            *bool    `json:"is_default"`
	AutoRedirect         *bool    `json:"auto_redirect"`
	Issuer               string   `json:"issuer"`
	ClientID             string   `json:"client_id"`
	ClientSecret         string   `json:"client_secret"`
	RedirectURI          string   `json:"redirect_uri"`
	Scopes               []string `json:"scopes"`
	IDPMetadataURL       string   `json:"idp_metadata_url"`
	IDPMetadataXML       string   `json:"idp_metadata_xml"`
	EntityID             string   `json:"entity_id"`
	ACSURL               string   `json:"acs_url"`
	NameIDFormat         string   `json:"name_id_format"`
	EmailAttribute       string   `json:"email_attribute"`
	UsernameAttribute    string   `json:"username_attribute"`
	DisplayNameAttribute string   `json:"display_name_attribute"`
	AllowIDPInitiated    *bool    `json:"allow_idp_initiated"`
	DefaultRedirectURI   string   `json:"default_redirect_uri"`
	URL                  string   `json:"url"`
	BaseDN               string   `json:"base_dn"`
	BindDN               string   `json:"bind_dn"`
	BindPassword         string   `json:"bind_password"`
	UserFilter           string   `json:"user_filter"`
	GroupBaseDN          string   `json:"group_base_dn"`
	GroupFilter          string   `json:"group_filter"`
	GroupMemberAttribute string   `json:"group_member_attribute"`
	GroupIdentifierAttr  string   `json:"group_identifier_attribute"`
	GroupNameAttribute   string   `json:"group_name_attribute"`
	StartTLS             *bool    `json:"start_tls"`
	InsecureSkipVerify   *bool    `json:"insecure_skip_verify"`
	SubjectAttribute     string   `json:"subject_attribute"`
}

type organizationIdentityProviderConfigView struct {
	Issuer                   string   `json:"issuer"`
	ClientID                 string   `json:"client_id"`
	RedirectURI              string   `json:"redirect_uri"`
	Scopes                   []string `json:"scopes"`
	ClientSecretConfigured   bool     `json:"client_secret_configured"`
	IDPMetadataURL           string   `json:"idp_metadata_url"`
	IDPMetadataXMLConfigured bool     `json:"idp_metadata_xml_configured"`
	EntityID                 string   `json:"entity_id"`
	ACSURL                   string   `json:"acs_url"`
	NameIDFormat             string   `json:"name_id_format"`
	EmailAttribute           string   `json:"email_attribute"`
	UsernameAttribute        string   `json:"username_attribute"`
	DisplayNameAttribute     string   `json:"display_name_attribute"`
	AllowIDPInitiated        bool     `json:"allow_idp_initiated"`
	DefaultRedirectURI       string   `json:"default_redirect_uri"`
	URL                      string   `json:"url"`
	BaseDN                   string   `json:"base_dn"`
	BindDN                   string   `json:"bind_dn"`
	BindPasswordConfigured   bool     `json:"bind_password_configured"`
	UserFilter               string   `json:"user_filter"`
	GroupBaseDN              string   `json:"group_base_dn"`
	GroupFilter              string   `json:"group_filter"`
	GroupMemberAttribute     string   `json:"group_member_attribute"`
	GroupIdentifierAttr      string   `json:"group_identifier_attribute"`
	GroupNameAttribute       string   `json:"group_name_attribute"`
	StartTLS                 bool     `json:"start_tls"`
	InsecureSkipVerify       bool     `json:"insecure_skip_verify"`
	SubjectAttribute         string   `json:"subject_attribute"`
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
	actor := pluginAuditActor(c)
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	var req organizationIdentityProviderPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		s.appendSecurityAudit(securityAuditActionIdentityProviderCreate, actor, false, err, map[string]string{
			"resource_type":   "identity_provider",
			"organization_id": org.OrganizationID,
			"stage":           "bind_payload",
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity provider payload"})
		return
	}
	record, err := s.organizationIdentityProviderFromPayload(org.OrganizationID, req, nil)
	if err != nil {
		s.appendSecurityAudit(securityAuditActionIdentityProviderCreate, actor, false, err, securityAuditDetailsWithExtras(map[string]string{
			"resource_type":   "identity_provider",
			"organization_id": org.OrganizationID,
			"provider_type":   strings.TrimSpace(strings.ToLower(req.ProviderType)),
			"slug":            normalizeIdentityProviderSlug(req.Slug),
			"name":            strings.TrimSpace(req.Name),
		}, map[string]string{
			"stage": "config_validation",
		}))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	record.IdentityProviderID, err = iam.NewService(s.db).GenerateIdentityProviderID()
	if err != nil {
		s.appendSecurityAudit(securityAuditActionIdentityProviderCreate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForIdentityProviderRecord(record), map[string]string{
			"stage": "generate_identity_provider_id",
		}))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.Create(&record).Error; err != nil {
		s.appendSecurityAudit(securityAuditActionIdentityProviderCreate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForIdentityProviderRecord(record), map[string]string{
			"stage": "persist_record",
		}))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.reloadEnterpriseIdentityProviders(); err != nil {
		s.appendSecurityAudit(securityAuditActionIdentityProviderCreate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForIdentityProviderRecord(record), map[string]string{
			"stage": "reload_enterprise_identity_providers",
		}))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	view, err := organizationIdentityProviderToView(record)
	if err != nil {
		s.appendSecurityAudit(securityAuditActionIdentityProviderCreate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForIdentityProviderRecord(record), map[string]string{
			"stage": "load_view",
		}))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.appendSecurityAudit(securityAuditActionIdentityProviderCreate, actor, true, nil, securityAuditDetailsForIdentityProviderView(view, ""))
	c.JSON(http.StatusCreated, gin.H{"identity_provider": view})
}

func (s *AdminServer) handleUpdateOrganizationIdentityProvider(c *gin.Context) {
	actor := pluginAuditActor(c)
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
		s.appendSecurityAudit(securityAuditActionIdentityProviderUpdate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForIdentityProviderRecord(current), map[string]string{
			"stage": "bind_payload",
		}))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity provider payload"})
		return
	}
	updated, err := s.organizationIdentityProviderFromPayload(org.OrganizationID, req, &current)
	if err != nil {
		s.appendSecurityAudit(securityAuditActionIdentityProviderUpdate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForIdentityProviderRecord(current), map[string]string{
			"requested_slug": normalizeIdentityProviderSlug(req.Slug),
			"stage":          "config_validation",
		}))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.Save(&updated).Error; err != nil {
		s.appendSecurityAudit(securityAuditActionIdentityProviderUpdate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForIdentityProviderRecord(updated), map[string]string{
			"stage": "persist_record",
		}))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.reloadEnterpriseIdentityProviders(); err != nil {
		s.appendSecurityAudit(securityAuditActionIdentityProviderUpdate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForIdentityProviderRecord(updated), map[string]string{
			"stage": "reload_enterprise_identity_providers",
		}))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	view, err := organizationIdentityProviderToView(updated)
	if err != nil {
		s.appendSecurityAudit(securityAuditActionIdentityProviderUpdate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForIdentityProviderRecord(updated), map[string]string{
			"stage": "load_view",
		}))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.appendSecurityAudit(securityAuditActionIdentityProviderUpdate, actor, true, nil, securityAuditDetailsForIdentityProviderView(view, current.Slug))
	c.JSON(http.StatusOK, gin.H{"identity_provider": view})
}

func (s *AdminServer) handleDeleteOrganizationIdentityProvider(c *gin.Context) {
	actor := pluginAuditActor(c)
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	record, ok := s.loadOrganizationIdentityProvider(c, org.OrganizationID, c.Param("provider_id"))
	if !ok {
		return
	}
	if err := s.db.Delete(&iam.OrganizationIdentityProvider{}, "identity_provider_id = ?", record.IdentityProviderID).Error; err != nil {
		s.appendSecurityAudit(securityAuditActionIdentityProviderDelete, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForIdentityProviderRecord(record), map[string]string{
			"stage": "delete_record",
		}))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.reloadEnterpriseIdentityProviders(); err != nil {
		s.appendSecurityAudit(securityAuditActionIdentityProviderDelete, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForIdentityProviderRecord(record), map[string]string{
			"stage": "reload_enterprise_identity_providers",
		}))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.appendSecurityAudit(securityAuditActionIdentityProviderDelete, actor, true, nil, securityAuditDetailsForIdentityProviderRecord(record))
	c.JSON(http.StatusOK, gin.H{"message": "organization identity provider deleted successfully"})
}

func (s *AdminServer) organizationIdentityProviderFromPayload(organizationID string, req organizationIdentityProviderPayload, current *iam.OrganizationIdentityProvider) (iam.OrganizationIdentityProvider, error) {
	providerType := strings.TrimSpace(strings.ToLower(req.ProviderType))
	if providerType == "" {
		providerType = string(iam.IdentityProviderTypeOIDC)
	}
	if providerType != string(iam.IdentityProviderTypeOIDC) &&
		providerType != string(iam.IdentityProviderTypeSAML) &&
		providerType != string(iam.IdentityProviderTypeLDAP) {
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
	if current != nil {
		currentID = current.IdentityProviderID
	}
	if err := s.ensureIdentityProviderSlugAvailable(slug, currentID); err != nil {
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

	var configJSON []byte
	switch providerType {
	case string(iam.IdentityProviderTypeOIDC):
		existingConfig := config.EnterpriseOIDCProviderConfig{}
		if current != nil && current.ProviderType == iam.IdentityProviderTypeOIDC {
			decoded, err := decodeStoredEnterpriseOIDCConfig(*current)
			if err != nil {
				return iam.OrganizationIdentityProvider{}, err
			}
			existingConfig = decoded
		}
		clientSecret := strings.TrimSpace(req.ClientSecret)
		if clientSecret == "" {
			clientSecret = strings.TrimSpace(existingConfig.ClientSecret)
		}

		providerConfig := config.EnterpriseOIDCProviderConfig{
			Slug:           slug,
			Name:           name,
			OrganizationID: organizationID,
			Priority:       priority,
			IsDefault:      isDefault,
			AutoRedirect:   autoRedirect,
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
		encoded, err := encodeStoredEnterpriseOIDCConfig(storedConfig)
		if err != nil {
			return iam.OrganizationIdentityProvider{}, err
		}
		configJSON = []byte(encoded)
	case string(iam.IdentityProviderTypeSAML):
		existingConfig := config.EnterpriseSAMLProviderConfig{}
		if current != nil && current.ProviderType == iam.IdentityProviderTypeSAML {
			decoded, err := decodeStoredEnterpriseSAMLConfig(*current)
			if err != nil {
				return iam.OrganizationIdentityProvider{}, err
			}
			existingConfig = decoded
		}

		idpMetadataURL := strings.TrimSpace(req.IDPMetadataURL)
		if idpMetadataURL == "" {
			idpMetadataURL = strings.TrimSpace(existingConfig.IDPMetadataURL)
		}
		idpMetadataXML := strings.TrimSpace(req.IDPMetadataXML)
		if idpMetadataXML == "" {
			idpMetadataXML = strings.TrimSpace(existingConfig.IDPMetadataXML)
		}

		allowIDPInitiated := existingConfig.AllowIDPInitiated
		if req.AllowIDPInitiated != nil {
			allowIDPInitiated = *req.AllowIDPInitiated
		}

		providerConfig := config.EnterpriseSAMLProviderConfig{
			Slug:                 slug,
			Name:                 name,
			OrganizationID:       organizationID,
			Priority:             priority,
			IsDefault:            isDefault,
			AutoRedirect:         autoRedirect,
			IDPMetadataURL:       idpMetadataURL,
			IDPMetadataXML:       idpMetadataXML,
			EntityID:             strings.TrimSpace(req.EntityID),
			ACSURL:               strings.TrimSpace(req.ACSURL),
			NameIDFormat:         strings.TrimSpace(req.NameIDFormat),
			EmailAttribute:       strings.TrimSpace(req.EmailAttribute),
			UsernameAttribute:    strings.TrimSpace(req.UsernameAttribute),
			DisplayNameAttribute: strings.TrimSpace(req.DisplayNameAttribute),
			AllowIDPInitiated:    allowIDPInitiated,
			DefaultRedirectURI:   strings.TrimSpace(req.DefaultRedirectURI),
		}
		if _, err := iam.NewEnterpriseSAMLProvider(providerConfig, s.publicBaseURL); err != nil {
			return iam.OrganizationIdentityProvider{}, err
		}

		storedConfig := config.EnterpriseSAMLProviderConfig{
			IDPMetadataURL:       providerConfig.IDPMetadataURL,
			IDPMetadataXML:       providerConfig.IDPMetadataXML,
			EntityID:             providerConfig.EntityID,
			ACSURL:               providerConfig.ACSURL,
			NameIDFormat:         providerConfig.NameIDFormat,
			EmailAttribute:       providerConfig.EmailAttribute,
			UsernameAttribute:    providerConfig.UsernameAttribute,
			DisplayNameAttribute: providerConfig.DisplayNameAttribute,
			AllowIDPInitiated:    providerConfig.AllowIDPInitiated,
			DefaultRedirectURI:   providerConfig.DefaultRedirectURI,
		}
		encoded, err := encodeStoredEnterpriseSAMLConfig(storedConfig)
		if err != nil {
			return iam.OrganizationIdentityProvider{}, err
		}
		configJSON = []byte(encoded)
	case string(iam.IdentityProviderTypeLDAP):
		existingConfig := config.EnterpriseLDAPProviderConfig{}
		if current != nil && current.ProviderType == iam.IdentityProviderTypeLDAP {
			decoded, err := decodeStoredEnterpriseLDAPConfig(*current)
			if err != nil {
				return iam.OrganizationIdentityProvider{}, err
			}
			existingConfig = decoded
		}

		bindPassword := strings.TrimSpace(req.BindPassword)
		if bindPassword == "" {
			bindPassword = strings.TrimSpace(existingConfig.BindPassword)
		}

		startTLS := existingConfig.StartTLS
		if req.StartTLS != nil {
			startTLS = *req.StartTLS
		}

		insecureSkipVerify := existingConfig.InsecureSkipVerify
		if req.InsecureSkipVerify != nil {
			insecureSkipVerify = *req.InsecureSkipVerify
		}

		providerConfig := config.EnterpriseLDAPProviderConfig{
			Slug:                 slug,
			Name:                 name,
			OrganizationID:       organizationID,
			Priority:             priority,
			IsDefault:            isDefault,
			AutoRedirect:         autoRedirect,
			URL:                  strings.TrimSpace(req.URL),
			BaseDN:               strings.TrimSpace(req.BaseDN),
			BindDN:               strings.TrimSpace(req.BindDN),
			BindPassword:         bindPassword,
			UserFilter:           strings.TrimSpace(req.UserFilter),
			GroupBaseDN:          strings.TrimSpace(req.GroupBaseDN),
			GroupFilter:          strings.TrimSpace(req.GroupFilter),
			GroupMemberAttribute: strings.TrimSpace(req.GroupMemberAttribute),
			GroupIdentifierAttr:  strings.TrimSpace(req.GroupIdentifierAttr),
			GroupNameAttribute:   strings.TrimSpace(req.GroupNameAttribute),
			StartTLS:             startTLS,
			InsecureSkipVerify:   insecureSkipVerify,
			SubjectAttribute:     strings.TrimSpace(req.SubjectAttribute),
			EmailAttribute:       strings.TrimSpace(req.EmailAttribute),
			UsernameAttribute:    strings.TrimSpace(req.UsernameAttribute),
			DisplayNameAttribute: strings.TrimSpace(req.DisplayNameAttribute),
		}
		if _, err := iam.NewEnterpriseLDAPProvider(providerConfig, nil); err != nil {
			return iam.OrganizationIdentityProvider{}, err
		}

		storedConfig := config.EnterpriseLDAPProviderConfig{
			URL:                  providerConfig.URL,
			BaseDN:               providerConfig.BaseDN,
			BindDN:               providerConfig.BindDN,
			BindPassword:         providerConfig.BindPassword,
			UserFilter:           providerConfig.UserFilter,
			GroupBaseDN:          providerConfig.GroupBaseDN,
			GroupFilter:          providerConfig.GroupFilter,
			GroupMemberAttribute: providerConfig.GroupMemberAttribute,
			GroupIdentifierAttr:  providerConfig.GroupIdentifierAttr,
			GroupNameAttribute:   providerConfig.GroupNameAttribute,
			StartTLS:             providerConfig.StartTLS,
			InsecureSkipVerify:   providerConfig.InsecureSkipVerify,
			SubjectAttribute:     providerConfig.SubjectAttribute,
			EmailAttribute:       providerConfig.EmailAttribute,
			UsernameAttribute:    providerConfig.UsernameAttribute,
			DisplayNameAttribute: providerConfig.DisplayNameAttribute,
		}
		encoded, err := encodeStoredEnterpriseLDAPConfig(storedConfig)
		if err != nil {
			return iam.OrganizationIdentityProvider{}, err
		}
		configJSON = []byte(encoded)
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
	if s.enterpriseSAML != nil && s.enterpriseSAML.HasStaticProviderSlug(slug) {
		return fmt.Errorf("slug %q is reserved by static enterprise saml configuration", slug)
	}
	if s.enterpriseLDAP != nil && s.enterpriseLDAP.HasStaticProviderSlug(slug) {
		return fmt.Errorf("slug %q is reserved by static enterprise ldap configuration", slug)
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

func (s *AdminServer) reloadEnterpriseIdentityProviders() error {
	if s.enterpriseOIDC == nil {
		goto saml
	}
	if err := s.enterpriseOIDC.Reload(); err != nil {
		return err
	}
saml:
	if s.enterpriseSAML != nil {
		if err := s.enterpriseSAML.Reload(); err != nil {
			return err
		}
	}
	if s.enterpriseLDAP == nil {
		return nil
	}
	return s.enterpriseLDAP.Reload()
}

func organizationIdentityProviderToView(record iam.OrganizationIdentityProvider) (organizationIdentityProviderView, error) {
	view := organizationIdentityProviderView{
		IdentityProviderID: record.IdentityProviderID,
		OrganizationID:     record.OrganizationID,
		ProviderType:       string(record.ProviderType),
		Name:               record.Name,
		Slug:               record.Slug,
		Enabled:            record.Enabled,
		Priority:           record.Priority,
		IsDefault:          record.IsDefault,
		AutoRedirect:       record.AutoRedirect,
		CreatedAt:          record.CreatedAt,
		UpdatedAt:          record.UpdatedAt,
	}
	switch record.ProviderType {
	case iam.IdentityProviderTypeOIDC:
		storedConfig, err := decodeStoredEnterpriseOIDCConfig(record)
		if err != nil {
			return organizationIdentityProviderView{}, err
		}
		view.Config = organizationIdentityProviderConfigView{
			Issuer:                 strings.TrimSpace(storedConfig.Issuer),
			ClientID:               strings.TrimSpace(storedConfig.ClientID),
			RedirectURI:            strings.TrimSpace(storedConfig.RedirectURI),
			Scopes:                 normalizeIdentityProviderScopes(storedConfig.Scopes),
			ClientSecretConfigured: strings.TrimSpace(storedConfig.ClientSecret) != "",
		}
	case iam.IdentityProviderTypeSAML:
		storedConfig, err := decodeStoredEnterpriseSAMLConfig(record)
		if err != nil {
			return organizationIdentityProviderView{}, err
		}
		view.Config = organizationIdentityProviderConfigView{
			IDPMetadataURL:           strings.TrimSpace(storedConfig.IDPMetadataURL),
			IDPMetadataXMLConfigured: strings.TrimSpace(storedConfig.IDPMetadataXML) != "",
			EntityID:                 strings.TrimSpace(storedConfig.EntityID),
			ACSURL:                   strings.TrimSpace(storedConfig.ACSURL),
			NameIDFormat:             strings.TrimSpace(storedConfig.NameIDFormat),
			EmailAttribute:           strings.TrimSpace(storedConfig.EmailAttribute),
			UsernameAttribute:        strings.TrimSpace(storedConfig.UsernameAttribute),
			DisplayNameAttribute:     strings.TrimSpace(storedConfig.DisplayNameAttribute),
			AllowIDPInitiated:        storedConfig.AllowIDPInitiated,
			DefaultRedirectURI:       strings.TrimSpace(storedConfig.DefaultRedirectURI),
		}
	case iam.IdentityProviderTypeLDAP:
		storedConfig, err := decodeStoredEnterpriseLDAPConfig(record)
		if err != nil {
			return organizationIdentityProviderView{}, err
		}
		view.Config = organizationIdentityProviderConfigView{
			URL:                    strings.TrimSpace(storedConfig.URL),
			BaseDN:                 strings.TrimSpace(storedConfig.BaseDN),
			BindDN:                 strings.TrimSpace(storedConfig.BindDN),
			BindPasswordConfigured: strings.TrimSpace(storedConfig.BindPassword) != "",
			UserFilter:             strings.TrimSpace(storedConfig.UserFilter),
			GroupBaseDN:            strings.TrimSpace(storedConfig.GroupBaseDN),
			GroupFilter:            strings.TrimSpace(storedConfig.GroupFilter),
			GroupMemberAttribute:   strings.TrimSpace(storedConfig.GroupMemberAttribute),
			GroupIdentifierAttr:    strings.TrimSpace(storedConfig.GroupIdentifierAttr),
			GroupNameAttribute:     strings.TrimSpace(storedConfig.GroupNameAttribute),
			StartTLS:               storedConfig.StartTLS,
			InsecureSkipVerify:     storedConfig.InsecureSkipVerify,
			SubjectAttribute:       strings.TrimSpace(storedConfig.SubjectAttribute),
			EmailAttribute:         strings.TrimSpace(storedConfig.EmailAttribute),
			UsernameAttribute:      strings.TrimSpace(storedConfig.UsernameAttribute),
			DisplayNameAttribute:   strings.TrimSpace(storedConfig.DisplayNameAttribute),
		}
	}
	return view, nil
}

func decodeStoredEnterpriseOIDCConfig(record iam.OrganizationIdentityProvider) (config.EnterpriseOIDCProviderConfig, error) {
	if strings.TrimSpace(record.ConfigJSON) == "" {
		return config.EnterpriseOIDCProviderConfig{}, fmt.Errorf("identity provider %q is missing config", record.Slug)
	}
	var providerConfig config.EnterpriseOIDCProviderConfig
	if err := secureconfig.OpenJSON(record.ConfigJSON, &providerConfig); err != nil {
		return config.EnterpriseOIDCProviderConfig{}, fmt.Errorf("decode identity provider %q config: %w", record.Slug, err)
	}
	return providerConfig, nil
}

func encodeStoredEnterpriseOIDCConfig(providerConfig config.EnterpriseOIDCProviderConfig) (string, error) {
	return secureconfig.SealJSON(providerConfig)
}

func decodeStoredEnterpriseSAMLConfig(record iam.OrganizationIdentityProvider) (config.EnterpriseSAMLProviderConfig, error) {
	if strings.TrimSpace(record.ConfigJSON) == "" {
		return config.EnterpriseSAMLProviderConfig{}, fmt.Errorf("identity provider %q is missing config", record.Slug)
	}
	var providerConfig config.EnterpriseSAMLProviderConfig
	if err := secureconfig.OpenJSON(record.ConfigJSON, &providerConfig); err != nil {
		return config.EnterpriseSAMLProviderConfig{}, fmt.Errorf("decode identity provider %q config: %w", record.Slug, err)
	}
	return providerConfig, nil
}

func encodeStoredEnterpriseSAMLConfig(providerConfig config.EnterpriseSAMLProviderConfig) (string, error) {
	return secureconfig.SealJSON(providerConfig)
}

func decodeStoredEnterpriseLDAPConfig(record iam.OrganizationIdentityProvider) (config.EnterpriseLDAPProviderConfig, error) {
	if strings.TrimSpace(record.ConfigJSON) == "" {
		return config.EnterpriseLDAPProviderConfig{}, fmt.Errorf("identity provider %q is missing config", record.Slug)
	}
	var providerConfig config.EnterpriseLDAPProviderConfig
	if err := secureconfig.OpenJSON(record.ConfigJSON, &providerConfig); err != nil {
		return config.EnterpriseLDAPProviderConfig{}, fmt.Errorf("decode identity provider %q config: %w", record.Slug, err)
	}
	return providerConfig, nil
}

func encodeStoredEnterpriseLDAPConfig(providerConfig config.EnterpriseLDAPProviderConfig) (string, error) {
	return secureconfig.SealJSON(providerConfig)
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
