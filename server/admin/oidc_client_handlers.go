package admin

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/oidc"
)

type oidcClientPayload struct {
	Name                  string                                   `json:"name"`
	ClientID              string                                   `json:"client_id"`
	ClientSecret          string                                   `json:"client_secret"`
	GrantTypes            []string                                 `json:"grant_types"`
	ServiceAccountSubject string                                   `json:"service_account_subject"`
	RedirectURIs          []string                                 `json:"redirect_uris"`
	Scopes                []string                                 `json:"scopes"`
	Public                *bool                                    `json:"public"`
	RequirePKCE           *bool                                    `json:"require_pkce"`
	RequireOrganization   *bool                                    `json:"require_organization"`
	AllowedOrganizations  []string                                 `json:"allowed_organizations"`
	RequiredOrgRoles      []string                                 `json:"required_org_roles"`
	RequiredOrgRolesAll   []string                                 `json:"required_org_roles_all"`
	RequiredOrgGroups     []string                                 `json:"required_org_groups"`
	RequiredOrgGroupsAll  []string                                 `json:"required_org_groups_all"`
	ScopePolicies         map[string]config.OIDCOrganizationPolicy `json:"scope_policies"`
	Enabled               *bool                                    `json:"enabled"`
}

type oidcClientView struct {
	Name                   string                                   `json:"name,omitempty"`
	ClientID               string                                   `json:"client_id"`
	GrantTypes             []string                                 `json:"grant_types,omitempty"`
	ServiceAccountEnabled  bool                                     `json:"service_account_enabled"`
	ServiceAccountSubject  string                                   `json:"service_account_subject,omitempty"`
	RedirectURIs           []string                                 `json:"redirect_uris"`
	Scopes                 []string                                 `json:"scopes,omitempty"`
	Public                 bool                                     `json:"public"`
	RequirePKCE            bool                                     `json:"require_pkce"`
	RequireOrganization    bool                                     `json:"require_organization"`
	AllowedOrganizations   []string                                 `json:"allowed_organizations,omitempty"`
	RequiredOrgRoles       []string                                 `json:"required_org_roles,omitempty"`
	RequiredOrgRolesAll    []string                                 `json:"required_org_roles_all,omitempty"`
	RequiredOrgGroups      []string                                 `json:"required_org_groups,omitempty"`
	RequiredOrgGroupsAll   []string                                 `json:"required_org_groups_all,omitempty"`
	ScopePolicies          map[string]config.OIDCOrganizationPolicy `json:"scope_policies,omitempty"`
	Enabled                bool                                     `json:"enabled"`
	Editable               bool                                     `json:"editable"`
	Source                 string                                   `json:"source"`
	ClientSecretConfigured bool                                     `json:"client_secret_configured"`
	CreatedAt              *time.Time                               `json:"created_at,omitempty"`
	UpdatedAt              *time.Time                               `json:"updated_at,omitempty"`
}

func (s *AdminServer) handleListOIDCClients(c *gin.Context) {
	views, err := s.listOIDCClientViews()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"clients": views})
}

func (s *AdminServer) handleCreateOIDCClient(c *gin.Context) {
	actor := pluginAuditActor(c)
	var req oidcClientPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientCreate, actor, false, err, map[string]string{
			"resource_type": "oidc_client",
			"stage":         "bind_payload",
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid oidc client payload"})
		return
	}

	clientCfg, enabled, err := s.oidcClientConfigFromPayload(req, nil, nil)
	if err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientCreate, actor, false, err, securityAuditDetailsWithExtras(map[string]string{
			"resource_type": "oidc_client",
			"client_id":     strings.TrimSpace(req.ClientID),
			"name":          strings.TrimSpace(req.Name),
		}, map[string]string{
			"stage": "config_validation",
		}))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.ensureOIDCClientIDAvailable(clientCfg.ClientID, ""); err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientCreate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForOIDCClient(oidcClientViewFromConfig(clientCfg, enabled, true, "database", nil, nil), ""), map[string]string{
			"stage": "client_id_validation",
		}))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	record, err := oidc.ClientRecordFromConfig(clientCfg, enabled)
	if err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientCreate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForOIDCClient(oidcClientViewFromConfig(clientCfg, enabled, true, "database", nil, nil), ""), map[string]string{
			"stage": "record_encoding",
		}))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.Create(&record).Error; err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientCreate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForOIDCClient(oidcClientViewFromConfig(clientCfg, enabled, true, "database", nil, nil), ""), map[string]string{
			"stage": "persist_record",
		}))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.reloadOIDCClients(); err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientCreate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForOIDCClient(oidcClientViewFromConfig(clientCfg, enabled, true, "database", nil, nil), ""), map[string]string{
			"stage": "reload_oidc_clients",
		}))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	view, err := oidcClientViewFromRecord(record)
	if err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientCreate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForOIDCClient(oidcClientViewFromConfig(clientCfg, enabled, true, "database", nil, nil), ""), map[string]string{
			"stage": "load_view",
		}))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.appendSecurityAudit(securityAuditActionOIDCClientCreate, actor, true, nil, securityAuditDetailsForOIDCClient(view, ""))
	c.JSON(http.StatusCreated, gin.H{"client": view})
}

func (s *AdminServer) handleUpdateOIDCClient(c *gin.Context) {
	actor := pluginAuditActor(c)
	currentRecord, ok := s.loadOIDCClientRecord(c, c.Param("client_id"))
	if !ok {
		return
	}

	var req oidcClientPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientUpdate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForOIDCClientRecord(currentRecord), map[string]string{
			"stage": "bind_payload",
		}))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid oidc client payload"})
		return
	}

	currentCfg, err := oidc.ClientConfigFromRecord(currentRecord)
	if err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientUpdate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForOIDCClientRecord(currentRecord), map[string]string{
			"stage": "decode_current_config",
		}))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	updatedCfg, enabled, err := s.oidcClientConfigFromPayload(req, &currentCfg, &currentRecord)
	if err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientUpdate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForOIDCClientRecord(currentRecord), map[string]string{
			"requested_client_id": strings.TrimSpace(req.ClientID),
			"stage":               "config_validation",
		}))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.ensureOIDCClientIDAvailable(updatedCfg.ClientID, currentRecord.ClientID); err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientUpdate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForOIDCClient(oidcClientViewFromConfig(updatedCfg, enabled, true, "database", nil, nil), currentRecord.ClientID), map[string]string{
			"stage": "client_id_validation",
		}))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updatedRecord, err := oidc.ClientRecordFromConfig(updatedCfg, enabled)
	if err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientUpdate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForOIDCClient(oidcClientViewFromConfig(updatedCfg, enabled, true, "database", nil, nil), currentRecord.ClientID), map[string]string{
			"stage": "record_encoding",
		}))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updatedRecord.CreatedAt = currentRecord.CreatedAt
	if err := s.persistUpdatedOIDCClient(currentRecord.ClientID, updatedRecord); err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientUpdate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForOIDCClient(oidcClientViewFromConfig(updatedCfg, enabled, true, "database", nil, nil), currentRecord.ClientID), map[string]string{
			"stage": "persist_record",
		}))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.reloadOIDCClients(); err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientUpdate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForOIDCClient(oidcClientViewFromConfig(updatedCfg, enabled, true, "database", nil, nil), currentRecord.ClientID), map[string]string{
			"stage": "reload_oidc_clients",
		}))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.Where("client_id = ?", updatedRecord.ClientID).First(&updatedRecord).Error; err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientUpdate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForOIDCClient(oidcClientViewFromConfig(updatedCfg, enabled, true, "database", nil, nil), currentRecord.ClientID), map[string]string{
			"stage": "load_updated_record",
		}))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	view, err := oidcClientViewFromRecord(updatedRecord)
	if err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientUpdate, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForOIDCClient(oidcClientViewFromConfig(updatedCfg, enabled, true, "database", nil, nil), currentRecord.ClientID), map[string]string{
			"stage": "load_view",
		}))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.appendSecurityAudit(securityAuditActionOIDCClientUpdate, actor, true, nil, securityAuditDetailsForOIDCClient(view, currentRecord.ClientID))
	c.JSON(http.StatusOK, gin.H{"client": view})
}

func (s *AdminServer) handleDeleteOIDCClient(c *gin.Context) {
	actor := pluginAuditActor(c)
	record, ok := s.loadOIDCClientRecord(c, c.Param("client_id"))
	if !ok {
		return
	}
	if err := s.db.Delete(&oidc.ClientRecord{}, "client_id = ?", record.ClientID).Error; err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientDelete, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForOIDCClientRecord(record), map[string]string{
			"stage": "delete_record",
		}))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.reloadOIDCClients(); err != nil {
		s.appendSecurityAudit(securityAuditActionOIDCClientDelete, actor, false, err, securityAuditDetailsWithExtras(securityAuditDetailsForOIDCClientRecord(record), map[string]string{
			"stage": "reload_oidc_clients",
		}))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.appendSecurityAudit(securityAuditActionOIDCClientDelete, actor, true, nil, securityAuditDetailsForOIDCClientRecord(record))
	c.JSON(http.StatusOK, gin.H{"message": "oidc client deleted successfully"})
}

func (s *AdminServer) listOIDCClientViews() ([]oidcClientView, error) {
	views := make([]oidcClientView, 0, len(s.staticOIDCClients()))
	for _, client := range s.staticOIDCClients() {
		views = append(views, oidcClientViewFromConfig(client, true, false, "config", nil, nil))
	}

	var records []oidc.ClientRecord
	if err := s.db.Order("created_at ASC").Find(&records).Error; err != nil {
		return nil, err
	}
	for _, record := range records {
		view, err := oidcClientViewFromRecord(record)
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}

	sort.SliceStable(views, func(i, j int) bool {
		if views[i].Source != views[j].Source {
			return views[i].Source < views[j].Source
		}
		if views[i].Enabled != views[j].Enabled {
			return views[i].Enabled && !views[j].Enabled
		}
		leftName := views[i].Name
		if leftName == "" {
			leftName = views[i].ClientID
		}
		rightName := views[j].Name
		if rightName == "" {
			rightName = views[j].ClientID
		}
		if strings.EqualFold(leftName, rightName) {
			return views[i].ClientID < views[j].ClientID
		}
		return strings.ToLower(leftName) < strings.ToLower(rightName)
	})
	return views, nil
}

func (s *AdminServer) oidcClientConfigFromPayload(req oidcClientPayload, current *config.OIDCClientConfig, currentRecord *oidc.ClientRecord) (config.OIDCClientConfig, bool, error) {
	var clientCfg config.OIDCClientConfig
	if current != nil {
		clientCfg = *current
	}

	if current == nil || req.Name != "" {
		clientCfg.Name = strings.TrimSpace(req.Name)
	}
	if current == nil || req.ClientID != "" {
		clientCfg.ClientID = strings.TrimSpace(req.ClientID)
	}
	if current == nil || req.GrantTypes != nil {
		clientCfg.GrantTypes = req.GrantTypes
	}
	if current == nil || req.ServiceAccountSubject != "" {
		clientCfg.ServiceAccountSubject = strings.TrimSpace(req.ServiceAccountSubject)
	}
	if current == nil || req.RedirectURIs != nil {
		clientCfg.RedirectURIs = req.RedirectURIs
	}
	if current == nil || req.Scopes != nil {
		clientCfg.Scopes = req.Scopes
	}
	if req.Public != nil {
		clientCfg.Public = *req.Public
	}
	if req.RequirePKCE != nil {
		clientCfg.RequirePKCE = *req.RequirePKCE
	}
	if req.RequireOrganization != nil {
		clientCfg.RequireOrganization = *req.RequireOrganization
	}
	if current == nil || req.AllowedOrganizations != nil {
		clientCfg.AllowedOrganizations = req.AllowedOrganizations
	}
	if current == nil || req.RequiredOrgRoles != nil {
		clientCfg.RequiredOrgRoles = req.RequiredOrgRoles
	}
	if current == nil || req.RequiredOrgRolesAll != nil {
		clientCfg.RequiredOrgRolesAll = req.RequiredOrgRolesAll
	}
	if current == nil || req.RequiredOrgGroups != nil {
		clientCfg.RequiredOrgGroups = req.RequiredOrgGroups
	}
	if current == nil || req.RequiredOrgGroupsAll != nil {
		clientCfg.RequiredOrgGroupsAll = req.RequiredOrgGroupsAll
	}
	if current == nil || req.ScopePolicies != nil {
		clientCfg.ScopePolicies = req.ScopePolicies
	}
	if secret := strings.TrimSpace(req.ClientSecret); secret != "" {
		clientCfg.ClientSecret = secret
	}
	if current == nil {
		clientCfg = oidc.NormalizeClientConfig(clientCfg)
		if err := oidc.ValidateClientConfig(clientCfg); err != nil {
			return config.OIDCClientConfig{}, false, err
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		return clientCfg, enabled, nil
	}

	clientCfg = oidc.NormalizeClientConfig(clientCfg)
	if err := oidc.ValidateClientConfig(clientCfg); err != nil {
		return config.OIDCClientConfig{}, false, err
	}
	enabled := currentRecord != nil && currentRecord.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	return clientCfg, enabled, nil
}

func (s *AdminServer) loadOIDCClientRecord(c *gin.Context, clientID string) (oidc.ClientRecord, bool) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id is required"})
		return oidc.ClientRecord{}, false
	}
	if s.hasStaticOIDCClientID(clientID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "static oidc client is read-only"})
		return oidc.ClientRecord{}, false
	}
	var record oidc.ClientRecord
	if err := s.db.Where("client_id = ?", clientID).First(&record).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "oidc client not found"})
			return oidc.ClientRecord{}, false
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return oidc.ClientRecord{}, false
	}
	return record, true
}

func (s *AdminServer) ensureOIDCClientIDAvailable(clientID, currentID string) error {
	clientID = strings.TrimSpace(clientID)
	currentID = strings.TrimSpace(currentID)
	if clientID == "" {
		return errors.New("client_id is required")
	}
	if clientID != currentID && s.hasStaticOIDCClientID(clientID) {
		return errors.New("client_id is reserved by static configuration")
	}
	var count int64
	query := s.db.Model(&oidc.ClientRecord{}).Where("client_id = ?", clientID)
	if currentID != "" {
		query = query.Where("client_id <> ?", currentID)
	}
	if err := query.Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return errors.New("client_id already exists")
	}
	return nil
}

func (s *AdminServer) persistUpdatedOIDCClient(currentID string, updated oidc.ClientRecord) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if currentID == updated.ClientID {
			return tx.Save(&updated).Error
		}
		if err := tx.Create(&updated).Error; err != nil {
			return err
		}
		if err := tx.Delete(&oidc.ClientRecord{}, "client_id = ?", currentID).Error; err != nil {
			return err
		}
		return nil
	})
}

func (s *AdminServer) reloadOIDCClients() error {
	if s == nil || s.oidcProvider == nil {
		return nil
	}
	return s.oidcProvider.Reload()
}

func (s *AdminServer) staticOIDCClients() []config.OIDCClientConfig {
	if s == nil {
		return nil
	}
	if len(s.oidcStaticCfgs) > 0 {
		return append([]config.OIDCClientConfig(nil), s.oidcStaticCfgs...)
	}
	if s.oidcProvider != nil {
		return s.oidcProvider.StaticClients()
	}
	return nil
}

func (s *AdminServer) hasStaticOIDCClientID(clientID string) bool {
	clientID = strings.TrimSpace(clientID)
	for _, client := range s.staticOIDCClients() {
		if client.ClientID == clientID {
			return true
		}
	}
	return false
}

func oidcClientViewFromRecord(record oidc.ClientRecord) (oidcClientView, error) {
	clientCfg, err := oidc.ClientConfigFromRecord(record)
	if err != nil {
		return oidcClientView{}, err
	}
	return oidcClientViewFromConfig(clientCfg, record.Enabled, true, "database", &record.CreatedAt, &record.UpdatedAt), nil
}

func oidcClientViewFromConfig(clientCfg config.OIDCClientConfig, enabled, editable bool, source string, createdAt, updatedAt *time.Time) oidcClientView {
	clientCfg = oidc.NormalizeClientConfig(clientCfg)
	return oidcClientView{
		Name:                   clientCfg.Name,
		ClientID:               clientCfg.ClientID,
		GrantTypes:             append([]string(nil), clientCfg.GrantTypes...),
		ServiceAccountEnabled:  containsString(clientCfg.GrantTypes, "client_credentials"),
		ServiceAccountSubject:  clientCfg.ServiceAccountSubject,
		RedirectURIs:           append([]string(nil), clientCfg.RedirectURIs...),
		Scopes:                 append([]string(nil), clientCfg.Scopes...),
		Public:                 clientCfg.Public,
		RequirePKCE:            clientCfg.RequirePKCE,
		RequireOrganization:    clientCfg.RequireOrganization,
		AllowedOrganizations:   append([]string(nil), clientCfg.AllowedOrganizations...),
		RequiredOrgRoles:       append([]string(nil), clientCfg.RequiredOrgRoles...),
		RequiredOrgRolesAll:    append([]string(nil), clientCfg.RequiredOrgRolesAll...),
		RequiredOrgGroups:      append([]string(nil), clientCfg.RequiredOrgGroups...),
		RequiredOrgGroupsAll:   append([]string(nil), clientCfg.RequiredOrgGroupsAll...),
		ScopePolicies:          cloneOIDCScopePolicies(clientCfg.ScopePolicies),
		Enabled:                enabled,
		Editable:               editable,
		Source:                 source,
		ClientSecretConfigured: strings.TrimSpace(clientCfg.ClientSecret) != "",
		CreatedAt:              createdAt,
		UpdatedAt:              updatedAt,
	}
}

func cloneOIDCScopePolicies(policies map[string]config.OIDCOrganizationPolicy) map[string]config.OIDCOrganizationPolicy {
	if len(policies) == 0 {
		return nil
	}
	cloned := make(map[string]config.OIDCOrganizationPolicy, len(policies))
	for scope, policy := range policies {
		cloned[strings.TrimSpace(scope)] = config.OIDCOrganizationPolicy{
			RequireOrganization:  policy.RequireOrganization,
			AllowedOrganizations: append([]string(nil), policy.AllowedOrganizations...),
			RequiredOrgRoles:     append([]string(nil), policy.RequiredOrgRoles...),
			RequiredOrgRolesAll:  append([]string(nil), policy.RequiredOrgRolesAll...),
			RequiredOrgGroups:    append([]string(nil), policy.RequiredOrgGroups...),
			RequiredOrgGroupsAll: append([]string(nil), policy.RequiredOrgGroupsAll...),
		}
	}
	return cloned
}
