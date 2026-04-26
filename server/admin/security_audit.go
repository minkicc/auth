package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/iam"
	"minki.cc/mkauth/server/oidc"
	"minki.cc/mkauth/server/plugins"
)

const (
	securityAuditActionSecretsReseal           = "secrets_reseal"
	securityAuditActionOIDCClientCreate        = "oidc_client_create"
	securityAuditActionOIDCClientUpdate        = "oidc_client_update"
	securityAuditActionOIDCClientDelete        = "oidc_client_delete"
	securityAuditActionIdentityProviderCreate  = "identity_provider_create"
	securityAuditActionIdentityProviderUpdate  = "identity_provider_update"
	securityAuditActionIdentityProviderDelete  = "identity_provider_delete"
	securityAuditActionAdminPrincipalCreate    = "admin_principal_create"
	securityAuditActionAdminPrincipalDelete    = "admin_principal_delete"
	securityAuditActionOrganizationAdminCreate = "organization_admin_create"
	securityAuditActionOrganizationAdminDelete = "organization_admin_delete"
	securityAuditExportMaxRows                 = 5000
)

type SecurityAuditEvent struct {
	EventID     string    `json:"id" gorm:"primaryKey;size:40"`
	Time        time.Time `json:"time" gorm:"index;not null"`
	Action      string    `json:"action" gorm:"index;size:64;not null"`
	ActorID     string    `json:"actor_id,omitempty" gorm:"size:120"`
	ActorIP     string    `json:"actor_ip,omitempty" gorm:"size:80"`
	UserAgent   string    `json:"user_agent,omitempty" gorm:"size:255"`
	Success     bool      `json:"success" gorm:"not null"`
	Error       string    `json:"error,omitempty" gorm:"type:text"`
	DetailsJSON string    `json:"details_json,omitempty" gorm:"type:text"`
}

func (SecurityAuditEvent) TableName() string {
	return "admin_security_audit_events"
}

type securityAuditEntryView struct {
	ID      string             `json:"id"`
	Time    string             `json:"time"`
	Action  string             `json:"action"`
	Actor   plugins.AuditActor `json:"actor,omitempty"`
	Success bool               `json:"success"`
	Error   string             `json:"error,omitempty"`
	Details map[string]string  `json:"details,omitempty"`
}

type securityAuditListOptions struct {
	Page           int
	Size           int
	Action         string
	ResourceType   string
	ClientID       string
	ProviderID     string
	OrganizationID string
	ActorID        string
	Query          string
	TimeFrom       *time.Time
	TimeTo         *time.Time
	Success        *bool
}

type securityAuditListResult struct {
	Entries []securityAuditEntryView `json:"audit"`
	Total   int64                    `json:"total"`
	Page    int                      `json:"page"`
	Size    int                      `json:"size"`
}

func (s *AdminServer) ensureSecurityAuditTable() error {
	if s == nil || s.db == nil {
		return fmt.Errorf("admin server requires database")
	}
	return s.db.AutoMigrate(&SecurityAuditEvent{})
}

func (s *AdminServer) appendSecurityAudit(action string, actor plugins.AuditActor, success bool, err error, details map[string]string) {
	if s == nil || s.db == nil {
		return
	}
	if migrateErr := s.ensureSecurityAuditTable(); migrateErr != nil {
		return
	}
	eventID, genErr := generateSecurityAuditID()
	if genErr != nil {
		return
	}
	detailsJSON := ""
	if len(details) > 0 {
		content, marshalErr := json.Marshal(details)
		if marshalErr != nil {
			return
		}
		detailsJSON = string(content)
	}
	auditEvent := SecurityAuditEvent{
		EventID:     eventID,
		Time:        time.Now().UTC(),
		Action:      action,
		ActorID:     actor.ID,
		ActorIP:     actor.IP,
		UserAgent:   actor.UserAgent,
		Success:     success,
		DetailsJSON: detailsJSON,
	}
	if err != nil {
		auditEvent.Error = err.Error()
	}
	if createErr := s.db.Create(&auditEvent).Error; createErr != nil {
		return
	}
	if s.plugins != nil {
		if dispatchErr := s.plugins.DispatchSecurityAudit(context.Background(), plugins.SecurityAuditSinkEvent{
			ID:      auditEvent.EventID,
			Time:    auditEvent.Time.Format(time.RFC3339),
			Action:  auditEvent.Action,
			Actor:   actor,
			Success: auditEvent.Success,
			Error:   auditEvent.Error,
			Details: details,
		}); dispatchErr != nil && s.logger != nil {
			s.logger.Printf("Failed to dispatch security audit sink event %s: %v", auditEvent.EventID, dispatchErr)
		}
	}
}

func (s *AdminServer) listSecurityAudit(limit int) ([]securityAuditEntryView, error) {
	result, err := s.listSecurityAuditWithOptions(securityAuditListOptions{
		Page: 1,
		Size: limit,
	})
	if err != nil {
		return nil, err
	}
	return result.Entries, nil
}

func (s *AdminServer) listSecurityAuditWithOptions(options securityAuditListOptions) (securityAuditListResult, error) {
	if s == nil || s.db == nil {
		return securityAuditListResult{}, fmt.Errorf("admin server requires database")
	}
	if err := s.ensureSecurityAuditTable(); err != nil {
		return securityAuditListResult{}, err
	}
	if options.Page <= 0 {
		options.Page = 1
	}
	if options.Size <= 0 {
		options.Size = 20
	}
	if options.Size > 200 {
		options.Size = 200
	}

	query, err := s.securityAuditQuery(options)
	if err != nil {
		return securityAuditListResult{}, err
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return securityAuditListResult{}, err
	}

	var events []SecurityAuditEvent
	offset := (options.Page - 1) * options.Size
	if err := query.Order("time DESC").Offset(offset).Limit(options.Size).Find(&events).Error; err != nil {
		return securityAuditListResult{}, err
	}
	views, err := securityAuditEntryViewsFromEvents(events)
	if err != nil {
		return securityAuditListResult{}, err
	}
	return securityAuditListResult{
		Entries: views,
		Total:   total,
		Page:    options.Page,
		Size:    options.Size,
	}, nil
}

func (s *AdminServer) listSecurityAuditEventsForExport(options securityAuditListOptions, limit int) ([]SecurityAuditEvent, int64, bool, error) {
	if s == nil || s.db == nil {
		return nil, 0, false, fmt.Errorf("admin server requires database")
	}
	if err := s.ensureSecurityAuditTable(); err != nil {
		return nil, 0, false, err
	}
	if limit <= 0 {
		limit = securityAuditExportMaxRows
	}
	query, err := s.securityAuditQuery(options)
	if err != nil {
		return nil, 0, false, err
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, false, err
	}
	var events []SecurityAuditEvent
	if err := query.Order("time DESC").Limit(limit).Find(&events).Error; err != nil {
		return nil, 0, false, err
	}
	return events, total, total > int64(limit), nil
}

func (s *AdminServer) securityAuditQuery(options securityAuditListOptions) (*gorm.DB, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("admin server requires database")
	}
	query := s.db.Model(&SecurityAuditEvent{})
	if action := strings.TrimSpace(options.Action); action != "" {
		query = query.Where("action = ?", action)
	}
	if actorID := strings.TrimSpace(strings.ToLower(options.ActorID)); actorID != "" {
		query = query.Where("LOWER(actor_id) LIKE ?", "%"+actorID+"%")
	}
	if options.TimeFrom != nil {
		query = query.Where("time >= ?", options.TimeFrom.UTC())
	}
	if options.TimeTo != nil {
		query = query.Where("time <= ?", options.TimeTo.UTC())
	}
	if options.Success != nil {
		query = query.Where("success = ?", *options.Success)
	}
	if resourceType := strings.TrimSpace(strings.ToLower(options.ResourceType)); resourceType != "" {
		query = query.Where("details_json LIKE ? ESCAPE '\\'", securityAuditJSONFieldPattern("resource_type", resourceType))
	}
	if clientID := strings.TrimSpace(options.ClientID); clientID != "" {
		query = query.Where("details_json LIKE ? ESCAPE '\\'", securityAuditJSONFieldPattern("client_id", clientID))
	}
	if providerID := strings.TrimSpace(options.ProviderID); providerID != "" {
		query = query.Where("details_json LIKE ? ESCAPE '\\'", securityAuditJSONFieldPattern("provider_id", providerID))
	}
	if organizationID := strings.TrimSpace(options.OrganizationID); organizationID != "" {
		query = query.Where("details_json LIKE ? ESCAPE '\\'", securityAuditJSONFieldPattern("organization_id", organizationID))
	}
	if searchQuery := strings.TrimSpace(strings.ToLower(options.Query)); searchQuery != "" {
		pattern := "%" + searchQuery + "%"
		query = query.Where(
			"LOWER(action) LIKE ? OR LOWER(error) LIKE ? OR LOWER(details_json) LIKE ? OR LOWER(actor_id) LIKE ? OR LOWER(event_id) LIKE ?",
			pattern,
			pattern,
			pattern,
			pattern,
			pattern,
		)
	}
	return query, nil
}

func securityAuditJSONFieldPattern(field string, value string) string {
	return fmt.Sprintf("%%\"%s\":\"%s\"%%", field, escapeSecurityAuditLike(value))
}

func escapeSecurityAuditLike(value string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"%", "\\%",
		"_", "\\_",
	)
	return replacer.Replace(value)
}

func securityAuditEntryViewsFromEvents(events []SecurityAuditEvent) ([]securityAuditEntryView, error) {
	views := make([]securityAuditEntryView, 0, len(events))
	for _, event := range events {
		view, err := securityAuditEntryViewFromEvent(event)
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	return views, nil
}

func securityAuditEntryViewFromEvent(event SecurityAuditEvent) (securityAuditEntryView, error) {
	view := securityAuditEntryView{
		ID:      event.EventID,
		Time:    event.Time.Format(time.RFC3339),
		Action:  event.Action,
		Actor:   plugins.AuditActor{ID: event.ActorID, IP: event.ActorIP, UserAgent: event.UserAgent},
		Success: event.Success,
		Error:   event.Error,
	}
	if event.DetailsJSON != "" {
		if err := json.Unmarshal([]byte(event.DetailsJSON), &view.Details); err != nil {
			return securityAuditEntryView{}, err
		}
	}
	return view, nil
}

func generateSecurityAuditID() (string, error) {
	suffix, err := auth.GenerateReadableRandomString(16)
	if err != nil {
		return "", err
	}
	return "secaud_" + suffix, nil
}

func securityAuditDetailsForReseal(result secretsResealResult, fallbackKeyCount int) map[string]string {
	return map[string]string{
		"oidc_clients":       strconv.Itoa(result.OIDCClients),
		"identity_providers": strconv.Itoa(result.IdentityProviders),
		"oidc_providers":     strconv.Itoa(result.OIDCProviders),
		"saml_providers":     strconv.Itoa(result.SAMLProviders),
		"ldap_providers":     strconv.Itoa(result.LDAPProviders),
		"fallback_key_count": strconv.Itoa(fallbackKeyCount),
	}
}

func securityAuditDetailsWithExtras(details map[string]string, extras map[string]string) map[string]string {
	if len(details) == 0 && len(extras) == 0 {
		return nil
	}
	merged := make(map[string]string, len(details)+len(extras))
	for key, value := range details {
		merged[key] = value
	}
	for key, value := range extras {
		if strings.TrimSpace(value) == "" {
			continue
		}
		merged[key] = value
	}
	return merged
}

func securityAuditDetailsForOIDCClient(view oidcClientView, previousClientID string) map[string]string {
	details := map[string]string{
		"resource_type":        "oidc_client",
		"client_id":            view.ClientID,
		"name":                 view.Name,
		"source":               view.Source,
		"public":               strconv.FormatBool(view.Public),
		"enabled":              strconv.FormatBool(view.Enabled),
		"require_pkce":         strconv.FormatBool(view.RequirePKCE),
		"require_organization": strconv.FormatBool(view.RequireOrganization),
		"grant_types":          strings.Join(view.GrantTypes, ","),
		"service_account":      strconv.FormatBool(view.ServiceAccountEnabled),
	}
	if previousClientID = strings.TrimSpace(previousClientID); previousClientID != "" && previousClientID != view.ClientID {
		details["previous_client_id"] = previousClientID
	}
	if len(view.RedirectURIs) > 0 {
		details["redirect_uri_count"] = strconv.Itoa(len(view.RedirectURIs))
	}
	if len(view.RequiredOrgRoles) > 0 {
		details["required_org_roles_count"] = strconv.Itoa(len(view.RequiredOrgRoles))
	}
	if len(view.RequiredOrgRolesAll) > 0 {
		details["required_org_roles_all_count"] = strconv.Itoa(len(view.RequiredOrgRolesAll))
	}
	if len(view.RequiredOrgGroups) > 0 {
		details["required_org_groups_count"] = strconv.Itoa(len(view.RequiredOrgGroups))
	}
	if len(view.RequiredOrgGroupsAll) > 0 {
		details["required_org_groups_all_count"] = strconv.Itoa(len(view.RequiredOrgGroupsAll))
	}
	if len(view.ScopePolicies) > 0 {
		details["scope_policy_count"] = strconv.Itoa(len(view.ScopePolicies))
	}
	return details
}

func securityAuditDetailsForOIDCClientRecord(record oidc.ClientRecord) map[string]string {
	details := map[string]string{
		"resource_type": "oidc_client",
		"client_id":     record.ClientID,
		"name":          record.Name,
		"source":        "database",
		"enabled":       strconv.FormatBool(record.Enabled),
	}
	if clientCfg, err := oidc.ClientConfigFromRecord(record); err == nil {
		details["public"] = strconv.FormatBool(clientCfg.Public)
		details["require_pkce"] = strconv.FormatBool(clientCfg.RequirePKCE)
		details["require_organization"] = strconv.FormatBool(clientCfg.RequireOrganization)
		details["grant_types"] = strings.Join(clientCfg.GrantTypes, ",")
		details["service_account"] = strconv.FormatBool(containsString(clientCfg.GrantTypes, "client_credentials"))
		details["redirect_uri_count"] = strconv.Itoa(len(clientCfg.RedirectURIs))
		if len(clientCfg.RequiredOrgRoles) > 0 {
			details["required_org_roles_count"] = strconv.Itoa(len(clientCfg.RequiredOrgRoles))
		}
		if len(clientCfg.RequiredOrgRolesAll) > 0 {
			details["required_org_roles_all_count"] = strconv.Itoa(len(clientCfg.RequiredOrgRolesAll))
		}
		if len(clientCfg.RequiredOrgGroups) > 0 {
			details["required_org_groups_count"] = strconv.Itoa(len(clientCfg.RequiredOrgGroups))
		}
		if len(clientCfg.RequiredOrgGroupsAll) > 0 {
			details["required_org_groups_all_count"] = strconv.Itoa(len(clientCfg.RequiredOrgGroupsAll))
		}
		if len(clientCfg.ScopePolicies) > 0 {
			details["scope_policy_count"] = strconv.Itoa(len(clientCfg.ScopePolicies))
		}
	}
	return details
}

func securityAuditDetailsForIdentityProviderView(view organizationIdentityProviderView, previousSlug string) map[string]string {
	details := map[string]string{
		"resource_type":   "identity_provider",
		"provider_id":     view.IdentityProviderID,
		"organization_id": view.OrganizationID,
		"provider_type":   view.ProviderType,
		"slug":            view.Slug,
		"name":            view.Name,
		"enabled":         strconv.FormatBool(view.Enabled),
		"priority":        strconv.Itoa(view.Priority),
		"is_default":      strconv.FormatBool(view.IsDefault),
		"auto_redirect":   strconv.FormatBool(view.AutoRedirect),
	}
	if previousSlug = strings.TrimSpace(previousSlug); previousSlug != "" && previousSlug != view.Slug {
		details["previous_slug"] = previousSlug
	}
	return details
}

func securityAuditDetailsForIdentityProviderRecord(record iam.OrganizationIdentityProvider) map[string]string {
	return map[string]string{
		"resource_type":   "identity_provider",
		"provider_id":     record.IdentityProviderID,
		"organization_id": record.OrganizationID,
		"provider_type":   string(record.ProviderType),
		"slug":            record.Slug,
		"name":            record.Name,
		"enabled":         strconv.FormatBool(record.Enabled),
		"priority":        strconv.Itoa(record.Priority),
		"is_default":      strconv.FormatBool(record.IsDefault),
		"auto_redirect":   strconv.FormatBool(record.AutoRedirect),
	}
}
