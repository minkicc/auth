package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
	"minki.cc/mkauth/server/secureconfig"
)

func TestOrganizationAdminHandlersManageDomainsAndMemberships(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&auth.User{}, &auth.AccountUser{}); err != nil {
		t.Fatalf("failed to migrate users: %v", err)
	}
	if err := iam.NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}
	if err := db.Create(&auth.User{
		UserID:   "usr_admin_test",
		Password: "hash",
		Status:   auth.UserStatusActive,
		Nickname: "Ada",
	}).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	server := &AdminServer{db: db, accessController: NewAccessController(&config.AdminConfig{}, db)}
	router := gin.New()
	router.GET("/organizations", server.handleListOrganizations)
	router.POST("/organizations", server.handleCreateOrganization)
	router.GET("/organizations/:id/admins", server.handleListOrganizationAdmins)
	router.POST("/organizations/:id/admins", server.handleCreateOrganizationAdmin)
	router.DELETE("/organizations/:id/admins/:user_id", server.handleDeleteOrganizationAdmin)
	router.GET("/organizations/:id/domains", server.handleListOrganizationDomains)
	router.POST("/organizations/:id/domains", server.handleCreateOrganizationDomain)
	router.PATCH("/organizations/:id/domains/:domain", server.handleUpdateOrganizationDomain)
	router.GET("/organizations/:id/memberships", server.handleListOrganizationMemberships)
	router.POST("/organizations/:id/memberships", server.handleUpsertOrganizationMembership)

	createResp := performJSON(t, router, http.MethodPost, "/organizations", map[string]any{
		"slug":         "acme",
		"name":         "Acme Inc",
		"display_name": "Acme",
		"metadata":     map[string]any{"plan": "enterprise"},
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("expected create status 201, got %d: %s", createResp.Code, createResp.Body.String())
	}
	var createBody struct {
		Organization iam.Organization `json:"organization"`
	}
	if err := json.Unmarshal(createResp.Body.Bytes(), &createBody); err != nil {
		t.Fatalf("failed to decode create body: %v", err)
	}
	if createBody.Organization.OrganizationID == "" || createBody.Organization.Slug != "acme" {
		t.Fatalf("unexpected organization response: %#v", createBody.Organization)
	}

	orgAdminResp := performJSON(t, router, http.MethodPost, "/organizations/acme/admins", map[string]any{
		"user_ref": "usr_admin_test",
	})
	if orgAdminResp.Code != http.StatusCreated {
		t.Fatalf("expected organization admin status 201, got %d: %s", orgAdminResp.Code, orgAdminResp.Body.String())
	}
	var orgAdminBody struct {
		Admin OrganizationAdminPrincipalView `json:"admin"`
	}
	if err := json.Unmarshal(orgAdminResp.Body.Bytes(), &orgAdminBody); err != nil {
		t.Fatalf("failed to decode organization admin body: %v", err)
	}
	if orgAdminBody.Admin.UserID != "usr_admin_test" || orgAdminBody.Admin.Nickname != "Ada" {
		t.Fatalf("unexpected organization admin response: %#v", orgAdminBody.Admin)
	}
	orgAdminsResp := performJSON(t, router, http.MethodGet, "/organizations/acme/admins", nil)
	if orgAdminsResp.Code != http.StatusOK {
		t.Fatalf("expected organization admins list status 200, got %d: %s", orgAdminsResp.Code, orgAdminsResp.Body.String())
	}
	var orgAdminsBody struct {
		Admins []OrganizationAdminPrincipalView `json:"admins"`
		Total  int                              `json:"total"`
	}
	if err := json.Unmarshal(orgAdminsResp.Body.Bytes(), &orgAdminsBody); err != nil {
		t.Fatalf("failed to decode organization admins list: %v", err)
	}
	if orgAdminsBody.Total != 1 || len(orgAdminsBody.Admins) != 1 {
		t.Fatalf("unexpected organization admins list: %#v", orgAdminsBody)
	}

	domainResp := performJSON(t, router, http.MethodPost, "/organizations/acme/domains", map[string]any{
		"domain":   "Example.COM",
		"verified": true,
	})
	if domainResp.Code != http.StatusOK {
		t.Fatalf("expected domain status 200, got %d: %s", domainResp.Code, domainResp.Body.String())
	}
	var domainBody struct {
		Domain iam.OrganizationDomain `json:"domain"`
	}
	if err := json.Unmarshal(domainResp.Body.Bytes(), &domainBody); err != nil {
		t.Fatalf("failed to decode domain body: %v", err)
	}
	if domainBody.Domain.Domain != "example.com" || !domainBody.Domain.Verified {
		t.Fatalf("unexpected domain response: %#v", domainBody.Domain)
	}

	memberResp := performJSON(t, router, http.MethodPost, "/organizations/acme/memberships", map[string]any{
		"user_id": "usr_admin_test",
		"roles":   []string{"admin", "developer"},
	})
	if memberResp.Code != http.StatusOK {
		t.Fatalf("expected membership status 200, got %d: %s", memberResp.Code, memberResp.Body.String())
	}
	var memberBody struct {
		Membership organizationMembershipView `json:"membership"`
	}
	if err := json.Unmarshal(memberResp.Body.Bytes(), &memberBody); err != nil {
		t.Fatalf("failed to decode membership body: %v", err)
	}
	if memberBody.Membership.UserID != "usr_admin_test" || memberBody.Membership.Nickname != "Ada" || len(memberBody.Membership.Roles) != 2 {
		t.Fatalf("unexpected membership response: %#v", memberBody.Membership)
	}

	listResp := performJSON(t, router, http.MethodGet, "/organizations?search=acme", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("expected list status 200, got %d: %s", listResp.Code, listResp.Body.String())
	}
	var listBody struct {
		Organizations []iam.Organization `json:"organizations"`
		Total         int64              `json:"total"`
	}
	if err := json.Unmarshal(listResp.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("failed to decode list body: %v", err)
	}
	if listBody.Total != 1 || len(listBody.Organizations) != 1 {
		t.Fatalf("unexpected organization list: %#v", listBody)
	}

	deleteOrgAdminResp := performJSON(t, router, http.MethodDelete, "/organizations/acme/admins/usr_admin_test", nil)
	if deleteOrgAdminResp.Code != http.StatusOK {
		t.Fatalf("expected organization admin delete status 200, got %d: %s", deleteOrgAdminResp.Code, deleteOrgAdminResp.Body.String())
	}
}

func TestOrganizationAdminHandlersManageIdentityProviders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	codec, err := secureconfig.New("identity-provider-admin-test-key")
	if err != nil {
		t.Fatalf("failed to create secure config codec: %v", err)
	}
	secureconfig.SetDefault(codec)
	defer secureconfig.SetDefault(nil)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := iam.NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}

	manager, err := iam.NewEnterpriseOIDCManager(config.IAMConfig{}, db, nil)
	if err != nil {
		t.Fatalf("failed to create enterprise oidc manager: %v", err)
	}

	server := &AdminServer{db: db, enterpriseOIDC: manager}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "admin@test")
		c.Next()
	})
	router.POST("/organizations", server.handleCreateOrganization)
	router.GET("/organizations/:id/identity-providers", server.handleListOrganizationIdentityProviders)
	router.POST("/organizations/:id/identity-providers", server.handleCreateOrganizationIdentityProvider)
	router.PATCH("/organizations/:id/identity-providers/:provider_id", server.handleUpdateOrganizationIdentityProvider)
	router.DELETE("/organizations/:id/identity-providers/:provider_id", server.handleDeleteOrganizationIdentityProvider)
	router.GET("/security/secrets/audit", server.handleGetSecretsAudit)

	createOrgResp := performJSON(t, router, http.MethodPost, "/organizations", map[string]any{
		"slug": "acme",
		"name": "Acme Inc",
	})
	if createOrgResp.Code != http.StatusCreated {
		t.Fatalf("expected create organization status 201, got %d: %s", createOrgResp.Code, createOrgResp.Body.String())
	}

	createProviderResp := performJSON(t, router, http.MethodPost, "/organizations/acme/identity-providers", map[string]any{
		"name":          "Acme Workforce",
		"slug":          "acme-workforce",
		"priority":      15,
		"is_default":    true,
		"auto_redirect": true,
		"issuer":        "https://login.acme.test",
		"client_id":     "acme-client",
		"client_secret": "super-secret",
		"redirect_uri":  "https://auth.example.com/api/enterprise/oidc/acme-workforce/callback",
		"scopes":        []string{"openid", "profile", "email"},
	})
	if createProviderResp.Code != http.StatusCreated {
		t.Fatalf("expected create identity provider status 201, got %d: %s", createProviderResp.Code, createProviderResp.Body.String())
	}
	var createProviderBody struct {
		IdentityProvider organizationIdentityProviderView `json:"identity_provider"`
	}
	if err := json.Unmarshal(createProviderResp.Body.Bytes(), &createProviderBody); err != nil {
		t.Fatalf("failed to decode identity provider body: %v", err)
	}
	if createProviderBody.IdentityProvider.IdentityProviderID == "" {
		t.Fatalf("expected identity provider id, got %#v", createProviderBody.IdentityProvider)
	}
	if !createProviderBody.IdentityProvider.Config.ClientSecretConfigured {
		t.Fatalf("expected client secret configured flag")
	}
	if createProviderBody.IdentityProvider.Priority != 15 || !createProviderBody.IdentityProvider.IsDefault || !createProviderBody.IdentityProvider.AutoRedirect {
		t.Fatalf("expected identity provider policy fields to round-trip, got %#v", createProviderBody.IdentityProvider)
	}
	if !manager.HasProviders() {
		t.Fatalf("expected enterprise oidc manager to reload created provider")
	}
	var storedRecord iam.OrganizationIdentityProvider
	if err := db.Where("identity_provider_id = ?", createProviderBody.IdentityProvider.IdentityProviderID).First(&storedRecord).Error; err != nil {
		t.Fatalf("failed to load identity provider record: %v", err)
	}
	if strings.Contains(storedRecord.ConfigJSON, "super-secret") {
		t.Fatalf("expected identity provider secret to be encrypted at rest, got %q", storedRecord.ConfigJSON)
	}

	listResp := performJSON(t, router, http.MethodGet, "/organizations/acme/identity-providers", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("expected list identity providers status 200, got %d: %s", listResp.Code, listResp.Body.String())
	}
	var listBody struct {
		IdentityProviders []organizationIdentityProviderView `json:"identity_providers"`
	}
	if err := json.Unmarshal(listResp.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("failed to decode list body: %v", err)
	}
	if len(listBody.IdentityProviders) != 1 || listBody.IdentityProviders[0].Slug != "acme-workforce" {
		t.Fatalf("unexpected identity provider list: %#v", listBody.IdentityProviders)
	}
	if !listBody.IdentityProviders[0].IsDefault || !listBody.IdentityProviders[0].AutoRedirect || listBody.IdentityProviders[0].Priority != 15 {
		t.Fatalf("expected identity provider policy fields in list response, got %#v", listBody.IdentityProviders[0])
	}

	updateResp := performJSON(t, router, http.MethodPatch, "/organizations/acme/identity-providers/"+createProviderBody.IdentityProvider.IdentityProviderID, map[string]any{
		"name":         "Acme Workforce",
		"slug":         "acme-workforce",
		"enabled":      false,
		"priority":     30,
		"is_default":   false,
		"issuer":       "https://login.acme.test",
		"client_id":    "acme-client",
		"redirect_uri": "https://auth.example.com/api/enterprise/oidc/acme-workforce/callback",
		"scopes":       []string{"openid", "email", "profile"},
	})
	if updateResp.Code != http.StatusOK {
		t.Fatalf("expected update identity provider status 200, got %d: %s", updateResp.Code, updateResp.Body.String())
	}
	var updateBody struct {
		IdentityProvider organizationIdentityProviderView `json:"identity_provider"`
	}
	if err := json.Unmarshal(updateResp.Body.Bytes(), &updateBody); err != nil {
		t.Fatalf("failed to decode update identity provider body: %v", err)
	}
	if updateBody.IdentityProvider.Priority != 30 || updateBody.IdentityProvider.IsDefault || updateBody.IdentityProvider.AutoRedirect != true {
		t.Fatalf("expected update to preserve unset auto_redirect and apply policy changes, got %#v", updateBody.IdentityProvider)
	}
	if manager.HasProviders() {
		t.Fatalf("expected disabled identity provider to be removed from runtime manager")
	}

	deleteResp := performJSON(t, router, http.MethodDelete, "/organizations/acme/identity-providers/"+createProviderBody.IdentityProvider.IdentityProviderID, nil)
	if deleteResp.Code != http.StatusOK {
		t.Fatalf("expected delete identity provider status 200, got %d: %s", deleteResp.Code, deleteResp.Body.String())
	}

	auditEntries := listSecurityAuditEntries(t, router)
	if len(auditEntries) != 3 {
		t.Fatalf("expected 3 security audit entries, got %#v", auditEntries)
	}
	if auditEntries[0].Action != securityAuditActionIdentityProviderDelete || !auditEntries[0].Success {
		t.Fatalf("expected latest audit entry to be identity provider delete success, got %#v", auditEntries[0])
	}
	if auditEntries[0].Actor.ID != "admin@test" || auditEntries[0].Details["provider_id"] != createProviderBody.IdentityProvider.IdentityProviderID {
		t.Fatalf("unexpected delete audit entry: %#v", auditEntries[0])
	}
	if auditEntries[1].Action != securityAuditActionIdentityProviderUpdate || !auditEntries[1].Success {
		t.Fatalf("expected middle audit entry to be identity provider update success, got %#v", auditEntries[1])
	}
	if auditEntries[1].Details["provider_type"] != "oidc" || auditEntries[1].Details["slug"] != "acme-workforce" {
		t.Fatalf("unexpected identity provider update details: %#v", auditEntries[1].Details)
	}
	if auditEntries[2].Action != securityAuditActionIdentityProviderCreate || !auditEntries[2].Success {
		t.Fatalf("expected oldest audit entry to be identity provider create success, got %#v", auditEntries[2])
	}
	if auditEntries[2].Details["organization_id"] == "" || auditEntries[2].Details["resource_type"] != "identity_provider" {
		t.Fatalf("unexpected identity provider create details: %#v", auditEntries[2].Details)
	}
}

func TestOrganizationAdminHandlersManageGroups(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&auth.User{}); err != nil {
		t.Fatalf("failed to migrate users: %v", err)
	}
	if err := iam.NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}
	for _, user := range []auth.User{
		{UserID: "usr_group_1", Password: "hash", Status: auth.UserStatusActive, Nickname: "Ada"},
		{UserID: "usr_group_2", Password: "hash", Status: auth.UserStatusActive, Nickname: "Linus"},
	} {
		if err := db.Create(&user).Error; err != nil {
			t.Fatalf("failed to create user %s: %v", user.UserID, err)
		}
	}

	server := &AdminServer{db: db}
	router := gin.New()
	router.POST("/organizations", server.handleCreateOrganization)
	router.GET("/organizations/:id/groups", server.handleListOrganizationGroups)
	router.POST("/organizations/:id/groups", server.handleCreateOrganizationGroup)
	router.GET("/organizations/:id/groups/:group_id", server.handleGetOrganizationGroup)
	router.PATCH("/organizations/:id/groups/:group_id", server.handleUpdateOrganizationGroup)
	router.DELETE("/organizations/:id/groups/:group_id", server.handleDeleteOrganizationGroup)

	createOrgResp := performJSON(t, router, http.MethodPost, "/organizations", map[string]any{
		"slug": "acme",
		"name": "Acme Inc",
	})
	if createOrgResp.Code != http.StatusCreated {
		t.Fatalf("expected create organization status 201, got %d: %s", createOrgResp.Code, createOrgResp.Body.String())
	}
	var createOrgBody struct {
		Organization iam.Organization `json:"organization"`
	}
	if err := json.Unmarshal(createOrgResp.Body.Bytes(), &createOrgBody); err != nil {
		t.Fatalf("failed to decode create organization body: %v", err)
	}

	createGroupResp := performJSON(t, router, http.MethodPost, "/organizations/acme/groups", map[string]any{
		"display_name": "Platform Team",
		"role_name":    "platform-team",
		"user_ids":     []string{"usr_group_1"},
	})
	if createGroupResp.Code != http.StatusCreated {
		t.Fatalf("expected create group status 201, got %d: %s", createGroupResp.Code, createGroupResp.Body.String())
	}
	var createGroupBody struct {
		Group organizationGroupView `json:"group"`
	}
	if err := json.Unmarshal(createGroupResp.Body.Bytes(), &createGroupBody); err != nil {
		t.Fatalf("failed to decode create group body: %v", err)
	}
	if createGroupBody.Group.GroupID == "" || createGroupBody.Group.MemberCount != 1 || !createGroupBody.Group.Editable {
		t.Fatalf("unexpected create group response: %#v", createGroupBody.Group)
	}
	if len(createGroupBody.Group.Members) != 1 || createGroupBody.Group.Members[0].Nickname != "Ada" {
		t.Fatalf("expected create group members to include Ada, got %#v", createGroupBody.Group.Members)
	}

	var membership1 iam.OrganizationMembership
	if err := db.First(&membership1, "organization_id = ? AND user_id = ?", createOrgBody.Organization.OrganizationID, "usr_group_1").Error; err != nil {
		t.Fatalf("failed to load auto-created organization membership: %v", err)
	}
	if roles := parseRolesJSON(membership1.RolesJSON); len(roles) != 1 || roles[0] != "platform-team" {
		t.Fatalf("expected platform-team role from manual group, got %#v", roles)
	}

	getGroupResp := performJSON(t, router, http.MethodGet, "/organizations/acme/groups/"+createGroupBody.Group.GroupID, nil)
	if getGroupResp.Code != http.StatusOK {
		t.Fatalf("expected get group status 200, got %d: %s", getGroupResp.Code, getGroupResp.Body.String())
	}

	updateGroupResp := performJSON(t, router, http.MethodPatch, "/organizations/acme/groups/"+createGroupBody.Group.GroupID, map[string]any{
		"display_name": "Platform Core",
		"role_name":    "platform-core",
		"user_ids":     []string{"usr_group_2"},
	})
	if updateGroupResp.Code != http.StatusOK {
		t.Fatalf("expected update group status 200, got %d: %s", updateGroupResp.Code, updateGroupResp.Body.String())
	}
	if err := db.First(&membership1, "organization_id = ? AND user_id = ?", createOrgBody.Organization.OrganizationID, "usr_group_1").Error; err != nil {
		t.Fatalf("failed to reload first membership: %v", err)
	}
	if roles := parseRolesJSON(membership1.RolesJSON); len(roles) != 0 {
		t.Fatalf("expected first user roles to be removed after group update, got %#v", roles)
	}
	var membership2 iam.OrganizationMembership
	if err := db.First(&membership2, "organization_id = ? AND user_id = ?", createOrgBody.Organization.OrganizationID, "usr_group_2").Error; err != nil {
		t.Fatalf("failed to load second membership: %v", err)
	}
	if roles := parseRolesJSON(membership2.RolesJSON); len(roles) != 1 || roles[0] != "platform-core" {
		t.Fatalf("expected second user to receive platform-core role, got %#v", roles)
	}

	deleteGroupResp := performJSON(t, router, http.MethodDelete, "/organizations/acme/groups/"+createGroupBody.Group.GroupID, nil)
	if deleteGroupResp.Code != http.StatusOK {
		t.Fatalf("expected delete group status 200, got %d: %s", deleteGroupResp.Code, deleteGroupResp.Body.String())
	}
	if err := db.First(&membership2, "organization_id = ? AND user_id = ?", createOrgBody.Organization.OrganizationID, "usr_group_2").Error; err != nil {
		t.Fatalf("failed to reload second membership after delete: %v", err)
	}
	if roles := parseRolesJSON(membership2.RolesJSON); len(roles) != 0 {
		t.Fatalf("expected second user roles to be removed after deleting group, got %#v", roles)
	}
}

func TestOrganizationAdminHandlersManageRoles(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&auth.User{}); err != nil {
		t.Fatalf("failed to migrate users: %v", err)
	}
	if err := iam.NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}
	for _, user := range []auth.User{
		{UserID: "usr_role_1", Password: "hash", Status: auth.UserStatusActive, Nickname: "Ada"},
		{UserID: "usr_role_2", Password: "hash", Status: auth.UserStatusActive, Nickname: "Linus"},
	} {
		if err := db.Create(&user).Error; err != nil {
			t.Fatalf("failed to create user %s: %v", user.UserID, err)
		}
	}

	server := &AdminServer{db: db}
	router := gin.New()
	router.POST("/organizations", server.handleCreateOrganization)
	router.POST("/organizations/:id/memberships", server.handleUpsertOrganizationMembership)
	router.POST("/organizations/:id/groups", server.handleCreateOrganizationGroup)
	router.GET("/organizations/:id/roles", server.handleListOrganizationRoles)
	router.POST("/organizations/:id/roles", server.handleCreateOrganizationRole)
	router.PATCH("/organizations/:id/roles/:role_id", server.handleUpdateOrganizationRole)
	router.DELETE("/organizations/:id/roles/:role_id", server.handleDeleteOrganizationRole)
	router.POST("/organizations/:id/roles/:role_id/bindings", server.handleCreateOrganizationRoleBinding)
	router.DELETE("/organizations/:id/roles/:role_id/bindings/:binding_id", server.handleDeleteOrganizationRoleBinding)

	createOrgResp := performJSON(t, router, http.MethodPost, "/organizations", map[string]any{
		"slug": "acme",
		"name": "Acme Inc",
	})
	if createOrgResp.Code != http.StatusCreated {
		t.Fatalf("expected create organization status 201, got %d: %s", createOrgResp.Code, createOrgResp.Body.String())
	}

	createMembershipResp := performJSON(t, router, http.MethodPost, "/organizations/acme/memberships", map[string]any{
		"user_id": "usr_role_1",
		"status":  "active",
	})
	if createMembershipResp.Code != http.StatusOK {
		t.Fatalf("expected create membership status 200, got %d: %s", createMembershipResp.Code, createMembershipResp.Body.String())
	}

	createGroupResp := performJSON(t, router, http.MethodPost, "/organizations/acme/groups", map[string]any{
		"display_name": "Platform Team",
		"user_ids":     []string{"usr_role_2"},
	})
	if createGroupResp.Code != http.StatusCreated {
		t.Fatalf("expected create group status 201, got %d: %s", createGroupResp.Code, createGroupResp.Body.String())
	}
	var createGroupBody struct {
		Group organizationGroupView `json:"group"`
	}
	if err := json.Unmarshal(createGroupResp.Body.Bytes(), &createGroupBody); err != nil {
		t.Fatalf("failed to decode create group body: %v", err)
	}

	createRoleResp := performJSON(t, router, http.MethodPost, "/organizations/acme/roles", map[string]any{
		"name":        "Admin",
		"description": "Organization admin role",
		"enabled":     true,
		"permissions": []string{"settings.manage", "billing.read"},
	})
	if createRoleResp.Code != http.StatusCreated {
		t.Fatalf("expected create role status 201, got %d: %s", createRoleResp.Code, createRoleResp.Body.String())
	}
	var createRoleBody struct {
		Role organizationRoleView `json:"role"`
	}
	if err := json.Unmarshal(createRoleResp.Body.Bytes(), &createRoleBody); err != nil {
		t.Fatalf("failed to decode create role body: %v", err)
	}
	if createRoleBody.Role.RoleID == "" || createRoleBody.Role.Slug != "admin" || len(createRoleBody.Role.Permissions) != 2 || createRoleBody.Role.BindingCount != 0 {
		t.Fatalf("unexpected create role response: %#v", createRoleBody.Role)
	}

	createMemberBindingResp := performJSON(t, router, http.MethodPost, "/organizations/acme/roles/"+createRoleBody.Role.RoleID+"/bindings", map[string]any{
		"subject_type": "membership",
		"subject_id":   "usr_role_1",
	})
	if createMemberBindingResp.Code != http.StatusCreated {
		t.Fatalf("expected create membership binding status 201, got %d: %s", createMemberBindingResp.Code, createMemberBindingResp.Body.String())
	}
	var memberBindingBody struct {
		Binding organizationRoleBindingView `json:"binding"`
	}
	if err := json.Unmarshal(createMemberBindingResp.Body.Bytes(), &memberBindingBody); err != nil {
		t.Fatalf("failed to decode membership binding body: %v", err)
	}
	if memberBindingBody.Binding.SubjectLabel != "Ada" {
		t.Fatalf("expected membership binding label Ada, got %#v", memberBindingBody.Binding)
	}

	createGroupBindingResp := performJSON(t, router, http.MethodPost, "/organizations/acme/roles/"+createRoleBody.Role.RoleID+"/bindings", map[string]any{
		"subject_type": "group",
		"subject_id":   createGroupBody.Group.GroupID,
	})
	if createGroupBindingResp.Code != http.StatusCreated {
		t.Fatalf("expected create group binding status 201, got %d: %s", createGroupBindingResp.Code, createGroupBindingResp.Body.String())
	}
	var groupBindingBody struct {
		Binding organizationRoleBindingView `json:"binding"`
	}
	if err := json.Unmarshal(createGroupBindingResp.Body.Bytes(), &groupBindingBody); err != nil {
		t.Fatalf("failed to decode group binding body: %v", err)
	}
	if groupBindingBody.Binding.SubjectLabel != "Platform Team" {
		t.Fatalf("expected group binding label Platform Team, got %#v", groupBindingBody.Binding)
	}

	listRolesResp := performJSON(t, router, http.MethodGet, "/organizations/acme/roles", nil)
	if listRolesResp.Code != http.StatusOK {
		t.Fatalf("expected list roles status 200, got %d: %s", listRolesResp.Code, listRolesResp.Body.String())
	}
	var listRolesBody struct {
		Roles []organizationRoleView `json:"roles"`
	}
	if err := json.Unmarshal(listRolesResp.Body.Bytes(), &listRolesBody); err != nil {
		t.Fatalf("failed to decode list roles body: %v", err)
	}
	if len(listRolesBody.Roles) != 1 || listRolesBody.Roles[0].BindingCount != 2 || len(listRolesBody.Roles[0].Bindings) != 2 {
		t.Fatalf("unexpected role list response: %#v", listRolesBody.Roles)
	}

	updateRoleResp := performJSON(t, router, http.MethodPatch, "/organizations/acme/roles/"+createRoleBody.Role.RoleID, map[string]any{
		"name":        "Admin",
		"slug":        "admin",
		"description": "Updated role",
		"enabled":     false,
		"permissions": []string{"settings.manage"},
	})
	if updateRoleResp.Code != http.StatusOK {
		t.Fatalf("expected update role status 200, got %d: %s", updateRoleResp.Code, updateRoleResp.Body.String())
	}
	var updateRoleBody struct {
		Role organizationRoleView `json:"role"`
	}
	if err := json.Unmarshal(updateRoleResp.Body.Bytes(), &updateRoleBody); err != nil {
		t.Fatalf("failed to decode update role body: %v", err)
	}
	if updateRoleBody.Role.Enabled || updateRoleBody.Role.Description != "Updated role" || len(updateRoleBody.Role.Permissions) != 1 || updateRoleBody.Role.Permissions[0] != "settings.manage" {
		t.Fatalf("unexpected updated role response: %#v", updateRoleBody.Role)
	}

	deleteBindingResp := performJSON(t, router, http.MethodDelete, "/organizations/acme/roles/"+createRoleBody.Role.RoleID+"/bindings/"+memberBindingBody.Binding.BindingID, nil)
	if deleteBindingResp.Code != http.StatusOK {
		t.Fatalf("expected delete binding status 200, got %d: %s", deleteBindingResp.Code, deleteBindingResp.Body.String())
	}

	deleteRoleResp := performJSON(t, router, http.MethodDelete, "/organizations/acme/roles/"+createRoleBody.Role.RoleID, nil)
	if deleteRoleResp.Code != http.StatusOK {
		t.Fatalf("expected delete role status 200, got %d: %s", deleteRoleResp.Code, deleteRoleResp.Body.String())
	}

	var roleCount int64
	if err := db.Model(&iam.OrganizationRole{}).Count(&roleCount).Error; err != nil {
		t.Fatalf("failed to count roles: %v", err)
	}
	if roleCount != 0 {
		t.Fatalf("expected roles to be deleted, found %d", roleCount)
	}
	var permissionCount int64
	if err := db.Model(&iam.OrganizationRolePermission{}).Count(&permissionCount).Error; err != nil {
		t.Fatalf("failed to count role permissions: %v", err)
	}
	if permissionCount != 0 {
		t.Fatalf("expected role permissions to be deleted, found %d", permissionCount)
	}
	var bindingCount int64
	if err := db.Model(&iam.OrganizationRoleBinding{}).Count(&bindingCount).Error; err != nil {
		t.Fatalf("failed to count role bindings: %v", err)
	}
	if bindingCount != 0 {
		t.Fatalf("expected role bindings to be deleted, found %d", bindingCount)
	}
}

func TestOrganizationAdminHandlersManageLDAPIdentityProviders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := iam.NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}

	manager, err := iam.NewEnterpriseLDAPManager(config.IAMConfig{}, db, nil)
	if err != nil {
		t.Fatalf("failed to create enterprise ldap manager: %v", err)
	}

	server := &AdminServer{db: db, enterpriseLDAP: manager}
	router := gin.New()
	router.POST("/organizations", server.handleCreateOrganization)
	router.GET("/organizations/:id/identity-providers", server.handleListOrganizationIdentityProviders)
	router.POST("/organizations/:id/identity-providers", server.handleCreateOrganizationIdentityProvider)
	router.PATCH("/organizations/:id/identity-providers/:provider_id", server.handleUpdateOrganizationIdentityProvider)

	createOrgResp := performJSON(t, router, http.MethodPost, "/organizations", map[string]any{
		"slug": "globex",
		"name": "Globex Corp",
	})
	if createOrgResp.Code != http.StatusCreated {
		t.Fatalf("expected create organization status 201, got %d: %s", createOrgResp.Code, createOrgResp.Body.String())
	}

	createProviderResp := performJSON(t, router, http.MethodPost, "/organizations/globex/identity-providers", map[string]any{
		"provider_type":              "ldap",
		"name":                       "Globex Directory",
		"slug":                       "globex-ldap",
		"priority":                   5,
		"is_default":                 true,
		"url":                        "ldaps://ldap.globex.test:636",
		"base_dn":                    "dc=globex,dc=test",
		"bind_dn":                    "cn=svc-bind,dc=globex,dc=test",
		"bind_password":              "super-secret",
		"user_filter":                "(&(objectClass=person)(uid={username}))",
		"group_member_attribute":     "memberOf",
		"group_base_dn":              "ou=groups,dc=globex,dc=test",
		"group_filter":               "(|(member={user_dn})(memberUid={username}))",
		"group_identifier_attribute": "entryUUID",
		"group_name_attribute":       "displayName",
		"subject_attribute":          "entryUUID",
		"email_attribute":            "mail",
		"username_attribute":         "uid",
		"display_name_attribute":     "displayName",
	})
	if createProviderResp.Code != http.StatusCreated {
		t.Fatalf("expected create ldap identity provider status 201, got %d: %s", createProviderResp.Code, createProviderResp.Body.String())
	}

	var createProviderBody struct {
		IdentityProvider organizationIdentityProviderView `json:"identity_provider"`
	}
	if err := json.Unmarshal(createProviderResp.Body.Bytes(), &createProviderBody); err != nil {
		t.Fatalf("failed to decode ldap identity provider body: %v", err)
	}
	if createProviderBody.IdentityProvider.ProviderType != "ldap" {
		t.Fatalf("expected provider_type ldap, got %#v", createProviderBody.IdentityProvider)
	}
	if createProviderBody.IdentityProvider.Config.URL != "ldaps://ldap.globex.test:636" ||
		createProviderBody.IdentityProvider.Config.BaseDN != "dc=globex,dc=test" ||
		!createProviderBody.IdentityProvider.Config.BindPasswordConfigured ||
		createProviderBody.IdentityProvider.Config.GroupMemberAttribute != "memberOf" ||
		createProviderBody.IdentityProvider.Config.GroupBaseDN != "ou=groups,dc=globex,dc=test" ||
		createProviderBody.IdentityProvider.Config.GroupFilter != "(|(member={user_dn})(memberUid={username}))" {
		t.Fatalf("unexpected ldap config view: %#v", createProviderBody.IdentityProvider.Config)
	}
	if !manager.HasProviders() {
		t.Fatalf("expected enterprise ldap manager to reload created provider")
	}

	updateResp := performJSON(t, router, http.MethodPatch, "/organizations/globex/identity-providers/"+createProviderBody.IdentityProvider.IdentityProviderID, map[string]any{
		"provider_type":              "ldap",
		"name":                       "Globex Directory",
		"slug":                       "globex-ldap",
		"enabled":                    false,
		"url":                        "ldaps://ldap.globex.test:636",
		"base_dn":                    "dc=globex,dc=test",
		"bind_dn":                    "cn=svc-bind,dc=globex,dc=test",
		"user_filter":                "(&(objectClass=person)(uid={username}))",
		"group_member_attribute":     "memberOf",
		"group_base_dn":              "ou=groups,dc=globex,dc=test",
		"group_filter":               "(|(member={user_dn})(memberUid={username}))",
		"group_identifier_attribute": "entryUUID",
		"group_name_attribute":       "displayName",
		"subject_attribute":          "entryUUID",
		"email_attribute":            "mail",
		"username_attribute":         "uid",
		"display_name_attribute":     "displayName",
	})
	if updateResp.Code != http.StatusOK {
		t.Fatalf("expected update ldap identity provider status 200, got %d: %s", updateResp.Code, updateResp.Body.String())
	}
	if manager.HasProviders() {
		t.Fatalf("expected disabled ldap identity provider to be removed from runtime manager")
	}
}

func performJSON(t *testing.T, router *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("failed to marshal request body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	return resp
}

func listSecurityAuditEntries(t *testing.T, router *gin.Engine) []securityAuditEntryView {
	t.Helper()
	resp := performJSON(t, router, http.MethodGet, "/security/secrets/audit?limit=20", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected security audit status 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body struct {
		Audit []securityAuditEntryView `json:"audit"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode security audit response: %v", err)
	}
	return body.Audit
}
