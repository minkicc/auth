package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

func TestOrganizationAdminHandlersManageDomainsAndMemberships(t *testing.T) {
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
	if err := db.Create(&auth.User{
		UserID:   "usr_admin_test",
		Password: "hash",
		Status:   auth.UserStatusActive,
		Nickname: "Ada",
	}).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	server := &AdminServer{db: db}
	router := gin.New()
	router.GET("/organizations", server.handleListOrganizations)
	router.POST("/organizations", server.handleCreateOrganization)
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
}

func TestOrganizationAdminHandlersManageIdentityProviders(t *testing.T) {
	gin.SetMode(gin.TestMode)
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
	router.POST("/organizations", server.handleCreateOrganization)
	router.GET("/organizations/:id/identity-providers", server.handleListOrganizationIdentityProviders)
	router.POST("/organizations/:id/identity-providers", server.handleCreateOrganizationIdentityProvider)
	router.PATCH("/organizations/:id/identity-providers/:provider_id", server.handleUpdateOrganizationIdentityProvider)
	router.DELETE("/organizations/:id/identity-providers/:provider_id", server.handleDeleteOrganizationIdentityProvider)

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
