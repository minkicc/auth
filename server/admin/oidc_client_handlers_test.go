package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/oidc"
	"minki.cc/mkauth/server/secureconfig"
)

func TestOIDCClientAdminHandlersManageClients(t *testing.T) {
	gin.SetMode(gin.TestMode)
	codec, err := secureconfig.New("oidc-client-admin-test-key")
	if err != nil {
		t.Fatalf("failed to create secure config codec: %v", err)
	}
	secureconfig.SetDefault(codec)
	defer secureconfig.SetDefault(nil)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&oidc.ClientRecord{}); err != nil {
		t.Fatalf("failed to migrate oidc client table: %v", err)
	}

	server := &AdminServer{db: db, oidcStaticCfgs: []config.OIDCClientConfig{{
		Name:         "Static SPA",
		ClientID:     "static-spa",
		Public:       true,
		RequirePKCE:  true,
		RedirectURIs: []string{"https://static.example.com/callback"},
		Scopes:       []string{"openid", "profile"},
	}}}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "admin@test")
		c.Next()
	})
	router.GET("/oidc/clients", server.handleListOIDCClients)
	router.POST("/oidc/clients", server.handleCreateOIDCClient)
	router.PATCH("/oidc/clients/:client_id", server.handleUpdateOIDCClient)
	router.DELETE("/oidc/clients/:client_id", server.handleDeleteOIDCClient)
	router.GET("/security/secrets/audit", server.handleGetSecretsAudit)

	createResp := performJSON(t, router, http.MethodPost, "/oidc/clients", map[string]any{
		"name":                   "Demo Backend",
		"client_id":              "demo-backend",
		"client_secret":          "super-secret",
		"redirect_uris":          []string{"https://api.example.com/oauth/callback"},
		"scopes":                 []string{"openid", "profile", "email"},
		"require_organization":   true,
		"allowed_organizations":  []string{"acme", "beta"},
		"required_org_roles":     []string{"admin"},
		"required_org_roles_all": []string{"security"},
		"scope_policies": map[string]any{
			"email": map[string]any{
				"required_org_groups_all": []string{"employees"},
			},
		},
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("expected create oidc client status 201, got %d: %s", createResp.Code, createResp.Body.String())
	}
	var createBody struct {
		Client oidcClientView `json:"client"`
	}
	if err := json.Unmarshal(createResp.Body.Bytes(), &createBody); err != nil {
		t.Fatalf("failed to decode create response: %v", err)
	}
	if createBody.Client.ClientID != "demo-backend" || !createBody.Client.ClientSecretConfigured || createBody.Client.Source != "database" || !createBody.Client.Editable {
		t.Fatalf("unexpected create response: %#v", createBody.Client)
	}
	if len(createBody.Client.RequiredOrgRolesAll) != 1 || createBody.Client.RequiredOrgRolesAll[0] != "security" {
		t.Fatalf("expected create response to include required_org_roles_all, got %#v", createBody.Client)
	}
	if policy, ok := createBody.Client.ScopePolicies["email"]; !ok || len(policy.RequiredOrgGroupsAll) != 1 || policy.RequiredOrgGroupsAll[0] != "employees" {
		t.Fatalf("expected create response to include email scope policy, got %#v", createBody.Client.ScopePolicies)
	}

	listResp := performJSON(t, router, http.MethodGet, "/oidc/clients", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("expected list oidc clients status 200, got %d: %s", listResp.Code, listResp.Body.String())
	}
	var listBody struct {
		Clients []oidcClientView `json:"clients"`
	}
	if err := json.Unmarshal(listResp.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("failed to decode list response: %v", err)
	}
	if len(listBody.Clients) != 2 {
		t.Fatalf("expected 2 oidc clients in list, got %#v", listBody.Clients)
	}
	if listBody.Clients[0].Source != "config" || listBody.Clients[1].Source != "database" {
		t.Fatalf("expected config and database clients in list, got %#v", listBody.Clients)
	}

	updateResp := performJSON(t, router, http.MethodPatch, "/oidc/clients/demo-backend", map[string]any{
		"name":                    "Demo Backend",
		"client_id":               "demo-backend-v2",
		"redirect_uris":           []string{"https://api.example.com/oauth/callback"},
		"scopes":                  []string{"openid", "profile", "email"},
		"require_organization":    true,
		"required_org_roles":      []string{"owner"},
		"required_org_roles_all":  []string{"security", "ops"},
		"required_org_groups":     []string{"platform"},
		"required_org_groups_all": []string{"employees"},
		"allowed_organizations":   []string{"acme"},
		"scope_policies": map[string]any{
			"profile": map[string]any{
				"required_org_roles": []string{"reader"},
			},
			"email": map[string]any{
				"required_org_groups_all": []string{"employees"},
			},
		},
		"enabled": false,
	})
	if updateResp.Code != http.StatusOK {
		t.Fatalf("expected update oidc client status 200, got %d: %s", updateResp.Code, updateResp.Body.String())
	}
	var updateBody struct {
		Client oidcClientView `json:"client"`
	}
	if err := json.Unmarshal(updateResp.Body.Bytes(), &updateBody); err != nil {
		t.Fatalf("failed to decode update response: %v", err)
	}
	if updateBody.Client.ClientID != "demo-backend-v2" || updateBody.Client.Enabled || !updateBody.Client.ClientSecretConfigured {
		t.Fatalf("unexpected update response: %#v", updateBody.Client)
	}
	if len(updateBody.Client.RequiredOrgRolesAll) != 2 {
		t.Fatalf("expected update response to include required_org_roles_all, got %#v", updateBody.Client)
	}
	if len(updateBody.Client.RequiredOrgGroupsAll) != 1 || updateBody.Client.RequiredOrgGroupsAll[0] != "employees" {
		t.Fatalf("expected update response to include required_org_groups_all, got %#v", updateBody.Client)
	}

	var storedRecord oidc.ClientRecord
	if err := db.Where("client_id = ?", "demo-backend-v2").First(&storedRecord).Error; err != nil {
		t.Fatalf("failed to load stored oidc client: %v", err)
	}
	if strings.Contains(storedRecord.ConfigJSON, "super-secret") {
		t.Fatalf("expected oidc client secret to be encrypted at rest, got %q", storedRecord.ConfigJSON)
	}
	storedCfg, err := oidc.ClientConfigFromRecord(storedRecord)
	if err != nil {
		t.Fatalf("failed to decode stored oidc client: %v", err)
	}
	if storedCfg.ClientSecret != "super-secret" || len(storedCfg.RequiredOrgRoles) != 1 || storedCfg.RequiredOrgRoles[0] != "owner" {
		t.Fatalf("unexpected stored client config: %#v", storedCfg)
	}
	if len(storedCfg.RequiredOrgRolesAll) != 2 || storedCfg.RequiredOrgRolesAll[0] != "ops" || storedCfg.RequiredOrgRolesAll[1] != "security" {
		t.Fatalf("expected stored required_org_roles_all, got %#v", storedCfg.RequiredOrgRolesAll)
	}
	if policy, ok := storedCfg.ScopePolicies["profile"]; !ok || len(policy.RequiredOrgRoles) != 1 || policy.RequiredOrgRoles[0] != "reader" {
		t.Fatalf("expected stored profile scope policy, got %#v", storedCfg.ScopePolicies)
	}

	staticDeleteResp := performJSON(t, router, http.MethodDelete, "/oidc/clients/static-spa", nil)
	if staticDeleteResp.Code != http.StatusBadRequest {
		t.Fatalf("expected static oidc client delete to be rejected, got %d: %s", staticDeleteResp.Code, staticDeleteResp.Body.String())
	}

	deleteResp := performJSON(t, router, http.MethodDelete, "/oidc/clients/demo-backend-v2", nil)
	if deleteResp.Code != http.StatusOK {
		t.Fatalf("expected delete oidc client status 200, got %d: %s", deleteResp.Code, deleteResp.Body.String())
	}
	var remaining int64
	if err := db.Model(&oidc.ClientRecord{}).Count(&remaining).Error; err != nil {
		t.Fatalf("failed to count oidc clients: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected oidc client table to be empty after delete, got %d", remaining)
	}

	auditEntries := listSecurityAuditEntries(t, router)
	if len(auditEntries) != 3 {
		t.Fatalf("expected 3 security audit entries, got %#v", auditEntries)
	}
	if auditEntries[0].Action != securityAuditActionOIDCClientDelete || !auditEntries[0].Success {
		t.Fatalf("expected latest audit entry to be oidc client delete success, got %#v", auditEntries[0])
	}
	if auditEntries[0].Actor.ID != "admin@test" || auditEntries[0].Details["client_id"] != "demo-backend-v2" {
		t.Fatalf("unexpected delete audit entry: %#v", auditEntries[0])
	}
	if auditEntries[1].Action != securityAuditActionOIDCClientUpdate || !auditEntries[1].Success {
		t.Fatalf("expected middle audit entry to be oidc client update success, got %#v", auditEntries[1])
	}
	if auditEntries[1].Details["client_id"] != "demo-backend-v2" || auditEntries[1].Details["previous_client_id"] != "demo-backend" {
		t.Fatalf("unexpected update audit details: %#v", auditEntries[1].Details)
	}
	if auditEntries[1].Details["scope_policy_count"] != "2" {
		t.Fatalf("expected update audit to include scope policy count, got %#v", auditEntries[1].Details)
	}
	if auditEntries[2].Action != securityAuditActionOIDCClientCreate || !auditEntries[2].Success {
		t.Fatalf("expected oldest audit entry to be oidc client create success, got %#v", auditEntries[2])
	}
	if auditEntries[2].Details["client_id"] != "demo-backend" || auditEntries[2].Details["resource_type"] != "oidc_client" {
		t.Fatalf("unexpected create audit details: %#v", auditEntries[2].Details)
	}
	if auditEntries[2].Details["required_org_roles_all_count"] != "1" {
		t.Fatalf("expected create audit details to include required_org_roles_all_count, got %#v", auditEntries[2].Details)
	}
}
