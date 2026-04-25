package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/iam"
)

func TestCurrentOrganizationAuthorizationEndpointAutoSelectsSingleMembership(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	registerResp := performJSONRequest(t, env.router, http.MethodPost, "/api/account/register", map[string]string{
		"username": "org_authz_user",
		"password": "demo12345",
	}, nil, nil)
	if registerResp.Code != http.StatusOK {
		t.Fatalf("expected register status 200, got %d with body %s", registerResp.Code, registerResp.Body.String())
	}

	sessionCookie := requireCookie(t, registerResp, auth.OIDCSessionCookieName)
	body := decodeBodyMap(t, registerResp)
	userID, ok := body["user_id"].(string)
	if !ok || userID == "" {
		t.Fatalf("expected user_id in register response, got %#v", body["user_id"])
	}

	now := time.Now()
	if err := env.db.Create(&iam.Organization{
		OrganizationID: "org_acme0000000000",
		Slug:           "acme",
		Name:           "Acme Inc",
		DisplayName:    "Acme",
		Status:         iam.OrganizationStatusActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create organization: %v", err)
	}
	if err := env.db.Create(&iam.OrganizationMembership{
		OrganizationID: "org_acme0000000000",
		UserID:         userID,
		Status:         iam.MembershipStatusActive,
		RolesJSON:      `["owner"]`,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create membership: %v", err)
	}
	if err := env.db.Create(&iam.OrganizationRole{
		RoleID:         "rol_acmesettings000",
		OrganizationID: "org_acme0000000000",
		Name:           "Settings Admin",
		Slug:           "settings-admin",
		Enabled:        true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create organization role: %v", err)
	}
	if err := env.db.Create(&iam.OrganizationRolePermission{
		OrganizationID: "org_acme0000000000",
		RoleID:         "rol_acmesettings000",
		PermissionKey:  "settings.manage",
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create organization role permission: %v", err)
	}
	if err := env.db.Create(&iam.OrganizationRoleBinding{
		BindingID:      "rbd_acmesettings000",
		OrganizationID: "org_acme0000000000",
		RoleID:         "rol_acmesettings000",
		SubjectType:    iam.RoleBindingSubjectMembership,
		SubjectID:      userID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create organization role binding: %v", err)
	}
	if err := env.db.Create(&iam.OrganizationGroup{
		GroupID:        "grp_acmeemployees00",
		OrganizationID: "org_acme0000000000",
		ProviderType:   iam.IdentityProviderTypeManual,
		ProviderID:     iam.ManualOrganizationGroupProvider,
		ExternalID:     "grp_acmeemployees00",
		DisplayName:    "Employees",
		RoleName:       "employees",
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create organization group: %v", err)
	}
	if err := env.db.Create(&iam.OrganizationGroupMember{
		OrganizationID: "org_acme0000000000",
		GroupID:        "grp_acmeemployees00",
		UserID:         userID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create organization group member: %v", err)
	}

	resp := performJSONRequest(t, env.router, http.MethodGet, "/api/user/organization/authorization", nil, sessionCookie, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected authorization status 200, got %d with body %s", resp.Code, resp.Body.String())
	}

	var response struct {
		Authorization map[string]any `json:"authorization"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode authorization response: %v", err)
	}
	if response.Authorization["organization_id"] != "org_acme0000000000" {
		t.Fatalf("expected organization_id org_acme0000000000, got %#v", response.Authorization["organization_id"])
	}
	if response.Authorization["organization_slug"] != "acme" {
		t.Fatalf("expected organization_slug acme, got %#v", response.Authorization["organization_slug"])
	}
	permissions, ok := response.Authorization["permissions"].([]any)
	if !ok || len(permissions) != 1 || permissions[0] != "settings.manage" {
		t.Fatalf("expected permissions to include settings.manage, got %#v", response.Authorization["permissions"])
	}
}

func TestCurrentOrganizationAuthorizationEndpointRequiresSelectionForMultipleMemberships(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	registerResp := performJSONRequest(t, env.router, http.MethodPost, "/api/account/register", map[string]string{
		"username": "org_authz_multi",
		"password": "demo12345",
	}, nil, nil)
	if registerResp.Code != http.StatusOK {
		t.Fatalf("expected register status 200, got %d with body %s", registerResp.Code, registerResp.Body.String())
	}

	sessionCookie := requireCookie(t, registerResp, auth.OIDCSessionCookieName)
	body := decodeBodyMap(t, registerResp)
	userID := body["user_id"].(string)

	now := time.Now()
	for _, org := range []iam.Organization{
		{
			OrganizationID: "org_alpha0000000000",
			Slug:           "alpha",
			Name:           "Alpha Inc",
			Status:         iam.OrganizationStatusActive,
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		{
			OrganizationID: "org_beta00000000000",
			Slug:           "beta",
			Name:           "Beta Inc",
			Status:         iam.OrganizationStatusActive,
			CreatedAt:      now,
			UpdatedAt:      now,
		},
	} {
		if err := env.db.Create(&org).Error; err != nil {
			t.Fatalf("failed to create organization %s: %v", org.OrganizationID, err)
		}
	}
	for _, membership := range []iam.OrganizationMembership{
		{
			OrganizationID: "org_alpha0000000000",
			UserID:         userID,
			Status:         iam.MembershipStatusActive,
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		{
			OrganizationID: "org_beta00000000000",
			UserID:         userID,
			Status:         iam.MembershipStatusActive,
			CreatedAt:      now.Add(time.Second),
			UpdatedAt:      now.Add(time.Second),
		},
	} {
		if err := env.db.Create(&membership).Error; err != nil {
			t.Fatalf("failed to create membership %s: %v", membership.OrganizationID, err)
		}
	}

	resp := performJSONRequest(t, env.router, http.MethodGet, "/api/user/organization/authorization", nil, sessionCookie, nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected authorization status 400, got %d with body %s", resp.Code, resp.Body.String())
	}

	var response map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode authorization error response: %v", err)
	}
	if response["error"] != "organization_selection_required" {
		t.Fatalf("expected organization_selection_required, got %#v", response["error"])
	}

	resp = performJSONRequest(t, env.router, http.MethodGet, "/api/user/organization/authorization?org_hint=beta", nil, sessionCookie, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected authorization status 200 with org_hint, got %d with body %s", resp.Code, resp.Body.String())
	}
}

func TestRequireOrganizationPermissionMiddleware(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	env.router.GET("/api/test/org-permission", env.handler.AuthRequired(), env.handler.RequireOrganizationPermission("settings.manage"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	registerResp := performJSONRequest(t, env.router, http.MethodPost, "/api/account/register", map[string]string{
		"username": "org_permission_user",
		"password": "demo12345",
	}, nil, nil)
	if registerResp.Code != http.StatusOK {
		t.Fatalf("expected register status 200, got %d with body %s", registerResp.Code, registerResp.Body.String())
	}

	sessionCookie := requireCookie(t, registerResp, auth.OIDCSessionCookieName)
	body := decodeBodyMap(t, registerResp)
	userID := body["user_id"].(string)

	now := time.Now()
	if err := env.db.Create(&iam.Organization{
		OrganizationID: "org_acme0000000000",
		Slug:           "acme",
		Name:           "Acme Inc",
		Status:         iam.OrganizationStatusActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create organization: %v", err)
	}
	if err := env.db.Create(&iam.OrganizationMembership{
		OrganizationID: "org_acme0000000000",
		UserID:         userID,
		Status:         iam.MembershipStatusActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create membership: %v", err)
	}

	resp := performJSONRequest(t, env.router, http.MethodGet, "/api/test/org-permission?organization_id=org_acme0000000000", nil, sessionCookie, nil)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected permission check to fail without role permission, got %d with body %s", resp.Code, resp.Body.String())
	}

	if err := env.db.Create(&iam.OrganizationRole{
		RoleID:         "rol_acmesettings000",
		OrganizationID: "org_acme0000000000",
		Name:           "Settings Admin",
		Slug:           "settings-admin",
		Enabled:        true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create role: %v", err)
	}
	if err := env.db.Create(&iam.OrganizationRolePermission{
		OrganizationID: "org_acme0000000000",
		RoleID:         "rol_acmesettings000",
		PermissionKey:  "settings.manage",
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create role permission: %v", err)
	}
	if err := env.db.Create(&iam.OrganizationRoleBinding{
		BindingID:      "rbd_acmesettings000",
		OrganizationID: "org_acme0000000000",
		RoleID:         "rol_acmesettings000",
		SubjectType:    iam.RoleBindingSubjectMembership,
		SubjectID:      userID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create role binding: %v", err)
	}

	resp = performJSONRequest(t, env.router, http.MethodGet, "/api/test/org-permission?organization_id=org_acme0000000000", nil, sessionCookie, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected permission check to succeed, got %d with body %s", resp.Code, resp.Body.String())
	}
}
