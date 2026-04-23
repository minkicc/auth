package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

func TestSCIMInboundProvisioningCreatesAndDisablesUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, router := newSCIMTestRouter(t, "scim-secret")

	createResp := performSCIMJSON(t, router, http.MethodPost, "/api/scim/v2/Users", map[string]any{
		"schemas":     []string{scimUserSchema},
		"externalId":  "00u-scim-ada",
		"userName":    "Ada@Example.COM",
		"displayName": "Ada Lovelace",
		"active":      true,
		"emails": []map[string]any{{
			"value":   "Ada@Example.COM",
			"primary": true,
			"type":    "work",
		}},
		"roles": []map[string]any{{"value": "admin"}, {"value": "developer"}},
	}, "scim-secret")
	if createResp.Code != http.StatusCreated {
		t.Fatalf("expected create status 201, got %d with body %s", createResp.Code, createResp.Body.String())
	}
	var created scimUserResource
	if err := json.Unmarshal(createResp.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to decode SCIM create response: %v", err)
	}
	if created.ID == "" || created.UserName != "Ada@Example.COM" || !created.Active {
		t.Fatalf("unexpected SCIM create response: %#v", created)
	}

	var identity iam.ExternalIdentity
	if err := db.First(&identity, "provider_type = ? AND provider_id = ? AND subject = ?", iam.IdentityProviderTypeSCIM, "acme-scim", "00u-scim-ada").Error; err != nil {
		t.Fatalf("expected external identity: %v", err)
	}
	if identity.UserID != created.ID || identity.Email != "ada@example.com" || !identity.EmailVerified {
		t.Fatalf("unexpected external identity: %#v", identity)
	}

	var membership iam.OrganizationMembership
	if err := db.First(&membership, "organization_id = ? AND user_id = ?", "org_acme", created.ID).Error; err != nil {
		t.Fatalf("expected organization membership: %v", err)
	}
	if membership.Status != iam.MembershipStatusActive || membership.RolesJSON != `["admin","developer"]` {
		t.Fatalf("unexpected membership: %#v", membership)
	}

	listResp := performSCIMJSON(t, router, http.MethodGet, "/api/scim/v2/Users?filter=userName%20eq%20%22ada@example.com%22", nil, "scim-secret")
	if listResp.Code != http.StatusOK {
		t.Fatalf("expected list status 200, got %d with body %s", listResp.Code, listResp.Body.String())
	}
	var list scimListResponse
	if err := json.Unmarshal(listResp.Body.Bytes(), &list); err != nil {
		t.Fatalf("failed to decode SCIM list response: %v", err)
	}
	if list.TotalResults != 1 || len(list.Resources) != 1 || list.Resources[0].ID != created.ID {
		t.Fatalf("unexpected SCIM list response: %#v", list)
	}

	patchResp := performSCIMJSON(t, router, http.MethodPatch, "/api/scim/v2/Users/"+created.ID, map[string]any{
		"schemas": []string{scimPatchSchema},
		"Operations": []map[string]any{{
			"op":    "Replace",
			"path":  "active",
			"value": false,
		}},
	}, "scim-secret")
	if patchResp.Code != http.StatusOK {
		t.Fatalf("expected patch status 200, got %d with body %s", patchResp.Code, patchResp.Body.String())
	}
	var patched scimUserResource
	if err := json.Unmarshal(patchResp.Body.Bytes(), &patched); err != nil {
		t.Fatalf("failed to decode SCIM patch response: %v", err)
	}
	if patched.Active {
		t.Fatalf("expected patched user to be inactive: %#v", patched)
	}

	var user auth.User
	if err := db.First(&user, "user_id = ?", created.ID).Error; err != nil {
		t.Fatalf("expected user: %v", err)
	}
	if user.Status != auth.UserStatusInactive {
		t.Fatalf("expected user to be inactive, got %s", user.Status)
	}
	if err := db.First(&membership, "organization_id = ? AND user_id = ?", "org_acme", created.ID).Error; err != nil {
		t.Fatalf("expected organization membership after patch: %v", err)
	}
	if membership.Status != iam.MembershipStatusDisabled {
		t.Fatalf("expected membership to be disabled, got %s", membership.Status)
	}
}

func TestSCIMInboundRequiresBearerToken(t *testing.T) {
	_, router := newSCIMTestRouter(t, "scim-secret")
	resp := performSCIMJSON(t, router, http.MethodGet, "/api/scim/v2/Users", nil, "")
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized status 401, got %d with body %s", resp.Code, resp.Body.String())
	}
}

func newSCIMTestRouter(t *testing.T, token string) (*gorm.DB, *gin.Engine) {
	t.Helper()
	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("failed to get sqlite handle: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&auth.User{}); err != nil {
		t.Fatalf("failed to migrate user table: %v", err)
	}
	service := iam.NewService(db)
	if err := service.AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}
	if err := db.Create(&iam.Organization{OrganizationID: "org_acme", Slug: "acme", Name: "Acme", Status: iam.OrganizationStatusActive}).Error; err != nil {
		t.Fatalf("failed to create organization: %v", err)
	}
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash SCIM token: %v", err)
	}
	handler := NewSCIMHandler(config.IAMConfig{SCIMInbound: []config.SCIMInboundConfig{{
		Enabled:         true,
		Slug:            "acme-scim",
		Name:            "Acme SCIM",
		OrganizationID:  "org_acme",
		BearerTokenHash: string(tokenHash),
	}}}, db, service)
	if handler == nil || !handler.Enabled() {
		t.Fatalf("expected SCIM handler to be enabled")
	}
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api/scim/v2"))
	return db, router
}

func performSCIMJSON(t *testing.T, router *gin.Engine, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("failed to marshal SCIM body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	return resp
}
