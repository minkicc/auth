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
