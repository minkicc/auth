package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
	"minki.cc/mkauth/server/plugins"
)

func TestSafeEnterpriseOIDCReturnURI(t *testing.T) {
	h := &AuthHandler{config: &config.Config{OIDC: config.OIDCConfig{Issuer: "https://auth.example.com"}}}

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "relative path", raw: "/oauth2/authorize?client_id=demo", want: "/oauth2/authorize?client_id=demo"},
		{name: "same origin absolute", raw: "https://auth.example.com/oauth2/authorize", want: "https://auth.example.com/oauth2/authorize"},
		{name: "cross origin absolute", raw: "https://evil.example.com/callback", want: ""},
		{name: "protocol relative", raw: "//evil.example.com/callback", want: ""},
		{name: "plain text", raw: "not a url", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.safeEnterpriseOIDCReturnURI(tc.raw); got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestGetPluginsReturnsInstalledPluginSummaries(t *testing.T) {
	gin.SetMode(gin.TestMode)

	registry, err := plugins.NewRegistry(config.PluginsConfig{})
	if err != nil {
		t.Fatalf("failed to create plugin registry: %v", err)
	}
	registry.Register(plugins.Summary{
		ID:      "enterprise_oidc",
		Name:    "Enterprise OIDC",
		Type:    string(plugins.PluginTypeIdentityConnector),
		Source:  plugins.PluginSourceBuiltin,
		Enabled: true,
	})

	h := &AuthHandler{pluginRegistry: registry}
	router := gin.New()
	router.GET("/plugins", h.GetPlugins)

	req := httptest.NewRequest(http.MethodGet, "/plugins", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	var body struct {
		Plugins []plugins.Summary `json:"plugins"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(body.Plugins) != 1 || body.Plugins[0].ID != "enterprise_oidc" {
		t.Fatalf("unexpected plugins response: %#v", body.Plugins)
	}
}

func TestDiscoverEnterpriseOIDC(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open("file:enterprise-oidc-handler-discover?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := iam.NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}
	if err := db.Create(&iam.Organization{
		OrganizationID: "org_acme000000000000",
		Slug:           "acme",
		Name:           "Acme Inc",
		DisplayName:    "Acme",
		Status:         iam.OrganizationStatusActive,
	}).Error; err != nil {
		t.Fatalf("failed to create organization: %v", err)
	}
	if err := db.Create(&iam.OrganizationDomain{
		Domain:         "example.com",
		OrganizationID: "org_acme000000000000",
		Verified:       true,
	}).Error; err != nil {
		t.Fatalf("failed to create organization domain: %v", err)
	}

	manager, err := iam.NewEnterpriseOIDCManager(config.IAMConfig{EnterpriseOIDC: []config.EnterpriseOIDCProviderConfig{{
		Slug:           "acme",
		Name:           "Acme Workforce",
		OrganizationID: "org_acme000000000000",
		Issuer:         "https://login.acme.test",
		ClientID:       "acme-client",
		ClientSecret:   "acme-secret",
		RedirectURI:    "https://auth.example.com/api/enterprise/oidc/acme/callback",
	}}}, db, nil)
	if err != nil {
		t.Fatalf("failed to create enterprise oidc manager: %v", err)
	}

	h := &AuthHandler{enterpriseOIDC: manager}
	router := gin.New()
	router.GET("/enterprise/oidc/discover", h.DiscoverEnterpriseOIDC)

	req := httptest.NewRequest(http.MethodGet, "/enterprise/oidc/discover?email=user@example.com", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d with body %s", recorder.Code, recorder.Body.String())
	}
	var body iam.EnterpriseOIDCDiscoveryResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode discovery response: %v", err)
	}
	if body.Status != iam.EnterpriseOIDCDiscoveryMatched || len(body.Providers) != 1 || body.Providers[0].Slug != "acme" {
		t.Fatalf("unexpected discovery body: %#v", body)
	}
}

func TestDiscoverEnterpriseOIDCRejectsInvalidEmail(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open("file:enterprise-oidc-handler-invalid-email?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := iam.NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}
	manager, err := iam.NewEnterpriseOIDCManager(config.IAMConfig{EnterpriseOIDC: []config.EnterpriseOIDCProviderConfig{{
		Slug:         "acme",
		Name:         "Acme Workforce",
		Issuer:       "https://login.acme.test",
		ClientID:     "acme-client",
		ClientSecret: "acme-secret",
		RedirectURI:  "https://auth.example.com/api/enterprise/oidc/acme/callback",
	}}}, db, nil)
	if err != nil {
		t.Fatalf("failed to create enterprise oidc manager: %v", err)
	}

	h := &AuthHandler{enterpriseOIDC: manager}
	router := gin.New()
	router.GET("/enterprise/oidc/discover", h.DiscoverEnterpriseOIDC)

	req := httptest.NewRequest(http.MethodGet, "/enterprise/oidc/discover?email=invalid-email", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d with body %s", recorder.Code, recorder.Body.String())
	}
}

func TestDiscoverEnterpriseOIDCByDomain(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open("file:enterprise-oidc-handler-domain?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := iam.NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}
	if err := db.Create(&iam.Organization{
		OrganizationID: "org_globex000000000",
		Slug:           "globex",
		Name:           "Globex Corp",
		Status:         iam.OrganizationStatusActive,
	}).Error; err != nil {
		t.Fatalf("failed to create organization: %v", err)
	}
	if err := db.Create(&iam.OrganizationDomain{
		Domain:         "globex.com",
		OrganizationID: "org_globex000000000",
		Verified:       true,
	}).Error; err != nil {
		t.Fatalf("failed to create organization domain: %v", err)
	}

	manager, err := iam.NewEnterpriseOIDCManager(config.IAMConfig{EnterpriseOIDC: []config.EnterpriseOIDCProviderConfig{{
		Slug:           "globex",
		Name:           "Globex Workforce",
		OrganizationID: "org_globex000000000",
		Issuer:         "https://login.globex.test",
		ClientID:       "globex-client",
		ClientSecret:   "globex-secret",
		RedirectURI:    "https://auth.example.com/api/enterprise/oidc/globex/callback",
	}}}, db, nil)
	if err != nil {
		t.Fatalf("failed to create enterprise oidc manager: %v", err)
	}

	h := &AuthHandler{enterpriseOIDC: manager}
	router := gin.New()
	router.GET("/enterprise/oidc/discover", h.DiscoverEnterpriseOIDC)

	req := httptest.NewRequest(http.MethodGet, "/enterprise/oidc/discover?domain=globex.com", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d with body %s", recorder.Code, recorder.Body.String())
	}
	var body iam.EnterpriseOIDCDiscoveryResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode discovery response: %v", err)
	}
	if body.Status != iam.EnterpriseOIDCDiscoveryMatched || body.Domain != "globex.com" || len(body.Providers) != 1 {
		t.Fatalf("unexpected domain discovery body: %#v", body)
	}
}
