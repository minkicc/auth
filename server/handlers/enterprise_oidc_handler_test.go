package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"minki.cc/mkauth/server/config"
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
