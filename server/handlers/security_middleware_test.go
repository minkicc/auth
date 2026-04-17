package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"minki.cc/mkauth/server/config"
)

func TestRequireSameOriginForBrowserSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newRouter := func(authMethod string) *gin.Engine {
		handler := &AuthHandler{
			config: &config.Config{
				OIDC: config.OIDCConfig{
					Issuer: "https://auth.example.com",
				},
			},
		}

		router := gin.New()
		router.Use(func(c *gin.Context) {
			if authMethod != "" {
				c.Set("auth_method", authMethod)
			}
			c.Next()
		})
		router.POST("/protected", handler.RequireSameOriginForBrowserSession(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true})
		})
		return router
	}

	tests := []struct {
		name       string
		authMethod string
		origin     string
		referer    string
		wantStatus int
	}{
		{
			name:       "access token bypasses same-origin check",
			authMethod: "access_token",
			wantStatus: http.StatusOK,
		},
		{
			name:       "matching origin is allowed",
			authMethod: "browser_session",
			origin:     "https://auth.example.com",
			wantStatus: http.StatusOK,
		},
		{
			name:       "matching referer is allowed",
			authMethod: "browser_session",
			referer:    "https://auth.example.com/profile",
			wantStatus: http.StatusOK,
		},
		{
			name:       "mismatched origin is rejected",
			authMethod: "browser_session",
			origin:     "https://evil.example.com",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "invalid referer is rejected",
			authMethod: "browser_session",
			referer:    "://not-a-url",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "missing origin and referer is rejected",
			authMethod: "browser_session",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := newRouter(tt.authMethod)
			req := httptest.NewRequest(http.MethodPost, "http://internal.example/protected", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d with body %s", tt.wantStatus, recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestRejectCrossOriginBrowserSessionCreation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := &AuthHandler{
		config: &config.Config{
			OIDC: config.OIDCConfig{
				Issuer: "https://auth.example.com",
			},
		},
	}

	router := gin.New()
	router.POST("/login", handler.RejectCrossOriginBrowserSessionCreation(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	tests := []struct {
		name         string
		origin       string
		referer      string
		secFetchSite string
		wantStatus   int
	}{
		{
			name:       "matching origin is allowed",
			origin:     "https://auth.example.com",
			wantStatus: http.StatusOK,
		},
		{
			name:       "matching referer is allowed",
			referer:    "https://auth.example.com/login",
			wantStatus: http.StatusOK,
		},
		{
			name:       "mismatched origin is rejected",
			origin:     "https://evil.example.com",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "mismatched referer is rejected",
			referer:    "https://evil.example.com/login",
			wantStatus: http.StatusForbidden,
		},
		{
			name:         "browser cross-site signal is rejected",
			secFetchSite: "cross-site",
			wantStatus:   http.StatusForbidden,
		},
		{
			name:       "non-browser call without origin metadata is allowed",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://internal.example/login", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}
			if tt.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tt.secFetchSite)
			}

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d with body %s", tt.wantStatus, recorder.Code, recorder.Body.String())
			}
		})
	}
}
