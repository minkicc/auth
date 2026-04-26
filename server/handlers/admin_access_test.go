package handlers

import (
	"net/http"
	"testing"

	"minki.cc/mkauth/server/admin"
	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
)

func TestCurrentUserAdminAccessEndpointReflectsConfiguredAdminUserID(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	registerResp := performJSONRequest(t, env.router, http.MethodPost, "/api/account/register", map[string]string{
		"username": "admin-user",
		"password": "very-secret-password",
	}, nil, nil)
	if registerResp.Code != http.StatusOK {
		t.Fatalf("expected register status 200, got %d with body %s", registerResp.Code, registerResp.Body.String())
	}

	body := decodeBodyMap(t, registerResp)
	userID, _ := body["user_id"].(string)
	if userID == "" {
		t.Fatalf("expected register response to include user_id, got %#v", body)
	}

	env.handler.SetAdminAccess(
		admin.NewAccessController(&config.AdminConfig{UserIDs: []string{userID}}, env.db),
		"/admin",
	)

	sessionCookie := requireCookie(t, registerResp, auth.OIDCSessionCookieName)
	resp := performJSONRequest(t, env.router, http.MethodGet, "/api/user/admin-access", nil, sessionCookie, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected admin access status 200, got %d with body %s", resp.Code, resp.Body.String())
	}

	decoded := decodeBodyMap(t, resp)
	if decoded["enabled"] != true || decoded["is_admin"] != true {
		t.Fatalf("expected admin access to be enabled and granted, got %#v", decoded)
	}
	if decoded["entry_url"] != "/admin" {
		t.Fatalf("expected admin entry_url to be returned, got %#v", decoded)
	}
}
