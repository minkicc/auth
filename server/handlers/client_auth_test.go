package handlers

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"example.com/auth/server/auth"
	"example.com/auth/server/config"
)

const (
	testPhoneClientID     = "phone-backend"
	testPhoneClientSecret = "phone-backend-secret"
	testPhoneNumber       = "+8613800138000"
)

func clientPhoneTestOIDCConfig(scopes []string) config.OIDCConfig {
	return config.OIDCConfig{
		Enabled: true,
		Issuer:  "http://127.0.0.1:8080",
		Clients: []config.OIDCClientConfig{
			{
				ClientID:     testPhoneClientID,
				ClientSecret: testPhoneClientSecret,
				GrantTypes:   []string{"phone_code"},
				Scopes:       scopes,
			},
			{
				ClientID:     "regular-backend",
				ClientSecret: "regular-backend-secret",
				GrantTypes:   []string{"authorization_code"},
				RedirectURIs: []string{"http://127.0.0.1:8082/auth/callback"},
				Scopes:       []string{"openid"},
			},
		},
	}
}

func clientBasicAuth(clientID, clientSecret string) map[string]string {
	credentials := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	return map[string]string{"Authorization": "Basic " + credentials}
}

func sendClientPhoneLoginCode(t *testing.T, env *authTestEnv, headers map[string]string) string {
	t.Helper()
	before := len(env.smsService.verificationSMS)
	resp := performJSONRequest(t, env.router, http.MethodPost, "/api/client/phone/send-login-code", map[string]string{
		"phone": testPhoneNumber,
	}, nil, headers)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected send-login-code status 200, got %d with body %s", resp.Code, resp.Body.String())
	}
	if len(env.smsService.verificationSMS) != before+1 {
		t.Fatalf("expected one login verification SMS, got %d new messages", len(env.smsService.verificationSMS)-before)
	}
	return env.smsService.verificationSMS[len(env.smsService.verificationSMS)-1].Code
}

func TestClientPhoneLoginRequiresAuthorizedPhoneCodeClient(t *testing.T) {
	env := newAuthTestEnvWithOIDCProvider(t, clientPhoneTestOIDCConfig([]string{"openid"}))
	defer env.Close()

	tests := []struct {
		name    string
		headers map[string]string
	}{
		{name: "wrong secret", headers: clientBasicAuth(testPhoneClientID, "wrong-secret")},
		{name: "missing phone code grant", headers: clientBasicAuth("regular-backend", "regular-backend-secret")},
		{name: "missing credentials", headers: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp := performJSONRequest(t, env.router, http.MethodPost, "/api/client/phone/send-login-code", map[string]string{
				"phone": testPhoneNumber,
			}, nil, test.headers)
			if resp.Code != http.StatusUnauthorized || !strings.Contains(resp.Body.String(), "invalid_client") {
				t.Fatalf("expected invalid_client status 401, got %d with body %s", resp.Code, resp.Body.String())
			}
		})
	}
}

func TestClientPhoneCodeLoginIssuesOnlyAllowedScopes(t *testing.T) {
	env := newAuthTestEnvWithOIDCProvider(t, clientPhoneTestOIDCConfig([]string{"openid"}))
	defer env.Close()
	requireVerifiedPhoneUser(t, env, testPhoneNumber, "demo12345")

	headers := clientBasicAuth(testPhoneClientID, testPhoneClientSecret)
	code := sendClientPhoneLoginCode(t, env, headers)
	resp := performJSONRequest(t, env.router, http.MethodPost, "/api/client/phone/code-login", map[string]string{
		"phone": testPhoneNumber,
		"code":  code,
	}, nil, headers)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected code-login status 200, got %d with body %s", resp.Code, resp.Body.String())
	}
	body := decodeBodyMap(t, resp)
	if body["scope"] != "openid" {
		t.Fatalf("expected scope to be constrained to openid, got %#v", body["scope"])
	}
	accessToken, ok := body["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatalf("expected access token, got %#v", body["access_token"])
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(accessToken, claims); err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	if claims["scope"] != "openid" {
		t.Fatalf("expected access token scope openid, got %#v", claims["scope"])
	}
	if _, ok := body["id_token"].(string); !ok {
		t.Fatalf("expected ID token, got %#v", body["id_token"])
	}
	if _, ok := body["refresh_token"]; ok {
		t.Fatalf("did not expect refresh token for phone_code-only client")
	}
	if len(resp.Result().Cookies()) != 0 {
		t.Fatalf("client phone login must not create browser cookies")
	}
}

func TestClientPhoneCodeLoginRejectsInvalidCodeAndDisabledUser(t *testing.T) {
	env := newAuthTestEnvWithOIDCProvider(t, clientPhoneTestOIDCConfig([]string{"openid", "profile"}))
	defer env.Close()
	requireVerifiedPhoneUser(t, env, testPhoneNumber, "demo12345")

	headers := clientBasicAuth(testPhoneClientID, testPhoneClientSecret)
	code := sendClientPhoneLoginCode(t, env, headers)
	invalidCode := "000000"
	if code == invalidCode {
		invalidCode = "000001"
	}
	invalidResp := performJSONRequest(t, env.router, http.MethodPost, "/api/client/phone/code-login", map[string]string{
		"phone": testPhoneNumber,
		"code":  invalidCode,
	}, nil, headers)
	if invalidResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected invalid code status 401, got %d with body %s", invalidResp.Code, invalidResp.Body.String())
	}

	var phoneUser auth.PhoneUser
	if err := env.db.First(&phoneUser, "phone = ?", testPhoneNumber).Error; err != nil {
		t.Fatalf("find phone user: %v", err)
	}
	if err := env.db.Model(&auth.User{}).Where("user_id = ?", phoneUser.UserID).Update("status", auth.UserStatusInactive).Error; err != nil {
		t.Fatalf("disable phone user: %v", err)
	}
	disabledResp := performJSONRequest(t, env.router, http.MethodPost, "/api/client/phone/code-login", map[string]string{
		"phone": testPhoneNumber,
		"code":  code,
	}, nil, headers)
	if disabledResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected disabled user status 401, got %d with body %s", disabledResp.Code, disabledResp.Body.String())
	}
}

func TestClientPhoneCodeLoginRateLimitsFailures(t *testing.T) {
	env := newAuthTestEnvWithOIDCProvider(t, clientPhoneTestOIDCConfig([]string{"openid"}))
	defer env.Close()
	requireVerifiedPhoneUser(t, env, testPhoneNumber, "demo12345")

	headers := clientBasicAuth(testPhoneClientID, testPhoneClientSecret)
	code := sendClientPhoneLoginCode(t, env, headers)
	invalidCode := "000000"
	if code == invalidCode {
		invalidCode = "000001"
	}
	for attempt := 1; attempt <= 5; attempt++ {
		resp := performJSONRequest(t, env.router, http.MethodPost, "/api/client/phone/code-login", map[string]string{
			"phone": testPhoneNumber,
			"code":  invalidCode,
		}, nil, headers)
		if resp.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d expected status 401, got %d with body %s", attempt, resp.Code, resp.Body.String())
		}
	}
	limitedResp := performJSONRequest(t, env.router, http.MethodPost, "/api/client/phone/code-login", map[string]string{
		"phone": testPhoneNumber,
		"code":  invalidCode,
	}, nil, headers)
	if limitedResp.Code != http.StatusTooManyRequests {
		t.Fatalf("expected rate-limited status 429, got %d with body %s", limitedResp.Code, limitedResp.Body.String())
	}
}
