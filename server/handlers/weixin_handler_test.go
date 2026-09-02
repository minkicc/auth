package handlers

import (
	"net/http"
	"net/url"
	"testing"

	"cc.minki/auth/server/auth"
	"cc.minki/auth/server/config"
	"github.com/gin-gonic/gin"
)

func TestWeixinLoginURLCreatesBrowserRedirectSession(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	weixinLogin, err := auth.NewWeixinLogin(env.db, auth.WeixinConfig{
		AppID:       "wx-test",
		AppSecret:   "secret",
		RedirectURL: "https://auth.example.com/api/weixin/callback",
	}, nil)
	if err != nil {
		t.Fatalf("create WeChat login: %v", err)
	}
	env.handler.weixinLogin = weixinLogin
	router := gin.New()
	env.handler.RegisterRoutes(router.Group(config.API_ROUTER_PATH), env.handler.config)

	response := performJSONRequest(t, router, http.MethodGet, "/api/weixin/url?client_id=k12&redirect_uri=https%3A%2F%2Fauth.example.com%2Foauth2%2Fauthorize%3Fclient_id%3Dk12%26state%3Dstate", nil, nil, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("expected QR session status 200, got %d with body %s", response.Code, response.Body.String())
	}
	body := decodeBodyMap(t, response)
	loginURL, err := url.Parse(body["url"].(string))
	if err != nil {
		t.Fatalf("parse login URL: %v", err)
	}
	if loginURL.Path != "/connect/qrconnect" || loginURL.Query().Get("scope") != "snsapi_login" {
		t.Fatalf("unexpected website application OAuth URL: %s", loginURL.String())
	}
	if len(response.Result().Cookies()) != 1 || response.Result().Cookies()[0].Name != "weixin_client_id" {
		t.Fatalf("expected WeChat browser session cookie, got %#v", response.Result().Cookies())
	}
}

func TestWeixinReturnURIOnlyAllowsLocalOIDCAuthorizeURL(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	tests := []struct {
		name string
		uri  string
		want string
	}{
		{
			name: "local authorize URL",
			uri:  "http://127.0.0.1:8080/oauth2/authorize?client_id=k12&state=state",
			want: "http://127.0.0.1:8080/oauth2/authorize?client_id=k12&state=state",
		},
		{
			name: "external URL",
			uri:  "https://evil.example/callback?client_id=k12",
		},
		{
			name: "different client",
			uri:  "http://127.0.0.1:8080/oauth2/authorize?client_id=other",
		},
		{
			name: "non authorize path",
			uri:  "http://127.0.0.1:8080/profile?client_id=k12",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := env.handler.weixinReturnURI("k12", tt.uri); got != tt.want {
				t.Fatalf("weixinReturnURI() = %q, want %q", got, tt.want)
			}
		})
	}
}
