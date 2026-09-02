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

	response := performJSONRequest(t, router, http.MethodGet, "/api/weixin/url?client_id=k12", nil, nil, nil)
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
