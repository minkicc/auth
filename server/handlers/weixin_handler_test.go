package handlers

import (
	"net/http"
	"net/url"
	"testing"

	"cc.minki/auth/server/auth"
	"cc.minki/auth/server/config"
	"github.com/gin-gonic/gin"
)

func TestWeixinLoginURLCreatesPendingQRCodeSession(t *testing.T) {
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
	transactionID, _ := body["transaction_id"].(string)
	if transactionID == "" {
		t.Fatalf("expected transaction ID, got %#v", body)
	}
	loginURL, err := url.Parse(body["url"].(string))
	if err != nil {
		t.Fatalf("parse login URL: %v", err)
	}
	if loginURL.Path != "/connect/oauth2/authorize" || loginURL.Query().Get("scope") != "snsapi_userinfo" {
		t.Fatalf("unexpected official account OAuth URL: %s", loginURL.String())
	}

	status := performJSONRequest(t, router, http.MethodGet, "/api/weixin/status?transaction_id="+url.QueryEscape(transactionID), nil, nil, nil)
	if status.Code != http.StatusOK || decodeBodyMap(t, status)["status"] != "pending" {
		t.Fatalf("expected pending QR session, got %d with body %s", status.Code, status.Body.String())
	}
}
