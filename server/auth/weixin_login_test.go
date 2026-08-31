package auth

import (
	"net/url"
	"testing"
)

func TestWeixinAuthURLUsesOfficialAccountOAuth(t *testing.T) {
	login := &WeixinLogin{Config: WeixinConfig{
		AppID:       "wx-test",
		RedirectURL: "https://auth.example.com/api/weixin/callback",
	}}
	raw := login.GetAuthURL("state-value")
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	if parsed.Path != "/connect/oauth2/authorize" {
		t.Fatalf("expected official account OAuth path, got %q", parsed.Path)
	}
	if got := parsed.Query().Get("scope"); got != "snsapi_userinfo" {
		t.Fatalf("expected snsapi_userinfo scope, got %q", got)
	}
	if got := parsed.Query().Get("state"); got != "state-value" {
		t.Fatalf("expected state to round trip, got %q", got)
	}
}
