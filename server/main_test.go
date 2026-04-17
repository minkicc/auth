package main

import (
	"reflect"
	"testing"

	"minki.cc/mkauth/server/config"
)

func TestCollectAllowedOrigins(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			Google: config.GoogleConfig{
				RedirectURL: "https://console.example.com/google/callback",
			},
			Weixin: config.WeixinConfig{
				RedirectURL: "https://console.example.com/weixin/callback",
			},
		},
		OIDC: config.OIDCConfig{
			Issuer: "https://auth.example.com",
			Clients: []config.OIDCClientConfig{
				{
					ClientID: "demo-spa",
					RedirectURIs: []string{
						"https://app.example.com/auth/callback",
						"https://app.example.com/another",
						"http://localhost:3000/callback",
					},
				},
			},
		},
	}

	got := collectAllowedOrigins(cfg)
	want := []string{
		"http://localhost:3000",
		"https://app.example.com",
		"https://auth.example.com",
		"https://console.example.com",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collectAllowedOrigins() = %v, want %v", got, want)
	}
}
