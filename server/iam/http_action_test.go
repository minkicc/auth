package iam

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
)

func TestHTTPActionHookMergesClaimsAndMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-secret" {
			t.Fatalf("expected bearer secret header")
		}
		var payload HTTPActionRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}
		if payload.Event != HookBeforeTokenIssue || payload.User.UserID != "usr_test" {
			t.Fatalf("unexpected action payload: %#v", payload)
		}
		_ = json.NewEncoder(w).Encode(HTTPActionResponse{
			Claims:   map[string]any{"department": "engineering"},
			Metadata: map[string]string{"risk": "low"},
		})
	}))
	defer server.Close()

	hook, err := NewHTTPActionHook(config.HTTPActionConfig{
		ID:      "claims",
		Enabled: true,
		Events:  []string{string(HookBeforeTokenIssue)},
		URL:     server.URL,
		Secret:  "test-secret",
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}

	data := &HookContext{
		User:   &auth.User{UserID: "usr_test"},
		Claims: map[string]any{"sub": "usr_test"},
	}
	if err := hook.Handle(context.Background(), HookBeforeTokenIssue, data); err != nil {
		t.Fatalf("failed to run hook: %v", err)
	}
	if data.Claims["department"] != "engineering" {
		t.Fatalf("expected merged department claim, got %#v", data.Claims)
	}
	if data.Metadata["risk"] != "low" {
		t.Fatalf("expected merged risk metadata, got %#v", data.Metadata)
	}
}

func TestHTTPActionHookCanDeny(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allow := false
		_ = json.NewEncoder(w).Encode(HTTPActionResponse{Allow: &allow, Error: "blocked"})
	}))
	defer server.Close()

	hook, err := NewHTTPActionHook(config.HTTPActionConfig{
		ID:      "risk",
		Enabled: true,
		Events:  []string{string(HookPostAuthenticate)},
		URL:     server.URL,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}

	if err := hook.Handle(context.Background(), HookPostAuthenticate, &HookContext{}); err == nil {
		t.Fatalf("expected denied hook error")
	}
}

func TestHTTPActionHookSkipsUnconfiguredEvents(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()

	hook, err := NewHTTPActionHook(config.HTTPActionConfig{
		ID:      "claims",
		Enabled: true,
		Events:  []string{string(HookBeforeUserInfo)},
		URL:     server.URL,
	})
	if err != nil {
		t.Fatalf("failed to create hook: %v", err)
	}
	if err := hook.Handle(context.Background(), HookBeforeTokenIssue, &HookContext{}); err != nil {
		t.Fatalf("unexpected hook error: %v", err)
	}
	if called {
		t.Fatalf("expected hook to skip unconfigured event")
	}
}
