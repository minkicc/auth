package iam

import (
	"context"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
)

func TestDatabaseClaimMapperHookInjectsClaims(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:claim-mapper-hook?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}
	rule, err := ClaimMapperRuleFromSpec("clm_test", ClaimMapperRuleSpec{
		Name:          "Tenant Claim",
		Enabled:       true,
		Claim:         "tenant_key",
		Value:         "tenant:${claim.org_slug}:${user.username}:${client_id}",
		Events:        []string{string(HookBeforeTokenIssue)},
		Clients:       []string{"demo-spa"},
		Organizations: []string{"acme"},
	}, nil)
	if err != nil {
		t.Fatalf("failed to build claim mapper rule: %v", err)
	}
	copyRule, err := ClaimMapperRuleFromSpec("clm_roles", ClaimMapperRuleSpec{
		Name:      "Role Copy",
		Enabled:   true,
		Claim:     "app_roles",
		ValueFrom: "claim.org_roles",
		Events:    []string{string(HookBeforeTokenIssue)},
	}, nil)
	if err != nil {
		t.Fatalf("failed to build role copy rule: %v", err)
	}
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("failed to create claim mapper rule: %v", err)
	}
	if err := db.Create(&copyRule).Error; err != nil {
		t.Fatalf("failed to create claim mapper rule: %v", err)
	}

	data := &HookContext{
		User:     &auth.User{UserID: "usr_test", Username: "ada"},
		ClientID: "demo-spa",
		Claims: map[string]any{
			"org_slug":  "acme",
			"org_roles": []string{"admin", "billing"},
		},
	}
	if err := NewDatabaseClaimMapperHook(db).Handle(context.Background(), HookBeforeTokenIssue, data); err != nil {
		t.Fatalf("failed to run claim mapper hook: %v", err)
	}
	if data.Claims["tenant_key"] != "tenant:acme:ada:demo-spa" {
		t.Fatalf("unexpected tenant_key claim: %#v", data.Claims["tenant_key"])
	}
	roles, ok := data.Claims["app_roles"].([]string)
	if !ok || len(roles) != 2 || roles[0] != "admin" || roles[1] != "billing" {
		t.Fatalf("unexpected app_roles claim: %#v", data.Claims["app_roles"])
	}
}

func TestDatabaseClaimMapperHookSkipsNonMatchingScope(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:claim-mapper-skip?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}
	rule, err := ClaimMapperRuleFromSpec("clm_test", ClaimMapperRuleSpec{
		Name:    "Tenant Claim",
		Enabled: true,
		Claim:   "tenant_key",
		Value:   "tenant",
		Clients: []string{"demo-spa"},
	}, nil)
	if err != nil {
		t.Fatalf("failed to build claim mapper rule: %v", err)
	}
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("failed to create claim mapper rule: %v", err)
	}

	data := &HookContext{ClientID: "other-client", Claims: map[string]any{}}
	if err := NewDatabaseClaimMapperHook(db).Handle(context.Background(), HookBeforeTokenIssue, data); err != nil {
		t.Fatalf("failed to run claim mapper hook: %v", err)
	}
	if _, ok := data.Claims["tenant_key"]; ok {
		t.Fatalf("expected non-matching client to be skipped, got %#v", data.Claims)
	}
}

func TestClaimMapperRuleRejectsProtectedClaims(t *testing.T) {
	_, err := ClaimMapperRuleFromSpec("clm_bad", ClaimMapperRuleSpec{
		Name:    "Bad",
		Enabled: true,
		Claim:   "sub",
		Value:   "attacker",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "protected") {
		t.Fatalf("expected protected claim error, got %v", err)
	}
}
