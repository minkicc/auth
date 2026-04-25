package oidc

import (
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/glebarez/sqlite"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/secureconfig"
)

func TestProviderReloadLoadsDatabaseClients(t *testing.T) {
	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer redisServer.Close()

	redisClient := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	defer redisClient.Close()

	redisStore := auth.NewRedisStoreFromClient(redisClient)
	accountRedis := auth.NewAccountRedisStore(redisClient)

	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}

	accountAuth := auth.NewAccountAuth(db, auth.AccountAuthConfig{
		MaxLoginAttempts:  5,
		LoginLockDuration: 15 * time.Minute,
		Redis:             accountRedis,
	})
	if err := accountAuth.AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate account tables: %v", err)
	}

	provider, err := NewProvider(config.OIDCConfig{
		Enabled: true,
		Issuer:  "http://127.0.0.1:8080",
	}, db, redisStore, accountAuth)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	if _, ok := provider.findClient("db-client"); ok {
		t.Fatalf("expected database client to be absent before insert")
	}

	record, err := ClientRecordFromConfig(config.OIDCClientConfig{
		Name:         "Database App",
		ClientID:     "db-client",
		ClientSecret: "super-secret",
		RedirectURIs: []string{"https://app.example.com/callback"},
		Scopes:       []string{"openid", "profile", "email"},
		OIDCOrganizationPolicy: config.OIDCOrganizationPolicy{
			RequireOrganization:  true,
			AllowedOrganizations: []string{"acme"},
			RequiredOrgRoles:     []string{"admin"},
			RequiredOrgRolesAll:  []string{"security"},
		},
		ScopePolicies: map[string]config.OIDCOrganizationPolicy{
			"email": {
				RequiredOrgGroupsAll: []string{"employees"},
			},
		},
	}, true)
	if err != nil {
		t.Fatalf("failed to build client record: %v", err)
	}
	if err := db.Create(&record).Error; err != nil {
		t.Fatalf("failed to insert oidc client record: %v", err)
	}

	if err := provider.Reload(); err != nil {
		t.Fatalf("failed to reload provider: %v", err)
	}

	client, ok := provider.findClient("db-client")
	if !ok {
		t.Fatalf("expected database client to be available after reload")
	}
	if client.Name != "Database App" || !client.RequireOrganization || len(client.RequiredOrgRoles) != 1 || client.RequiredOrgRoles[0] != "admin" {
		t.Fatalf("unexpected reloaded client: %#v", client)
	}
	if len(client.RequiredOrgRolesAll) != 1 || client.RequiredOrgRolesAll[0] != "security" {
		t.Fatalf("expected RequiredOrgRolesAll to reload, got %#v", client.RequiredOrgRolesAll)
	}
	if policy, ok := client.ScopePolicies["email"]; !ok || len(policy.RequiredOrgGroupsAll) != 1 || policy.RequiredOrgGroupsAll[0] != "employees" {
		t.Fatalf("expected email scope policy to reload, got %#v", client.ScopePolicies)
	}
	origins := provider.AllowedOrigins()
	if len(origins) != 1 || origins[0] != "https://app.example.com" {
		t.Fatalf("unexpected allowed origins: %#v", origins)
	}

	if err := db.Model(&ClientRecord{}).Where("client_id = ?", "db-client").Update("enabled", false).Error; err != nil {
		t.Fatalf("failed to disable oidc client: %v", err)
	}
	if err := provider.Reload(); err != nil {
		t.Fatalf("failed to reload provider after disable: %v", err)
	}
	if _, ok := provider.findClient("db-client"); ok {
		t.Fatalf("expected disabled database client to disappear from runtime")
	}
}

func TestClientRecordFromConfigNormalizesValues(t *testing.T) {
	codec, err := secureconfig.New("provider-client-test-key")
	if err != nil {
		t.Fatalf("failed to create secure config codec: %v", err)
	}
	secureconfig.SetDefault(codec)
	defer secureconfig.SetDefault(nil)

	record, err := ClientRecordFromConfig(config.OIDCClientConfig{
		Name:         " Demo App ",
		ClientID:     " demo-app ",
		ClientSecret: " secret ",
		RedirectURIs: []string{" https://app.example.com/callback ", "https://app.example.com/callback"},
		Scopes:       []string{" profile ", "openid", "profile", "email"},
		OIDCOrganizationPolicy: config.OIDCOrganizationPolicy{
			AllowedOrganizations: []string{" Acme ", "acme"},
			RequiredOrgRolesAll:  []string{" Admin ", "admin"},
		},
		ScopePolicies: map[string]config.OIDCOrganizationPolicy{
			" Email ": {
				RequiredOrgGroups:    []string{" Employees ", "employees"},
				RequiredOrgGroupsAll: []string{" Staff ", "staff"},
			},
		},
	}, true)
	if err != nil {
		t.Fatalf("ClientRecordFromConfig() returned error: %v", err)
	}
	if !strings.HasPrefix(record.ConfigJSON, "enc:v1:") {
		t.Fatalf("expected encrypted config json, got %q", record.ConfigJSON)
	}
	client, err := ClientConfigFromRecord(record)
	if err != nil {
		t.Fatalf("ClientConfigFromRecord() returned error: %v", err)
	}
	if client.ClientID != "demo-app" || client.Name != "Demo App" || client.ClientSecret != "secret" {
		t.Fatalf("unexpected normalized client: %#v", client)
	}
	if got := strings.Join(client.Scopes, ","); got != "email,openid,profile" {
		t.Fatalf("unexpected normalized scopes: %s", got)
	}
	if got := strings.Join(client.AllowedOrganizations, ","); got != "Acme" {
		t.Fatalf("unexpected normalized organizations: %s", got)
	}
	if got := strings.Join(client.RequiredOrgRolesAll, ","); got != "admin" {
		t.Fatalf("unexpected normalized required_org_roles_all: %s", got)
	}
	policy, ok := client.ScopePolicies["email"]
	if !ok {
		t.Fatalf("expected normalized email scope policy, got %#v", client.ScopePolicies)
	}
	if got := strings.Join(policy.RequiredOrgGroups, ","); got != "employees" {
		t.Fatalf("unexpected normalized scope required_org_groups: %s", got)
	}
	if got := strings.Join(policy.RequiredOrgGroupsAll, ","); got != "staff" {
		t.Fatalf("unexpected normalized scope required_org_groups_all: %s", got)
	}
}

func TestValidateClientConfigRejectsUnknownScopePolicy(t *testing.T) {
	err := ValidateClientConfig(config.OIDCClientConfig{
		ClientID:     "demo-app",
		ClientSecret: "secret",
		RedirectURIs: []string{"https://app.example.com/callback"},
		Scopes:       []string{"openid", "profile"},
		ScopePolicies: map[string]config.OIDCOrganizationPolicy{
			"email": {
				RequiredOrgRoles: []string{"admin"},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported scope") {
		t.Fatalf("expected unsupported scope policy error, got %v", err)
	}
}
