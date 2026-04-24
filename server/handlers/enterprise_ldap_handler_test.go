package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

type fakeEnterpriseLDAPAuthenticator struct {
	info            *iam.EnterpriseLDAPUserInfo
	err             error
	lastUsername    string
	lastPassword    string
	lastProviderURL string
}

func (f *fakeEnterpriseLDAPAuthenticator) Authenticate(_ context.Context, cfg config.EnterpriseLDAPProviderConfig, username, password string) (*iam.EnterpriseLDAPUserInfo, error) {
	f.lastUsername = username
	f.lastPassword = password
	f.lastProviderURL = cfg.URL
	if f.err != nil {
		return nil, f.err
	}
	return f.info, nil
}

func TestEnterpriseLDAPLoginCreatesBrowserSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer redisServer.Close()

	redisClient := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	defer redisClient.Close()

	db, err := gorm.Open(sqlite.Open("file:enterprise-ldap-login?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	accountAuth := auth.NewAccountAuth(db, auth.AccountAuthConfig{
		MaxLoginAttempts:  5,
		LoginLockDuration: 15 * time.Minute,
		Redis:             auth.NewAccountRedisStore(redisClient),
	})
	if err := accountAuth.AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate account tables: %v", err)
	}
	if err := iam.NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}

	authenticator := &fakeEnterpriseLDAPAuthenticator{
		info: &iam.EnterpriseLDAPUserInfo{
			Subject:           "ldap-subject-001",
			Email:             "ada@globex.com",
			EmailVerified:     true,
			Name:              "Ada Lovelace",
			PreferredUsername: "ada",
			DN:                "uid=ada,ou=people,dc=globex,dc=test",
			ProfileJSON:       `{"source":"ldap"}`,
		},
	}
	ldapManager, err := iam.NewEnterpriseLDAPManagerWithAuthenticator(config.IAMConfig{EnterpriseLDAP: []config.EnterpriseLDAPProviderConfig{{
		Slug:                 "globex-ldap",
		Name:                 "Globex Directory",
		OrganizationID:       "org_globex000000000",
		URL:                  "ldaps://ldap.globex.test:636",
		BaseDN:               "dc=globex,dc=test",
		BindDN:               "cn=svc-bind,dc=globex,dc=test",
		BindPassword:         "super-secret",
		UserFilter:           "(&(objectClass=person)(uid={username}))",
		SubjectAttribute:     "entryUUID",
		EmailAttribute:       "mail",
		UsernameAttribute:    "uid",
		DisplayNameAttribute: "displayName",
	}}}, db, nil, authenticator)
	if err != nil {
		t.Fatalf("failed to create enterprise ldap manager: %v", err)
	}

	sessionMgr := auth.NewSessionManager(auth.NewSessionRedisStore(redisClient))
	redisStore := auth.NewRedisStoreFromClient(redisClient)
	cfg := &config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "http://127.0.0.1:8080",
		},
	}
	handler := NewAuthHandler(
		true,
		accountAuth,
		nil,
		nil,
		nil,
		nil,
		nil,
		sessionMgr,
		redisStore,
		nil,
		nil,
		nil,
		nil,
		nil,
		ldapManager,
		nil,
		nil,
		cfg,
	)
	router := gin.New()
	handler.RegisterRoutes(router.Group(config.API_ROUTER_PATH), cfg)

	resp := performJSONRequest(t, router, http.MethodPost, "/api/enterprise/ldap/globex-ldap/login", map[string]string{
		"username": "ada",
		"password": "correct-horse-battery-staple",
	}, nil, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected ldap login status 200, got %d with body %s", resp.Code, resp.Body.String())
	}
	if authenticator.lastUsername != "ada" || authenticator.lastPassword != "correct-horse-battery-staple" {
		t.Fatalf("unexpected ldap authenticator inputs: %#v", authenticator)
	}
	requireCookie(t, resp, auth.OIDCSessionCookieName)

	body := decodeBodyMap(t, resp)
	if body["authenticated"] != true {
		t.Fatalf("expected authenticated response, got %#v", body)
	}

	var identity iam.ExternalIdentity
	if err := db.First(&identity, "provider_type = ? AND provider_id = ? AND subject = ?", iam.IdentityProviderTypeLDAP, "globex-ldap", "ldap-subject-001").Error; err != nil {
		t.Fatalf("expected ldap external identity: %v", err)
	}
	if identity.Email != "ada@globex.com" {
		t.Fatalf("unexpected ldap external identity: %#v", identity)
	}

	var membership iam.OrganizationMembership
	if err := db.First(&membership, "organization_id = ? AND user_id = ?", "org_globex000000000", identity.UserID).Error; err != nil {
		t.Fatalf("expected organization membership: %v", err)
	}
	if membership.Status != iam.MembershipStatusActive {
		t.Fatalf("unexpected membership status: %#v", membership)
	}
}

func TestEnterpriseLDAPLoginRejectsInvalidCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer redisServer.Close()

	redisClient := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	defer redisClient.Close()

	db, err := gorm.Open(sqlite.Open("file:enterprise-ldap-login-denied?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	accountAuth := auth.NewAccountAuth(db, auth.AccountAuthConfig{
		MaxLoginAttempts:  5,
		LoginLockDuration: 15 * time.Minute,
		Redis:             auth.NewAccountRedisStore(redisClient),
	})
	if err := accountAuth.AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate account tables: %v", err)
	}
	if err := iam.NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}

	ldapManager, err := iam.NewEnterpriseLDAPManagerWithAuthenticator(config.IAMConfig{EnterpriseLDAP: []config.EnterpriseLDAPProviderConfig{{
		Slug:   "globex-ldap",
		Name:   "Globex Directory",
		URL:    "ldaps://ldap.globex.test:636",
		BaseDN: "dc=globex,dc=test",
	}}}, db, nil, &fakeEnterpriseLDAPAuthenticator{err: errors.New("invalid credentials")})
	if err != nil {
		t.Fatalf("failed to create enterprise ldap manager: %v", err)
	}

	sessionMgr := auth.NewSessionManager(auth.NewSessionRedisStore(redisClient))
	redisStore := auth.NewRedisStoreFromClient(redisClient)
	cfg := &config.Config{OIDC: config.OIDCConfig{Issuer: "http://127.0.0.1:8080"}}
	handler := NewAuthHandler(
		true,
		accountAuth,
		nil,
		nil,
		nil,
		nil,
		nil,
		sessionMgr,
		redisStore,
		nil,
		nil,
		nil,
		nil,
		nil,
		ldapManager,
		nil,
		nil,
		cfg,
	)
	router := gin.New()
	handler.RegisterRoutes(router.Group(config.API_ROUTER_PATH), cfg)

	resp := performJSONRequest(t, router, http.MethodPost, "/api/enterprise/ldap/globex-ldap/login", map[string]string{
		"username": "ada",
		"password": "bad-password",
	}, nil, nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected ldap login status 401, got %d with body %s", resp.Code, resp.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if body["error"] != "enterprise ldap authentication failed" {
		t.Fatalf("unexpected ldap error body: %#v", body)
	}
}
