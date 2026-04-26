package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

const (
	testCodeVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	testRedirectURI   = "http://127.0.0.1:3000/callback"
)

type integrationEnv struct {
	router      *gin.Engine
	db          *gorm.DB
	accountAuth *auth.AccountAuth
	provider    *Provider
	redisClient *redis.Client
	redisServer *miniredis.Miniredis
}

func newIntegrationEnv(t *testing.T) *integrationEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}

	redisClient := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
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
	if err := iam.NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}

	cfg := config.OIDCConfig{
		Enabled: true,
		Issuer:  "http://127.0.0.1:8080",
		Clients: []config.OIDCClientConfig{
			{
				ClientID:     "demo-spa",
				Public:       true,
				RequirePKCE:  true,
				RedirectURIs: []string{testRedirectURI},
				Scopes:       []string{"openid", "profile"},
			},
			{
				ClientID:     "service-api",
				ClientSecret: "service-secret",
				GrantTypes:   []string{"client_credentials"},
				Scopes:       []string{"admin_api", "profile"},
			},
		},
	}

	provider, err := NewProvider(cfg, db, redisStore, accountAuth)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	router := gin.New()
	provider.RegisterRoutes(router)

	return &integrationEnv{
		router:      router,
		db:          db,
		accountAuth: accountAuth,
		provider:    provider,
		redisClient: redisClient,
		redisServer: redisServer,
	}
}

func (e *integrationEnv) Close() {
	_ = e.redisClient.Close()
	e.redisServer.Close()
}

func (e *integrationEnv) createAccountUser(t *testing.T, username string) *auth.User {
	t.Helper()

	user, err := e.accountAuth.Register(username, "demo12345", username)
	if err != nil {
		t.Fatalf("failed to create account user: %v", err)
	}
	return user
}

func (e *integrationEnv) createBrowserSessionCookie(t *testing.T, userID string) *http.Cookie {
	t.Helper()

	session, err := e.provider.sessionMgr.CreateUserSession(userID, "203.0.113.10", "oidc-provider-test", auth.SessionExpiration)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	browserSessionID, err := auth.CreateBrowserSession(e.provider.redis, session)
	if err != nil {
		t.Fatalf("failed to create browser session: %v", err)
	}

	return &http.Cookie{
		Name:  auth.OIDCSessionCookieName,
		Value: browserSessionID,
		Path:  "/",
	}
}

func (e *integrationEnv) createOrganizationMembership(t *testing.T, userID string) {
	t.Helper()

	e.createOrganizationMembershipRecord(t, userID, "org_test000000000000", "acme", []string{"owner", "billing_admin"})
}

func (e *integrationEnv) createOrganizationMembershipRecord(t *testing.T, userID, organizationID, slug string, roles []string) {
	t.Helper()

	rolesJSON, err := json.Marshal(roles)
	if err != nil {
		t.Fatalf("failed to marshal organization roles: %v", err)
	}
	now := time.Now()
	var count int64
	if err := e.db.Model(&iam.Organization{}).Where("organization_id = ?", organizationID).Count(&count).Error; err != nil {
		t.Fatalf("failed to check organization: %v", err)
	}
	if count == 0 {
		if err := e.db.Create(&iam.Organization{
			OrganizationID: organizationID,
			Slug:           slug,
			Name:           strings.Title(slug),
			Status:         iam.OrganizationStatusActive,
			CreatedAt:      now,
			UpdatedAt:      now,
		}).Error; err != nil {
			t.Fatalf("failed to create organization: %v", err)
		}
	}
	if err := e.db.Create(&iam.OrganizationMembership{
		OrganizationID: organizationID,
		UserID:         userID,
		Status:         iam.MembershipStatusActive,
		RolesJSON:      string(rolesJSON),
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create organization membership: %v", err)
	}
}

func (e *integrationEnv) createOrganizationGroup(t *testing.T, userID, displayName, roleName string) {
	t.Helper()

	e.createOrganizationGroupRecord(t, "org_test000000000000", "grp_test000000000000", userID, displayName, roleName)
}

func (e *integrationEnv) createOrganizationGroupRecord(t *testing.T, organizationID, groupID, userID, displayName, roleName string) {
	t.Helper()

	now := time.Now()
	if err := e.db.Create(&iam.OrganizationGroup{
		GroupID:        groupID,
		OrganizationID: organizationID,
		ProviderType:   iam.IdentityProviderTypeManual,
		ProviderID:     iam.ManualOrganizationGroupProvider,
		ExternalID:     groupID,
		DisplayName:    displayName,
		RoleName:       roleName,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create organization group: %v", err)
	}
	if err := e.db.Create(&iam.OrganizationGroupMember{
		OrganizationID: organizationID,
		GroupID:        groupID,
		UserID:         userID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create organization group member: %v", err)
	}
}

func (e *integrationEnv) createOrganizationRoleRecord(t *testing.T, organizationID, roleID, name, slug string, permissions []string) {
	t.Helper()

	now := time.Now()
	if err := e.db.Create(&iam.OrganizationRole{
		RoleID:         roleID,
		OrganizationID: organizationID,
		Name:           name,
		Slug:           slug,
		Enabled:        true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create organization role: %v", err)
	}

	for _, permission := range permissions {
		if err := e.db.Create(&iam.OrganizationRolePermission{
			OrganizationID: organizationID,
			RoleID:         roleID,
			PermissionKey:  permission,
			CreatedAt:      now,
			UpdatedAt:      now,
		}).Error; err != nil {
			t.Fatalf("failed to create organization role permission: %v", err)
		}
	}
}

func (e *integrationEnv) bindOrganizationRoleToMembership(t *testing.T, organizationID, bindingID, roleID, userID string) {
	t.Helper()

	now := time.Now()
	if err := e.db.Create(&iam.OrganizationRoleBinding{
		BindingID:      bindingID,
		OrganizationID: organizationID,
		RoleID:         roleID,
		SubjectType:    iam.RoleBindingSubjectMembership,
		SubjectID:      userID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create organization role binding: %v", err)
	}
}

func (e *integrationEnv) parseIDToken(t *testing.T, token string) *idTokenClaims {
	t.Helper()

	parsed, err := jwt.ParseWithClaims(token, &idTokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		return e.provider.signer.publicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	if err != nil {
		t.Fatalf("failed to parse id token: %v", err)
	}

	claims, ok := parsed.Claims.(*idTokenClaims)
	if !ok || !parsed.Valid {
		t.Fatalf("expected valid id token claims")
	}
	return claims
}

func performRequest(t *testing.T, router http.Handler, method, target string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	var body strings.Reader
	if form != nil {
		body = *strings.NewReader(form.Encode())
	} else {
		body = *strings.NewReader("")
	}

	req := httptest.NewRequest(method, target, &body)
	req.Host = "127.0.0.1:8080"
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func performBearerRequest(t *testing.T, router http.Handler, method, target, accessToken string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, target, nil)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Authorization", "Bearer "+accessToken)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func responseCookie(recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func exchangeAuthorizationCode(t *testing.T, env *integrationEnv, code string) (string, string) {
	t.Helper()

	tokenResp := performRequest(t, env.router, http.MethodPost, "/oauth2/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"demo-spa"},
		"code":          {code},
		"redirect_uri":  {testRedirectURI},
		"code_verifier": {testCodeVerifier},
	}, nil)
	if tokenResp.Code != http.StatusOK {
		t.Fatalf("expected token status 200, got %d with body %s", tokenResp.Code, tokenResp.Body.String())
	}

	var tokenBody map[string]interface{}
	if err := json.Unmarshal(tokenResp.Body.Bytes(), &tokenBody); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	accessToken, _ := tokenBody["access_token"].(string)
	idToken, _ := tokenBody["id_token"].(string)
	if accessToken == "" || idToken == "" {
		t.Fatalf("expected access_token and id_token in response")
	}
	return accessToken, idToken
}

func TestClientCredentialsIssuesServiceAccountAccessToken(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	tokenResp := performRequest(t, env.router, http.MethodPost, "/oauth2/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"service-api"},
		"client_secret": {"service-secret"},
		"scope":         {"admin_api"},
	}, nil)
	if tokenResp.Code != http.StatusOK {
		t.Fatalf("expected client_credentials token status 200, got %d with body %s", tokenResp.Code, tokenResp.Body.String())
	}

	var tokenBody map[string]interface{}
	if err := json.Unmarshal(tokenResp.Body.Bytes(), &tokenBody); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}
	if _, ok := tokenBody["id_token"]; ok {
		t.Fatalf("client_credentials response must not include id_token: %#v", tokenBody)
	}
	if tokenBody["scope"] != "admin_api" {
		t.Fatalf("expected admin_api scope, got %#v", tokenBody["scope"])
	}
	accessToken, _ := tokenBody["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("expected access_token in client_credentials response")
	}

	claims, err := env.provider.ParseAccessToken(accessToken)
	if err != nil {
		t.Fatalf("failed to parse client_credentials access token: %v", err)
	}
	if claims.Subject != "svc:service-api" || claims.ClientID != "service-api" {
		t.Fatalf("unexpected service account token identity: %#v", claims)
	}
	if claims.ID == "" {
		t.Fatalf("expected service account access token to include jti")
	}
	if claims.GrantType != grantTypeClientCredentials || claims.SubjectType != accessTokenSubjectTypeServiceAccount || !claims.ServiceAccount {
		t.Fatalf("expected service account token markers, got %#v", claims)
	}
	if claims.Scope != "admin_api" {
		t.Fatalf("expected admin_api scope in token, got %q", claims.Scope)
	}

	userInfoResp := performBearerRequest(t, env.router, http.MethodGet, "/oauth2/userinfo", accessToken)
	if userInfoResp.Code != http.StatusUnauthorized {
		t.Fatalf("service account token should not be accepted by userinfo, got %d: %s", userInfoResp.Code, userInfoResp.Body.String())
	}
}

func TestTokenIntrospectionReportsServiceAccountToken(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	tokenResp := performRequest(t, env.router, http.MethodPost, "/oauth2/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"service-api"},
		"client_secret": {"service-secret"},
		"scope":         {"admin_api"},
	}, nil)
	if tokenResp.Code != http.StatusOK {
		t.Fatalf("expected client_credentials token status 200, got %d with body %s", tokenResp.Code, tokenResp.Body.String())
	}
	var tokenBody map[string]interface{}
	if err := json.Unmarshal(tokenResp.Body.Bytes(), &tokenBody); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}
	accessToken, _ := tokenBody["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("expected access_token in client_credentials response")
	}

	introspectionResp := performRequest(t, env.router, http.MethodPost, "/oauth2/introspect", url.Values{
		"client_id":       {"service-api"},
		"client_secret":   {"service-secret"},
		"token":           {accessToken},
		"token_type_hint": {"access_token"},
	}, nil)
	if introspectionResp.Code != http.StatusOK {
		t.Fatalf("expected introspection status 200, got %d with body %s", introspectionResp.Code, introspectionResp.Body.String())
	}
	if introspectionResp.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("expected no-store cache control, got %q", introspectionResp.Header().Get("Cache-Control"))
	}
	var introspectionBody map[string]interface{}
	if err := json.Unmarshal(introspectionResp.Body.Bytes(), &introspectionBody); err != nil {
		t.Fatalf("failed to decode introspection response: %v", err)
	}
	if introspectionBody["active"] != true {
		t.Fatalf("expected active token, got %#v", introspectionBody)
	}
	if introspectionBody["sub"] != "svc:service-api" || introspectionBody["client_id"] != "service-api" || introspectionBody["scope"] != "admin_api" {
		t.Fatalf("unexpected service token introspection identity: %#v", introspectionBody)
	}
	if introspectionBody["grant_type"] != grantTypeClientCredentials ||
		introspectionBody["subject_type"] != accessTokenSubjectTypeServiceAccount ||
		introspectionBody["service_account"] != true {
		t.Fatalf("expected service account markers in introspection response, got %#v", introspectionBody)
	}
	if introspectionBody["jti"] == "" {
		t.Fatalf("expected active introspection response to include jti, got %#v", introspectionBody)
	}

	inactiveResp := performRequest(t, env.router, http.MethodPost, "/oauth2/introspect", url.Values{
		"client_id":     {"service-api"},
		"client_secret": {"service-secret"},
		"token":         {"not-a-jwt"},
	}, nil)
	if inactiveResp.Code != http.StatusOK {
		t.Fatalf("expected inactive introspection status 200, got %d with body %s", inactiveResp.Code, inactiveResp.Body.String())
	}
	var inactiveBody map[string]interface{}
	if err := json.Unmarshal(inactiveResp.Body.Bytes(), &inactiveBody); err != nil {
		t.Fatalf("failed to decode inactive introspection response: %v", err)
	}
	if inactiveBody["active"] != false {
		t.Fatalf("expected inactive token response, got %#v", inactiveBody)
	}

	revokeResp := performRequest(t, env.router, http.MethodPost, "/oauth2/revoke", url.Values{
		"client_id":       {"service-api"},
		"client_secret":   {"service-secret"},
		"token":           {accessToken},
		"token_type_hint": {"access_token"},
	}, nil)
	if revokeResp.Code != http.StatusOK {
		t.Fatalf("expected revocation status 200, got %d with body %s", revokeResp.Code, revokeResp.Body.String())
	}

	revokedIntrospectionResp := performRequest(t, env.router, http.MethodPost, "/oauth2/introspect", url.Values{
		"client_id":     {"service-api"},
		"client_secret": {"service-secret"},
		"token":         {accessToken},
	}, nil)
	if revokedIntrospectionResp.Code != http.StatusOK {
		t.Fatalf("expected revoked introspection status 200, got %d with body %s", revokedIntrospectionResp.Code, revokedIntrospectionResp.Body.String())
	}
	var revokedIntrospectionBody map[string]interface{}
	if err := json.Unmarshal(revokedIntrospectionResp.Body.Bytes(), &revokedIntrospectionBody); err != nil {
		t.Fatalf("failed to decode revoked introspection response: %v", err)
	}
	if revokedIntrospectionBody["active"] != false {
		t.Fatalf("expected revoked token to introspect inactive, got %#v", revokedIntrospectionBody)
	}

	publicResp := performRequest(t, env.router, http.MethodPost, "/oauth2/introspect", url.Values{
		"client_id": {"demo-spa"},
		"token":     {accessToken},
	}, nil)
	if publicResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected public client introspection to be rejected, got %d with body %s", publicResp.Code, publicResp.Body.String())
	}
}

func TestClientCredentialsRejectsOIDCUserScopes(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	tokenResp := performRequest(t, env.router, http.MethodPost, "/oauth2/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"service-api"},
		"client_secret": {"service-secret"},
		"scope":         {"openid"},
	}, nil)
	if tokenResp.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid_scope status 400, got %d with body %s", tokenResp.Code, tokenResp.Body.String())
	}
	var tokenBody map[string]interface{}
	if err := json.Unmarshal(tokenResp.Body.Bytes(), &tokenBody); err != nil {
		t.Fatalf("failed to decode invalid_scope response: %v", err)
	}
	if tokenBody["error"] != "invalid_scope" {
		t.Fatalf("expected invalid_scope error, got %#v", tokenBody)
	}
}

func TestAuthorizeReusesBrowserSessionAndTokenExchangeSucceeds(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	user := env.createAccountUser(t, "demo")
	env.createOrganizationMembership(t, user.UserID)
	env.createOrganizationGroup(t, user.UserID, "Platform Team", "platform-team")
	hookRegistry, err := iam.NewHookRegistry(iam.HookFunc{
		HookName: "test-claims",
		Fn: func(ctx context.Context, event iam.HookEvent, data *iam.HookContext) error {
			if event == iam.HookBeforeTokenIssue {
				data.Claims["department"] = "engineering"
			}
			if event == iam.HookBeforeUserInfo {
				data.Claims["userinfo_source"] = "hook"
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("failed to create hook registry: %v", err)
	}
	env.provider.SetHookRegistry(hookRegistry)
	sessionCookie := env.createBrowserSessionCookie(t, user.UserID)

	authorizeURL := "/oauth2/authorize?client_id=demo-spa" +
		"&redirect_uri=" + url.QueryEscape(testRedirectURI) +
		"&response_type=code" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&code_challenge=" + testCodeChallenge +
		"&code_challenge_method=S256" +
		"&state=abc123"

	authorizeResp := performRequest(t, env.router, http.MethodGet, authorizeURL, nil, sessionCookie)
	if authorizeResp.Code != http.StatusFound {
		t.Fatalf("expected authorize status 302, got %d with body %s", authorizeResp.Code, authorizeResp.Body.String())
	}

	refreshedCookie := responseCookie(authorizeResp, auth.OIDCSessionCookieName)
	if refreshedCookie == nil || refreshedCookie.Value != sessionCookie.Value {
		t.Fatalf("expected authorize to refresh browser session cookie")
	}

	location := authorizeResp.Header().Get("Location")
	redirectLocation, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect location %q: %v", location, err)
	}
	if redirectLocation.Scheme+"://"+redirectLocation.Host+redirectLocation.Path != testRedirectURI {
		t.Fatalf("expected redirect to %s, got %s", testRedirectURI, location)
	}
	if redirectLocation.Query().Get("state") != "abc123" {
		t.Fatalf("expected state to round-trip, got %q", redirectLocation.Query().Get("state"))
	}
	code := redirectLocation.Query().Get("code")
	if code == "" {
		t.Fatalf("expected authorization code in redirect location %s", location)
	}

	tokenResp := performRequest(t, env.router, http.MethodPost, "/oauth2/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"demo-spa"},
		"code":          {code},
		"redirect_uri":  {testRedirectURI},
		"code_verifier": {testCodeVerifier},
	}, nil)
	if tokenResp.Code != http.StatusOK {
		t.Fatalf("expected token status 200, got %d with body %s", tokenResp.Code, tokenResp.Body.String())
	}

	var tokenBody map[string]interface{}
	if err := json.Unmarshal(tokenResp.Body.Bytes(), &tokenBody); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}
	if tokenBody["token_type"] != "Bearer" {
		t.Fatalf("expected Bearer token type, got %#v", tokenBody["token_type"])
	}

	accessToken, _ := tokenBody["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("expected access_token in token response")
	}

	claims, err := env.provider.ParseAccessToken(accessToken)
	if err != nil {
		t.Fatalf("failed to parse access token: %v", err)
	}
	if claims.Subject != user.UserID {
		t.Fatalf("expected token subject %s, got %s", user.UserID, claims.Subject)
	}
	if !strings.HasPrefix(claims.Subject, auth.UserIDPrefix) {
		t.Fatalf("expected access token subject to use internal user ID prefix %s, got %s", auth.UserIDPrefix, claims.Subject)
	}
	if claims.ClientID != "demo-spa" {
		t.Fatalf("expected client_id demo-spa, got %s", claims.ClientID)
	}
	if claims.ID == "" {
		t.Fatalf("expected access token to include jti")
	}
	if claims.Scope != "openid profile" {
		t.Fatalf("expected scope 'openid profile', got %q", claims.Scope)
	}

	idToken, _ := tokenBody["id_token"].(string)
	if idToken == "" {
		t.Fatalf("expected id_token in token response")
	}
	idTokenClaims := env.parseIDToken(t, idToken)
	if idTokenClaims.Subject != user.UserID {
		t.Fatalf("expected id token subject %s, got %s", user.UserID, idTokenClaims.Subject)
	}
	if !strings.HasPrefix(idTokenClaims.Subject, auth.UserIDPrefix) {
		t.Fatalf("expected id token subject to use internal user ID prefix %s, got %s", auth.UserIDPrefix, idTokenClaims.Subject)
	}
	if idTokenClaims.PreferredUsername != "demo" {
		t.Fatalf("expected id token preferred_username demo, got %q", idTokenClaims.PreferredUsername)
	}
	if idTokenClaims.OrgID != "org_test000000000000" {
		t.Fatalf("expected id token org_id org_test000000000000, got %q", idTokenClaims.OrgID)
	}
	if idTokenClaims.OrgSlug != "acme" {
		t.Fatalf("expected id token org_slug acme, got %q", idTokenClaims.OrgSlug)
	}
	if !stringSliceEqual(idTokenClaims.OrgRoles, []string{"billing_admin", "owner", "platform-team"}) {
		t.Fatalf("expected id token org_roles owner/billing_admin/platform-team, got %#v", idTokenClaims.OrgRoles)
	}
	if !stringSliceEqual(idTokenClaims.OrgGroups, []string{"Platform Team"}) {
		t.Fatalf("expected id token org_groups Platform Team, got %#v", idTokenClaims.OrgGroups)
	}
	idTokenMap := parseIDTokenMap(t, env.provider, idToken)
	if idTokenMap["department"] != "engineering" {
		t.Fatalf("expected custom id token department claim from hook, got %#v", idTokenMap["department"])
	}

	userInfoResp := performBearerRequest(t, env.router, http.MethodGet, "/oauth2/userinfo", accessToken)
	if userInfoResp.Code != http.StatusOK {
		t.Fatalf("expected userinfo status 200, got %d with body %s", userInfoResp.Code, userInfoResp.Body.String())
	}

	var userInfoBody map[string]interface{}
	if err := json.Unmarshal(userInfoResp.Body.Bytes(), &userInfoBody); err != nil {
		t.Fatalf("failed to decode userinfo response: %v", err)
	}
	userInfoSub, ok := userInfoBody["sub"].(string)
	if !ok || userInfoSub != user.UserID {
		t.Fatalf("expected userinfo sub %s, got %#v", user.UserID, userInfoBody["sub"])
	}
	if !strings.HasPrefix(userInfoSub, auth.UserIDPrefix) {
		t.Fatalf("expected userinfo sub to use internal user ID prefix %s, got %s", auth.UserIDPrefix, userInfoSub)
	}
	if userInfoBody["preferred_username"] != "demo" {
		t.Fatalf("expected userinfo preferred_username demo, got %#v", userInfoBody["preferred_username"])
	}
	if userInfoBody["org_id"] != "org_test000000000000" {
		t.Fatalf("expected userinfo org_id org_test000000000000, got %#v", userInfoBody["org_id"])
	}
	if userInfoBody["org_slug"] != "acme" {
		t.Fatalf("expected userinfo org_slug acme, got %#v", userInfoBody["org_slug"])
	}
	userInfoRoles, ok := userInfoBody["org_roles"].([]interface{})
	if !ok || len(userInfoRoles) != 3 || userInfoRoles[0] != "billing_admin" || userInfoRoles[1] != "owner" || userInfoRoles[2] != "platform-team" {
		t.Fatalf("expected userinfo org_roles owner/billing_admin/platform-team, got %#v", userInfoBody["org_roles"])
	}
	userInfoGroups, ok := userInfoBody["org_groups"].([]interface{})
	if !ok || len(userInfoGroups) != 1 || userInfoGroups[0] != "Platform Team" {
		t.Fatalf("expected userinfo org_groups Platform Team, got %#v", userInfoBody["org_groups"])
	}
	if userInfoBody["userinfo_source"] != "hook" {
		t.Fatalf("expected custom userinfo claim from hook, got %#v", userInfoBody["userinfo_source"])
	}

	revokeResp := performRequest(t, env.router, http.MethodPost, "/oauth2/revoke", url.Values{
		"client_id":       {"demo-spa"},
		"token":           {accessToken},
		"token_type_hint": {"access_token"},
	}, nil)
	if revokeResp.Code != http.StatusOK {
		t.Fatalf("expected public client revocation status 200, got %d with body %s", revokeResp.Code, revokeResp.Body.String())
	}

	revokedUserInfoResp := performBearerRequest(t, env.router, http.MethodGet, "/oauth2/userinfo", accessToken)
	if revokedUserInfoResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected revoked user access token to be rejected by userinfo, got %d with body %s", revokedUserInfoResp.Code, revokedUserInfoResp.Body.String())
	}
}

func parseIDTokenMap(t *testing.T, provider *Provider, token string) jwt.MapClaims {
	t.Helper()

	parsed, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		return provider.signer.publicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	if err != nil {
		t.Fatalf("failed to parse id token map: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		t.Fatalf("expected valid id token map claims")
	}
	return claims
}

func stringSliceEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func TestAuthorizeDisabledUserReturnsAccessDeniedAndClearsBrowserSession(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	user := env.createAccountUser(t, "disabled_user")
	sessionCookie := env.createBrowserSessionCookie(t, user.UserID)

	if err := env.db.Model(&auth.User{}).
		Where("user_id = ?", user.UserID).
		Update("status", auth.UserStatusInactive).Error; err != nil {
		t.Fatalf("failed to disable user: %v", err)
	}

	authorizeURL := "/oauth2/authorize?client_id=demo-spa" +
		"&redirect_uri=" + url.QueryEscape(testRedirectURI) +
		"&response_type=code" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&code_challenge=" + testCodeChallenge +
		"&code_challenge_method=S256" +
		"&state=disabled-state"

	authorizeResp := performRequest(t, env.router, http.MethodGet, authorizeURL, nil, sessionCookie)
	if authorizeResp.Code != http.StatusFound {
		t.Fatalf("expected authorize status 302, got %d with body %s", authorizeResp.Code, authorizeResp.Body.String())
	}

	location := authorizeResp.Header().Get("Location")
	redirectLocation, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect location %q: %v", location, err)
	}
	if redirectLocation.Query().Get("error") != "access_denied" {
		t.Fatalf("expected access_denied, got %q in location %s", redirectLocation.Query().Get("error"), location)
	}
	if redirectLocation.Query().Get("state") != "disabled-state" {
		t.Fatalf("expected state to round-trip, got %q", redirectLocation.Query().Get("state"))
	}

	clearedCookie := responseCookie(authorizeResp, auth.OIDCSessionCookieName)
	if clearedCookie == nil || clearedCookie.Value != "" || clearedCookie.MaxAge >= 0 {
		t.Fatalf("expected browser session cookie to be cleared, got %#v", clearedCookie)
	}
}

func TestAuthorizeRedirectsToLoginWithLoginHint(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	authorizeURL := "/oauth2/authorize?client_id=demo-spa" +
		"&redirect_uri=" + url.QueryEscape(testRedirectURI) +
		"&response_type=code" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&code_challenge=" + testCodeChallenge +
		"&code_challenge_method=S256" +
		"&state=hint-state" +
		"&login_hint=" + url.QueryEscape("user@example.com")

	authorizeResp := performRequest(t, env.router, http.MethodGet, authorizeURL, nil, nil)
	if authorizeResp.Code != http.StatusFound {
		t.Fatalf("expected authorize status 302, got %d with body %s", authorizeResp.Code, authorizeResp.Body.String())
	}

	location := authorizeResp.Header().Get("Location")
	loginLocation, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse login redirect location %q: %v", location, err)
	}
	if loginLocation.Path != "/login" {
		t.Fatalf("expected redirect to /login, got %s", location)
	}
	if loginLocation.Query().Get("client_id") != "demo-spa" {
		t.Fatalf("expected client_id demo-spa, got %q", loginLocation.Query().Get("client_id"))
	}
	if loginLocation.Query().Get("login_hint") != "user@example.com" {
		t.Fatalf("expected login_hint to round-trip, got %q", loginLocation.Query().Get("login_hint"))
	}

	redirectValue := loginLocation.Query().Get("redirect_uri")
	if redirectValue == "" {
		t.Fatalf("expected redirect_uri in login redirect")
	}
	redirectURL, err := url.Parse(redirectValue)
	if err != nil {
		t.Fatalf("failed to parse nested redirect_uri %q: %v", redirectValue, err)
	}
	if redirectURL.Query().Get("login_hint") != "user@example.com" {
		t.Fatalf("expected nested authorize redirect_uri to retain login_hint, got %q", redirectURL.Query().Get("login_hint"))
	}
}

func TestAuthorizeRedirectsToLoginWithDomainHint(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	authorizeURL := "/oauth2/authorize?client_id=demo-spa" +
		"&redirect_uri=" + url.QueryEscape(testRedirectURI) +
		"&response_type=code" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&code_challenge=" + testCodeChallenge +
		"&code_challenge_method=S256" +
		"&state=domain-state" +
		"&domain_hint=" + url.QueryEscape("example.com")

	authorizeResp := performRequest(t, env.router, http.MethodGet, authorizeURL, nil, nil)
	if authorizeResp.Code != http.StatusFound {
		t.Fatalf("expected authorize status 302, got %d with body %s", authorizeResp.Code, authorizeResp.Body.String())
	}

	location := authorizeResp.Header().Get("Location")
	loginLocation, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse login redirect location %q: %v", location, err)
	}
	if loginLocation.Path != "/login" {
		t.Fatalf("expected redirect to /login, got %s", location)
	}
	if loginLocation.Query().Get("domain_hint") != "example.com" {
		t.Fatalf("expected domain_hint to round-trip, got %q", loginLocation.Query().Get("domain_hint"))
	}

	redirectValue := loginLocation.Query().Get("redirect_uri")
	if redirectValue == "" {
		t.Fatalf("expected redirect_uri in login redirect")
	}
	redirectURL, err := url.Parse(redirectValue)
	if err != nil {
		t.Fatalf("failed to parse nested redirect_uri %q: %v", redirectValue, err)
	}
	if redirectURL.Query().Get("domain_hint") != "example.com" {
		t.Fatalf("expected nested authorize redirect_uri to retain domain_hint, got %q", redirectURL.Query().Get("domain_hint"))
	}
}

func TestAuthorizeRedirectsToLoginWithOrgHint(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	authorizeURL := "/oauth2/authorize?client_id=demo-spa" +
		"&redirect_uri=" + url.QueryEscape(testRedirectURI) +
		"&response_type=code" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&code_challenge=" + testCodeChallenge +
		"&code_challenge_method=S256" +
		"&state=org-state" +
		"&org_hint=" + url.QueryEscape("acme")

	authorizeResp := performRequest(t, env.router, http.MethodGet, authorizeURL, nil, nil)
	if authorizeResp.Code != http.StatusFound {
		t.Fatalf("expected authorize status 302, got %d with body %s", authorizeResp.Code, authorizeResp.Body.String())
	}

	location := authorizeResp.Header().Get("Location")
	loginLocation, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse login redirect location %q: %v", location, err)
	}
	if loginLocation.Path != "/login" {
		t.Fatalf("expected redirect to /login, got %s", location)
	}
	if loginLocation.Query().Get("org_hint") != "acme" {
		t.Fatalf("expected org_hint to round-trip, got %q", loginLocation.Query().Get("org_hint"))
	}

	redirectValue := loginLocation.Query().Get("redirect_uri")
	if redirectValue == "" {
		t.Fatalf("expected redirect_uri in login redirect")
	}
	redirectURL, err := url.Parse(redirectValue)
	if err != nil {
		t.Fatalf("failed to parse nested redirect_uri %q: %v", redirectValue, err)
	}
	if redirectURL.Query().Get("org_hint") != "acme" {
		t.Fatalf("expected nested authorize redirect_uri to retain org_hint, got %q", redirectURL.Query().Get("org_hint"))
	}
}

func TestAuthorizeSelectsOrganizationFromOrgHint(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	user := env.createAccountUser(t, "demo")
	env.createOrganizationMembershipRecord(t, user.UserID, "org_alpha0000000000", "alpha", []string{"viewer"})
	env.createOrganizationMembershipRecord(t, user.UserID, "org_beta00000000000", "beta", []string{"admin"})
	env.createOrganizationGroupRecord(t, "org_beta00000000000", "grp_beta0000000000", user.UserID, "Beta Team", "beta-team")
	sessionCookie := env.createBrowserSessionCookie(t, user.UserID)

	authorizeURL := "/oauth2/authorize?client_id=demo-spa" +
		"&redirect_uri=" + url.QueryEscape(testRedirectURI) +
		"&response_type=code" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&code_challenge=" + testCodeChallenge +
		"&code_challenge_method=S256" +
		"&state=org-select" +
		"&org_hint=" + url.QueryEscape("beta")

	authorizeResp := performRequest(t, env.router, http.MethodGet, authorizeURL, nil, sessionCookie)
	if authorizeResp.Code != http.StatusFound {
		t.Fatalf("expected authorize status 302, got %d with body %s", authorizeResp.Code, authorizeResp.Body.String())
	}

	redirectLocation, err := url.Parse(authorizeResp.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse authorize redirect: %v", err)
	}
	code := redirectLocation.Query().Get("code")
	if code == "" {
		t.Fatalf("expected authorization code in redirect location %s", redirectLocation.String())
	}

	tokenResp := performRequest(t, env.router, http.MethodPost, "/oauth2/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"demo-spa"},
		"code":          {code},
		"redirect_uri":  {testRedirectURI},
		"code_verifier": {testCodeVerifier},
	}, nil)
	if tokenResp.Code != http.StatusOK {
		t.Fatalf("expected token status 200, got %d with body %s", tokenResp.Code, tokenResp.Body.String())
	}

	var tokenBody map[string]interface{}
	if err := json.Unmarshal(tokenResp.Body.Bytes(), &tokenBody); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}
	accessToken, _ := tokenBody["access_token"].(string)
	idToken, _ := tokenBody["id_token"].(string)
	if accessToken == "" || idToken == "" {
		t.Fatalf("expected access_token and id_token in response")
	}

	accessClaims, err := env.provider.ParseAccessToken(accessToken)
	if err != nil {
		t.Fatalf("failed to parse access token: %v", err)
	}
	if accessClaims.OrgID != "org_beta00000000000" {
		t.Fatalf("expected access token org_id org_beta00000000000, got %q", accessClaims.OrgID)
	}
	if accessClaims.OrgSlug != "beta" {
		t.Fatalf("expected access token org_slug beta, got %q", accessClaims.OrgSlug)
	}

	idTokenClaims := env.parseIDToken(t, idToken)
	if idTokenClaims.OrgID != "org_beta00000000000" {
		t.Fatalf("expected id token org_id org_beta00000000000, got %q", idTokenClaims.OrgID)
	}
	if idTokenClaims.OrgSlug != "beta" {
		t.Fatalf("expected id token org_slug beta, got %q", idTokenClaims.OrgSlug)
	}
	if !stringSliceEqual(idTokenClaims.OrgRoles, []string{"admin", "beta-team"}) {
		t.Fatalf("expected id token org_roles admin/beta-team, got %#v", idTokenClaims.OrgRoles)
	}
	if !stringSliceEqual(idTokenClaims.OrgGroups, []string{"Beta Team"}) {
		t.Fatalf("expected id token org_groups Beta Team, got %#v", idTokenClaims.OrgGroups)
	}

	userInfoResp := performBearerRequest(t, env.router, http.MethodGet, "/oauth2/userinfo", accessToken)
	if userInfoResp.Code != http.StatusOK {
		t.Fatalf("expected userinfo status 200, got %d with body %s", userInfoResp.Code, userInfoResp.Body.String())
	}
	var userInfoBody map[string]interface{}
	if err := json.Unmarshal(userInfoResp.Body.Bytes(), &userInfoBody); err != nil {
		t.Fatalf("failed to decode userinfo response: %v", err)
	}
	if userInfoBody["org_id"] != "org_beta00000000000" {
		t.Fatalf("expected userinfo org_id org_beta00000000000, got %#v", userInfoBody["org_id"])
	}
	if userInfoBody["org_slug"] != "beta" {
		t.Fatalf("expected userinfo org_slug beta, got %#v", userInfoBody["org_slug"])
	}
	userInfoRoles, ok := userInfoBody["org_roles"].([]interface{})
	if !ok || len(userInfoRoles) != 2 || userInfoRoles[0] != "admin" || userInfoRoles[1] != "beta-team" {
		t.Fatalf("expected userinfo org_roles admin/beta-team, got %#v", userInfoBody["org_roles"])
	}
	userInfoGroups, ok := userInfoBody["org_groups"].([]interface{})
	if !ok || len(userInfoGroups) != 1 || userInfoGroups[0] != "Beta Team" {
		t.Fatalf("expected userinfo org_groups Beta Team, got %#v", userInfoBody["org_groups"])
	}
}

func TestAuthorizeRejectsOrgHintWithoutMembership(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	user := env.createAccountUser(t, "demo")
	env.createOrganizationMembershipRecord(t, user.UserID, "org_alpha0000000000", "alpha", []string{"viewer"})
	sessionCookie := env.createBrowserSessionCookie(t, user.UserID)

	authorizeURL := "/oauth2/authorize?client_id=demo-spa" +
		"&redirect_uri=" + url.QueryEscape(testRedirectURI) +
		"&response_type=code" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&code_challenge=" + testCodeChallenge +
		"&code_challenge_method=S256" +
		"&state=org-denied" +
		"&org_hint=" + url.QueryEscape("beta")

	authorizeResp := performRequest(t, env.router, http.MethodGet, authorizeURL, nil, sessionCookie)
	if authorizeResp.Code != http.StatusFound {
		t.Fatalf("expected authorize status 302, got %d with body %s", authorizeResp.Code, authorizeResp.Body.String())
	}

	location := authorizeResp.Header().Get("Location")
	redirectLocation, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect location %q: %v", location, err)
	}
	if redirectLocation.Query().Get("error") != "access_denied" {
		t.Fatalf("expected access_denied, got %q in location %s", redirectLocation.Query().Get("error"), location)
	}
	if redirectLocation.Query().Get("state") != "org-denied" {
		t.Fatalf("expected state to round-trip, got %q", redirectLocation.Query().Get("state"))
	}
}

func TestAuthorizeAutomaticallyPinsSingleEligibleOrganizationForClientPolicy(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	env.provider.cfg.Clients[0].RequireOrganization = true
	env.provider.cfg.Clients[0].RequiredOrgRoles = []string{"admin"}

	user := env.createAccountUser(t, "demo")
	env.createOrganizationMembershipRecord(t, user.UserID, "org_alpha0000000000", "alpha", []string{"viewer"})
	env.createOrganizationMembershipRecord(t, user.UserID, "org_beta00000000000", "beta", []string{"admin"})
	sessionCookie := env.createBrowserSessionCookie(t, user.UserID)

	authorizeURL := "/oauth2/authorize?client_id=demo-spa" +
		"&redirect_uri=" + url.QueryEscape(testRedirectURI) +
		"&response_type=code" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&code_challenge=" + testCodeChallenge +
		"&code_challenge_method=S256" +
		"&state=policy-admin"

	authorizeResp := performRequest(t, env.router, http.MethodGet, authorizeURL, nil, sessionCookie)
	if authorizeResp.Code != http.StatusFound {
		t.Fatalf("expected authorize status 302, got %d with body %s", authorizeResp.Code, authorizeResp.Body.String())
	}

	redirectLocation, err := url.Parse(authorizeResp.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse authorize redirect: %v", err)
	}
	if redirectLocation.Path != "/callback" || redirectLocation.Host != "127.0.0.1:3000" {
		t.Fatalf("expected direct callback redirect, got %s", redirectLocation.String())
	}
	code := redirectLocation.Query().Get("code")
	if code == "" {
		t.Fatalf("expected authorization code in redirect location %s", redirectLocation.String())
	}

	accessToken, idToken := exchangeAuthorizationCode(t, env, code)

	accessClaims, err := env.provider.ParseAccessToken(accessToken)
	if err != nil {
		t.Fatalf("failed to parse access token: %v", err)
	}
	if accessClaims.OrgID != "org_beta00000000000" || accessClaims.OrgSlug != "beta" {
		t.Fatalf("expected policy-selected beta organization in access token, got %#v", accessClaims)
	}

	idTokenClaims := env.parseIDToken(t, idToken)
	if idTokenClaims.OrgID != "org_beta00000000000" || idTokenClaims.OrgSlug != "beta" {
		t.Fatalf("expected policy-selected beta organization in id token, got %#v", idTokenClaims)
	}
	if !stringSliceEqual(idTokenClaims.OrgRoles, []string{"admin"}) {
		t.Fatalf("expected id token org_roles admin, got %#v", idTokenClaims.OrgRoles)
	}
}

func TestAuthorizeUsesFirstClassRoleBindingForClaimsAndClientPolicy(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	env.provider.cfg.Clients[0].RequireOrganization = true
	env.provider.cfg.Clients[0].RequiredOrgRoles = []string{"admin"}

	user := env.createAccountUser(t, "bound-role-user")
	env.createOrganizationMembershipRecord(t, user.UserID, "org_bound0000000000", "bound", nil)
	env.createOrganizationRoleRecord(t, "org_bound0000000000", "rol_adminbound0000", "Admin", "admin", []string{"settings.manage"})
	env.bindOrganizationRoleToMembership(t, "org_bound0000000000", "rbd_adminbound0000", "rol_adminbound0000", user.UserID)
	sessionCookie := env.createBrowserSessionCookie(t, user.UserID)

	authorizeURL := "/oauth2/authorize?client_id=demo-spa" +
		"&redirect_uri=" + url.QueryEscape(testRedirectURI) +
		"&response_type=code" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&code_challenge=" + testCodeChallenge +
		"&code_challenge_method=S256" +
		"&state=bound-role"

	authorizeResp := performRequest(t, env.router, http.MethodGet, authorizeURL, nil, sessionCookie)
	if authorizeResp.Code != http.StatusFound {
		t.Fatalf("expected authorize status 302, got %d with body %s", authorizeResp.Code, authorizeResp.Body.String())
	}

	redirectLocation, err := url.Parse(authorizeResp.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse authorize redirect: %v", err)
	}
	code := redirectLocation.Query().Get("code")
	if code == "" {
		t.Fatalf("expected authorization code in redirect location %s", redirectLocation.String())
	}

	accessToken, idToken := exchangeAuthorizationCode(t, env, code)

	idTokenClaims := env.parseIDToken(t, idToken)
	if idTokenClaims.OrgID != "org_bound0000000000" || idTokenClaims.OrgSlug != "bound" {
		t.Fatalf("expected bound organization claims, got %#v", idTokenClaims)
	}
	if !stringSliceEqual(idTokenClaims.OrgRoles, []string{"admin"}) {
		t.Fatalf("expected id token org_roles admin from first-class role binding, got %#v", idTokenClaims.OrgRoles)
	}

	userInfoResp := performBearerRequest(t, env.router, http.MethodGet, "/oauth2/userinfo", accessToken)
	if userInfoResp.Code != http.StatusOK {
		t.Fatalf("expected userinfo status 200, got %d with body %s", userInfoResp.Code, userInfoResp.Body.String())
	}
	var userInfoBody map[string]interface{}
	if err := json.Unmarshal(userInfoResp.Body.Bytes(), &userInfoBody); err != nil {
		t.Fatalf("failed to decode userinfo response: %v", err)
	}
	userInfoRoles, ok := userInfoBody["org_roles"].([]interface{})
	if !ok || len(userInfoRoles) != 1 || userInfoRoles[0] != "admin" {
		t.Fatalf("expected userinfo org_roles admin from first-class role binding, got %#v", userInfoBody["org_roles"])
	}
}

func TestAuthorizeSupportsAllOfOrganizationPolicy(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	env.provider.cfg.Clients[0].RequireOrganization = true
	env.provider.cfg.Clients[0].RequiredOrgRolesAll = []string{"admin", "security"}
	env.provider.cfg.Clients[0].RequiredOrgGroupsAll = []string{"Employees"}

	user := env.createAccountUser(t, "all-of-user")
	env.createOrganizationMembershipRecord(t, user.UserID, "org_alpha0000000000", "alpha", []string{"admin"})
	env.createOrganizationMembershipRecord(t, user.UserID, "org_beta00000000000", "beta", []string{"admin", "security"})
	env.createOrganizationGroupRecord(t, "org_beta00000000000", "grp_betaemployees00", user.UserID, "Employees", "employees")
	sessionCookie := env.createBrowserSessionCookie(t, user.UserID)

	authorizeURL := "/oauth2/authorize?client_id=demo-spa" +
		"&redirect_uri=" + url.QueryEscape(testRedirectURI) +
		"&response_type=code" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&code_challenge=" + testCodeChallenge +
		"&code_challenge_method=S256" +
		"&state=all-of"

	authorizeResp := performRequest(t, env.router, http.MethodGet, authorizeURL, nil, sessionCookie)
	if authorizeResp.Code != http.StatusFound {
		t.Fatalf("expected authorize status 302, got %d with body %s", authorizeResp.Code, authorizeResp.Body.String())
	}

	redirectLocation, err := url.Parse(authorizeResp.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse authorize redirect: %v", err)
	}
	code := redirectLocation.Query().Get("code")
	if code == "" {
		t.Fatalf("expected authorization code in redirect location %s", redirectLocation.String())
	}

	accessToken, idToken := exchangeAuthorizationCode(t, env, code)
	accessClaims, err := env.provider.ParseAccessToken(accessToken)
	if err != nil {
		t.Fatalf("failed to parse access token: %v", err)
	}
	if accessClaims.OrgID != "org_beta00000000000" {
		t.Fatalf("expected all-of policy to pin beta organization, got %#v", accessClaims)
	}

	idTokenClaims := env.parseIDToken(t, idToken)
	if !stringSliceEqual(idTokenClaims.OrgRoles, []string{"admin", "employees", "security"}) {
		t.Fatalf("expected merged all-of roles in id token, got %#v", idTokenClaims.OrgRoles)
	}
	if !stringSliceEqual(idTokenClaims.OrgGroups, []string{"Employees"}) {
		t.Fatalf("expected all-of groups in id token, got %#v", idTokenClaims.OrgGroups)
	}
}

func TestAuthorizeAppliesScopeSpecificOrganizationPolicy(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	env.provider.cfg.Clients[0].Scopes = []string{"openid", "profile", "email"}
	env.provider.cfg.Clients[0].RequireOrganization = true
	env.provider.cfg.Clients[0].ScopePolicies = map[string]config.OIDCOrganizationPolicy{
		"email": {
			RequiredOrgRolesAll: []string{"admin", "security"},
		},
	}

	user := env.createAccountUser(t, "scope-policy-user")
	env.createOrganizationMembershipRecord(t, user.UserID, "org_scope0000000000", "scope", []string{"admin"})
	sessionCookie := env.createBrowserSessionCookie(t, user.UserID)

	authorizeURL := "/oauth2/authorize?client_id=demo-spa" +
		"&redirect_uri=" + url.QueryEscape(testRedirectURI) +
		"&response_type=code" +
		"&scope=" + url.QueryEscape("openid profile email") +
		"&code_challenge=" + testCodeChallenge +
		"&code_challenge_method=S256" +
		"&state=scope-email-denied"

	authorizeResp := performRequest(t, env.router, http.MethodGet, authorizeURL, nil, sessionCookie)
	if authorizeResp.Code != http.StatusFound {
		t.Fatalf("expected authorize status 302, got %d with body %s", authorizeResp.Code, authorizeResp.Body.String())
	}

	redirectLocation, err := url.Parse(authorizeResp.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse authorize redirect: %v", err)
	}
	if redirectLocation.Query().Get("error") != "access_denied" {
		t.Fatalf("expected scope-specific access_denied, got %q in %s", redirectLocation.Query().Get("error"), redirectLocation.String())
	}

	profileAuthorizeURL := "/oauth2/authorize?client_id=demo-spa" +
		"&redirect_uri=" + url.QueryEscape(testRedirectURI) +
		"&response_type=code" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&code_challenge=" + testCodeChallenge +
		"&code_challenge_method=S256" +
		"&state=scope-profile-ok"

	profileAuthorizeResp := performRequest(t, env.router, http.MethodGet, profileAuthorizeURL, nil, sessionCookie)
	if profileAuthorizeResp.Code != http.StatusFound {
		t.Fatalf("expected profile-only authorize status 302, got %d with body %s", profileAuthorizeResp.Code, profileAuthorizeResp.Body.String())
	}
	profileRedirect, err := url.Parse(profileAuthorizeResp.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse profile authorize redirect: %v", err)
	}
	if profileRedirect.Query().Get("error") != "" {
		t.Fatalf("expected profile-only request to succeed, got redirect %s", profileRedirect.String())
	}
}

func TestAuthorizeRejectsWhenClientOrganizationPolicyHasNoEligibleMembership(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	env.provider.cfg.Clients[0].RequireOrganization = true
	env.provider.cfg.Clients[0].AllowedOrganizations = []string{"beta"}

	user := env.createAccountUser(t, "demo")
	env.createOrganizationMembershipRecord(t, user.UserID, "org_alpha0000000000", "alpha", []string{"viewer"})
	sessionCookie := env.createBrowserSessionCookie(t, user.UserID)

	authorizeURL := "/oauth2/authorize?client_id=demo-spa" +
		"&redirect_uri=" + url.QueryEscape(testRedirectURI) +
		"&response_type=code" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&code_challenge=" + testCodeChallenge +
		"&code_challenge_method=S256" +
		"&state=policy-denied"

	authorizeResp := performRequest(t, env.router, http.MethodGet, authorizeURL, nil, sessionCookie)
	if authorizeResp.Code != http.StatusFound {
		t.Fatalf("expected authorize status 302, got %d with body %s", authorizeResp.Code, authorizeResp.Body.String())
	}

	location := authorizeResp.Header().Get("Location")
	redirectLocation, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect location %q: %v", location, err)
	}
	if redirectLocation.Query().Get("error") != "access_denied" {
		t.Fatalf("expected access_denied, got %q in location %s", redirectLocation.Query().Get("error"), location)
	}
	if redirectLocation.Query().Get("state") != "policy-denied" {
		t.Fatalf("expected state to round-trip, got %q", redirectLocation.Query().Get("state"))
	}
}

func TestAuthorizeRedirectsToOrganizationChooserWithoutOrgHint(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	user := env.createAccountUser(t, "demo")
	env.createOrganizationMembershipRecord(t, user.UserID, "org_alpha0000000000", "alpha", []string{"viewer"})
	env.createOrganizationMembershipRecord(t, user.UserID, "org_beta00000000000", "beta", []string{"admin"})
	sessionCookie := env.createBrowserSessionCookie(t, user.UserID)

	authorizeURL := "/oauth2/authorize?client_id=demo-spa" +
		"&redirect_uri=" + url.QueryEscape(testRedirectURI) +
		"&response_type=code" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&code_challenge=" + testCodeChallenge +
		"&code_challenge_method=S256" +
		"&state=choose-org"

	authorizeResp := performRequest(t, env.router, http.MethodGet, authorizeURL, nil, sessionCookie)
	if authorizeResp.Code != http.StatusFound {
		t.Fatalf("expected authorize status 302, got %d with body %s", authorizeResp.Code, authorizeResp.Body.String())
	}

	location := authorizeResp.Header().Get("Location")
	chooserLocation, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse chooser redirect location %q: %v", location, err)
	}
	if chooserLocation.Path != "/select-organization" {
		t.Fatalf("expected redirect to /select-organization, got %s", location)
	}
	if chooserLocation.Query().Get("client_id") != "demo-spa" {
		t.Fatalf("expected client_id demo-spa, got %q", chooserLocation.Query().Get("client_id"))
	}

	redirectValue := chooserLocation.Query().Get("redirect_uri")
	if redirectValue == "" {
		t.Fatalf("expected nested redirect_uri in chooser redirect")
	}
	redirectURL, err := url.Parse(redirectValue)
	if err != nil {
		t.Fatalf("failed to parse nested redirect_uri %q: %v", redirectValue, err)
	}
	if redirectURL.Path != "/oauth2/authorize" {
		t.Fatalf("expected nested authorize redirect, got %s", redirectURL.String())
	}
	if redirectURL.Query().Get("state") != "choose-org" {
		t.Fatalf("expected nested authorize state to round-trip, got %q", redirectURL.Query().Get("state"))
	}
	if redirectURL.Query().Get("org_hint") != "" {
		t.Fatalf("expected nested authorize URL to omit org_hint until user chooses, got %q", redirectURL.Query().Get("org_hint"))
	}
}

func TestAuthorizePromptNoneReturnsInteractionRequiredForOrganizationChooser(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	user := env.createAccountUser(t, "demo")
	env.createOrganizationMembershipRecord(t, user.UserID, "org_alpha0000000000", "alpha", []string{"viewer"})
	env.createOrganizationMembershipRecord(t, user.UserID, "org_beta00000000000", "beta", []string{"admin"})
	sessionCookie := env.createBrowserSessionCookie(t, user.UserID)

	authorizeURL := "/oauth2/authorize?client_id=demo-spa" +
		"&redirect_uri=" + url.QueryEscape(testRedirectURI) +
		"&response_type=code" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&code_challenge=" + testCodeChallenge +
		"&code_challenge_method=S256" +
		"&state=choose-org-none" +
		"&prompt=none"

	authorizeResp := performRequest(t, env.router, http.MethodGet, authorizeURL, nil, sessionCookie)
	if authorizeResp.Code != http.StatusFound {
		t.Fatalf("expected authorize status 302, got %d with body %s", authorizeResp.Code, authorizeResp.Body.String())
	}

	location := authorizeResp.Header().Get("Location")
	redirectLocation, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect location %q: %v", location, err)
	}
	if redirectLocation.Query().Get("error") != "interaction_required" {
		t.Fatalf("expected interaction_required, got %q in location %s", redirectLocation.Query().Get("error"), location)
	}
	if redirectLocation.Query().Get("state") != "choose-org-none" {
		t.Fatalf("expected state to round-trip, got %q", redirectLocation.Query().Get("state"))
	}
}
