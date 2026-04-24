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

	rolesJSON, err := json.Marshal([]string{"owner", "billing_admin"})
	if err != nil {
		t.Fatalf("failed to marshal organization roles: %v", err)
	}
	now := time.Now()
	if err := e.db.Create(&iam.Organization{
		OrganizationID: "org_test000000000000",
		Slug:           "acme",
		Name:           "Acme",
		Status:         iam.OrganizationStatusActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create organization: %v", err)
	}
	if err := e.db.Create(&iam.OrganizationMembership{
		OrganizationID: "org_test000000000000",
		UserID:         userID,
		Status:         iam.MembershipStatusActive,
		RolesJSON:      string(rolesJSON),
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create organization membership: %v", err)
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

func TestAuthorizeReusesBrowserSessionAndTokenExchangeSucceeds(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	user := env.createAccountUser(t, "demo")
	env.createOrganizationMembership(t, user.UserID)
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
	if !stringSliceEqual(idTokenClaims.OrgRoles, []string{"owner", "billing_admin"}) {
		t.Fatalf("expected id token org_roles owner/billing_admin, got %#v", idTokenClaims.OrgRoles)
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
	if !ok || len(userInfoRoles) != 2 || userInfoRoles[0] != "owner" || userInfoRoles[1] != "billing_admin" {
		t.Fatalf("expected userinfo org_roles owner/billing_admin, got %#v", userInfoBody["org_roles"])
	}
	if userInfoBody["userinfo_source"] != "hook" {
		t.Fatalf("expected custom userinfo claim from hook, got %#v", userInfoBody["userinfo_source"])
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
