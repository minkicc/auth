package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
)

const (
	testCodeVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	testRedirectURI   = "http://127.0.0.1:3000/callback"
)

type integrationEnv struct {
	router      *gin.Engine
	db          *gorm.DB
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
		provider:    provider,
		redisClient: redisClient,
		redisServer: redisServer,
	}
}

func (e *integrationEnv) Close() {
	_ = e.redisClient.Close()
	e.redisServer.Close()
}

func (e *integrationEnv) createUser(t *testing.T, userID string) *auth.User {
	t.Helper()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("demo12345"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	user := &auth.User{
		UserID:       userID,
		Password:     string(hashedPassword),
		TokenVersion: auth.DefaultTokenVersion,
		Status:       auth.UserStatusActive,
		Nickname:     userID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := e.db.Create(user).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
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

	user := env.createUser(t, "demo_user")
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
	if claims.ClientID != "demo-spa" {
		t.Fatalf("expected client_id demo-spa, got %s", claims.ClientID)
	}
	if claims.Scope != "openid profile" {
		t.Fatalf("expected scope 'openid profile', got %q", claims.Scope)
	}
}

func TestAuthorizeDisabledUserReturnsAccessDeniedAndClearsBrowserSession(t *testing.T) {
	env := newIntegrationEnv(t)
	defer env.Close()

	user := env.createUser(t, "disabled_user")
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
