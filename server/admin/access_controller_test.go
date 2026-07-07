package admin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
	"minki.cc/mkauth/server/oidc"
)

func TestAccessControllerListsAndMutatesAdmins(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&auth.User{}, &auth.AccountUser{}); err != nil {
		t.Fatalf("failed to migrate auth tables: %v", err)
	}

	users := []auth.User{
		{UserID: "usr_cfg_admin", Password: "hash", Status: auth.UserStatusActive, Nickname: "Ops"},
		{UserID: "usr_db_admin", Password: "hash", Status: auth.UserStatusActive, Nickname: "DB"},
	}
	for _, user := range users {
		if err := db.Create(&user).Error; err != nil {
			t.Fatalf("failed to create user %s: %v", user.UserID, err)
		}
	}
	accountUsers := []auth.AccountUser{
		{Username: "ops-admin", UserID: "usr_cfg_admin"},
		{Username: "db-admin", UserID: "usr_db_admin"},
	}
	for _, accountUser := range accountUsers {
		if err := db.Create(&accountUser).Error; err != nil {
			t.Fatalf("failed to create account user %s: %v", accountUser.Username, err)
		}
	}

	controller := NewAccessController(&config.AdminConfig{
		UserIDs: []string{"usr_cfg_admin"},
	}, db)

	created, err := controller.AddDatabaseAdmin("db-admin")
	if err != nil {
		t.Fatalf("expected database admin add to succeed, got %v", err)
	}
	if created.UserID != "usr_db_admin" || !created.Editable {
		t.Fatalf("unexpected created admin view: %#v", created)
	}

	admins, err := controller.ListAdminPrincipals()
	if err != nil {
		t.Fatalf("expected list admins to succeed, got %v", err)
	}
	if len(admins) != 2 {
		t.Fatalf("expected 2 admins, got %d", len(admins))
	}

	foundConfig := false
	foundDatabase := false
	for _, admin := range admins {
		switch admin.UserID {
		case "usr_cfg_admin":
			foundConfig = true
			if admin.Editable || admin.Username != "ops-admin" {
				t.Fatalf("unexpected config admin view: %#v", admin)
			}
		case "usr_db_admin":
			foundDatabase = true
			if !admin.Editable || admin.Username != "db-admin" {
				t.Fatalf("unexpected database admin view: %#v", admin)
			}
		}
	}
	if !foundConfig || !foundDatabase {
		t.Fatalf("expected both config and database admins to be present: %#v", admins)
	}

	if err := controller.DeleteDatabaseAdmin("usr_cfg_admin"); err != ErrAdminPrincipalManagedByConfig {
		t.Fatalf("expected config admin delete to fail with managed-by-config, got %v", err)
	}
	if err := controller.DeleteDatabaseAdmin("usr_db_admin"); err != nil {
		t.Fatalf("expected database admin delete to succeed, got %v", err)
	}
}

func TestAdminBootstrapUsesBrowserSessionAndAdminUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&auth.User{}, &auth.AccountUser{}); err != nil {
		t.Fatalf("failed to migrate auth tables: %v", err)
	}
	if err := db.Create(&auth.User{
		UserID:   "usr_bootstrap_admin",
		Password: "hash",
		Status:   auth.UserStatusActive,
		Nickname: "Bootstrap",
	}).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	if err := db.Create(&auth.AccountUser{
		Username: "bootstrap-admin",
		UserID:   "usr_bootstrap_admin",
	}).Error; err != nil {
		t.Fatalf("failed to create account user: %v", err)
	}

	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer redisServer.Close()

	redisClient := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	redisStore := auth.NewRedisStoreFromClient(redisClient)
	sessionMgr := auth.NewSessionManager(auth.NewSessionRedisStore(redisClient))

	userSession, err := sessionMgr.CreateUserSession("usr_bootstrap_admin", "127.0.0.1", "test-agent", time.Hour)
	if err != nil {
		t.Fatalf("failed to create user session: %v", err)
	}
	browserSessionID, err := auth.CreateBrowserSession(redisStore, userSession)
	if err != nil {
		t.Fatalf("failed to create browser session: %v", err)
	}

	controller := NewAccessController(&config.AdminConfig{
		UserIDs: []string{"usr_bootstrap_admin"},
	}, db)
	server := &AdminServer{
		db:               db,
		config:           &config.AdminConfig{SecretKey: "test-secret", SessionTTL: 30},
		logger:           log.New(io.Discard, "", 0),
		redis:            redisStore,
		sessionMgr:       sessionMgr,
		accessController: controller,
	}

	router := gin.New()
	store := cookie.NewStore([]byte("test-secret"))
	router.Use(sessions.Sessions("kcauth_admin_session", store))
	router.POST("/login", server.handleLogin)
	router.GET("/verify", server.authMiddleware(), server.handleVerifySession)

	loginReq := httptest.NewRequest(http.MethodPost, "/login", nil)
	loginReq.AddCookie(&http.Cookie{Name: auth.OIDCSessionCookieName, Value: browserSessionID, Path: "/"})
	loginResp := httptest.NewRecorder()
	router.ServeHTTP(loginResp, loginReq)
	if loginResp.Code != http.StatusOK {
		t.Fatalf("expected bootstrap login status 200, got %d: %s", loginResp.Code, loginResp.Body.String())
	}

	var loginBody struct {
		UserID   string   `json:"user_id"`
		Username string   `json:"username"`
		Nickname string   `json:"nickname"`
		Roles    []string `json:"roles"`
		Sources  []string `json:"sources"`
	}
	if err := json.Unmarshal(loginResp.Body.Bytes(), &loginBody); err != nil {
		t.Fatalf("failed to decode login body: %v", err)
	}
	if loginBody.UserID != "usr_bootstrap_admin" || loginBody.Username != "bootstrap-admin" || len(loginBody.Sources) != 1 {
		t.Fatalf("unexpected bootstrap login body: %#v", loginBody)
	}

	adminCookies := loginResp.Result().Cookies()
	if len(adminCookies) == 0 {
		t.Fatalf("expected admin session cookie to be set")
	}

	verifyReq := httptest.NewRequest(http.MethodGet, "/verify", nil)
	for _, cookie := range adminCookies {
		verifyReq.AddCookie(cookie)
	}
	verifyResp := httptest.NewRecorder()
	router.ServeHTTP(verifyResp, verifyReq)
	if verifyResp.Code != http.StatusOK {
		t.Fatalf("expected verify status 200, got %d: %s", verifyResp.Code, verifyResp.Body.String())
	}

	var verifyBody struct {
		UserID   string   `json:"user_id"`
		Username string   `json:"username"`
		Nickname string   `json:"nickname"`
		Roles    []string `json:"roles"`
	}
	if err := json.Unmarshal(verifyResp.Body.Bytes(), &verifyBody); err != nil {
		t.Fatalf("failed to decode verify body: %v", err)
	}
	if verifyBody.UserID != "usr_bootstrap_admin" || verifyBody.Username != "bootstrap-admin" || verifyBody.Nickname != "Bootstrap" {
		t.Fatalf("unexpected verify body: %#v", verifyBody)
	}
}

func TestAdminBearerTokenCanListOrganizations(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&auth.User{}, &auth.AccountUser{}); err != nil {
		t.Fatalf("failed to migrate auth tables: %v", err)
	}
	if err := iam.NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}
	if err := db.Create(&auth.User{
		UserID:       "usr_bearer_admin",
		Password:     "hash",
		TokenVersion: auth.DefaultTokenVersion,
		Status:       auth.UserStatusActive,
		Nickname:     "Bearer Admin",
	}).Error; err != nil {
		t.Fatalf("failed to create admin user: %v", err)
	}
	if err := db.Create(&auth.User{
		UserID:       "usr_regular",
		Password:     "hash",
		TokenVersion: auth.DefaultTokenVersion,
		Status:       auth.UserStatusActive,
		Nickname:     "Regular",
	}).Error; err != nil {
		t.Fatalf("failed to create regular user: %v", err)
	}
	for _, accountUser := range []auth.AccountUser{
		{Username: "bearer-admin", UserID: "usr_bearer_admin"},
		{Username: "regular", UserID: "usr_regular"},
	} {
		if err := db.Create(&accountUser).Error; err != nil {
			t.Fatalf("failed to create account user: %v", err)
		}
	}
	if err := db.Create(&iam.Organization{
		OrganizationID: "org_bearer_alpha",
		Slug:           "bearer-alpha",
		Name:           "Bearer Alpha",
		DisplayName:    "Bearer Alpha",
		Status:         iam.OrganizationStatusActive,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}).Error; err != nil {
		t.Fatalf("failed to create organization: %v", err)
	}

	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer redisServer.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	redisStore := auth.NewRedisStoreFromClient(redisClient)
	accountAuth := auth.NewAccountAuth(db, auth.AccountAuthConfig{Redis: auth.NewAccountRedisStore(redisClient)})

	privateKey, privateKeyPEM := testOIDCPrivateKey(t)
	provider, err := oidc.NewProvider(config.OIDCConfig{
		Enabled:       true,
		Issuer:        "https://auth.example.test",
		KeyID:         "test-key",
		PrivateKeyPEM: privateKeyPEM,
		Clients: []config.OIDCClientConfig{
			{
				ClientID:    "chnnl_api",
				Public:      true,
				RequirePKCE: true,
				GrantTypes:  []string{"authorization_code"},
				RedirectURIs: []string{
					"https://chnnl.example.test/oauth/oidc",
				},
				Scopes: []string{"openid", "profile", "email"},
			},
		},
	}, db, redisStore, accountAuth)
	if err != nil {
		t.Fatalf("failed to create oidc provider: %v", err)
	}

	controller := NewAccessController(&config.AdminConfig{
		UserIDs: []string{"usr_bearer_admin"},
	}, db)
	server := &AdminServer{
		db:               db,
		config:           &config.AdminConfig{SecretKey: "test-secret", SessionTTL: 30},
		logger:           log.New(io.Discard, "", 0),
		accessController: controller,
		oidcProvider:     provider,
	}

	router := gin.New()
	router.GET("/admin-api/organizations", server.authMiddleware(), server.handleListOrganizations)

	adminToken := signAdminTestAccessToken(t, privateKey, "usr_bearer_admin")
	req := httptest.NewRequest(http.MethodGet, "/admin-api/organizations", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected admin bearer status 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body struct {
		Organizations []map[string]any `json:"organizations"`
		Total         int64            `json:"total"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode organizations response: %v", err)
	}
	if body.Total != 1 || len(body.Organizations) != 1 || body.Organizations[0]["organization_id"] != "org_bearer_alpha" {
		t.Fatalf("unexpected organizations response: %#v", body)
	}

	regularToken := signAdminTestAccessToken(t, privateKey, "usr_regular")
	req = httptest.NewRequest(http.MethodGet, "/admin-api/organizations", nil)
	req.Header.Set("Authorization", "Bearer "+regularToken)
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected regular bearer status 403, got %d: %s", resp.Code, resp.Body.String())
	}
}

func testOIDCPrivateKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	return privateKey, string(pemBytes)
}

func signAdminTestAccessToken(t *testing.T, privateKey *rsa.PrivateKey, subject string) string {
	t.Helper()
	now := time.Now()
	claims := oidc.AccessTokenClaims{
		Scope:        "openid profile email",
		ClientID:     "chnnl_api",
		TokenType:    "access_token",
		TokenVersion: auth.DefaultTokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.test",
			Subject:   subject,
			Audience:  jwt.ClaimStrings{"chnnl_api"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			ID:        subject + "-token",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign access token: %v", err)
	}
	return signed
}

func TestAdminSessionIsRejectedAfterAdminAccessRevoked(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&auth.User{}, &auth.AccountUser{}); err != nil {
		t.Fatalf("failed to migrate auth tables: %v", err)
	}
	if err := db.Create(&auth.User{
		UserID:   "usr_revoked_admin",
		Password: "hash",
		Status:   auth.UserStatusActive,
		Nickname: "Revoked",
	}).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	if err := db.Create(&auth.AccountUser{
		Username: "revoked-admin",
		UserID:   "usr_revoked_admin",
	}).Error; err != nil {
		t.Fatalf("failed to create account user: %v", err)
	}

	controller := NewAccessController(&config.AdminConfig{
		SecretKey:  "test-secret",
		SessionTTL: 30,
	}, db)
	if _, err := controller.AddDatabaseAdmin("usr_revoked_admin"); err != nil {
		t.Fatalf("failed to add database admin: %v", err)
	}

	server := &AdminServer{
		db:               db,
		config:           &config.AdminConfig{SecretKey: "test-secret", SessionTTL: 30},
		logger:           log.New(io.Discard, "", 0),
		accessController: controller,
	}

	router := gin.New()
	store := cookie.NewStore([]byte("test-secret"))
	router.Use(sessions.Sessions("kcauth_admin_session", store))
	router.GET("/seed", func(c *gin.Context) {
		session := sessions.Default(c)
		rolesJSON, _ := json.Marshal([]string{"admin"})
		sourcesJSON, _ := json.Marshal([]string{adminPrincipalSourceDatabase})
		session.Set(sessionUserIDKey, "usr_revoked_admin")
		session.Set(sessionUsernameKey, "revoked-admin")
		session.Set(sessionNicknameKey, "Revoked")
		session.Set(sessionRoleKey, string(rolesJSON))
		session.Set(sessionSourceKey, string(sourcesJSON))
		if err := session.Save(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Status(http.StatusOK)
	})
	router.GET("/verify", server.authMiddleware(), server.handleVerifySession)

	seedReq := httptest.NewRequest(http.MethodGet, "/seed", nil)
	seedResp := httptest.NewRecorder()
	router.ServeHTTP(seedResp, seedReq)
	if seedResp.Code != http.StatusOK {
		t.Fatalf("failed to seed admin session: %d %s", seedResp.Code, seedResp.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	for _, cookie := range seedResp.Result().Cookies() {
		req.AddCookie(cookie)
	}

	if err := controller.DeleteDatabaseAdmin("usr_revoked_admin"); err != nil {
		t.Fatalf("failed to revoke database admin: %v", err)
	}

	verifyResp := httptest.NewRecorder()
	router.ServeHTTP(verifyResp, req)
	if verifyResp.Code != http.StatusForbidden {
		t.Fatalf("expected revoked admin session to be rejected with 403, got %d: %s", verifyResp.Code, verifyResp.Body.String())
	}
}

func TestOrganizationAdminSessionIsScopedToAssignedOrganizations(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&auth.User{}, &auth.AccountUser{}); err != nil {
		t.Fatalf("failed to migrate auth tables: %v", err)
	}
	if err := iam.NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}
	if err := db.Create(&auth.User{
		UserID:   "usr_org_admin",
		Password: "hash",
		Status:   auth.UserStatusActive,
		Nickname: "Org Admin",
	}).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	if err := db.Create(&auth.AccountUser{
		Username: "org-admin",
		UserID:   "usr_org_admin",
	}).Error; err != nil {
		t.Fatalf("failed to create account user: %v", err)
	}
	orgs := []iam.Organization{
		{OrganizationID: "org_allowed0000000", Slug: "allowed", Name: "Allowed", Status: iam.OrganizationStatusActive},
		{OrganizationID: "org_denied00000000", Slug: "denied", Name: "Denied", Status: iam.OrganizationStatusActive},
	}
	for _, org := range orgs {
		if err := db.Create(&org).Error; err != nil {
			t.Fatalf("failed to create org %s: %v", org.OrganizationID, err)
		}
	}

	controller := NewAccessController(&config.AdminConfig{SecretKey: "test-secret", SessionTTL: 30}, db)
	if _, err := controller.AddOrganizationAdmin("org_allowed0000000", "org-admin"); err != nil {
		t.Fatalf("failed to add organization admin: %v", err)
	}
	server := &AdminServer{
		db:               db,
		config:           &config.AdminConfig{SecretKey: "test-secret", SessionTTL: 30},
		logger:           log.New(io.Discard, "", 0),
		accessController: controller,
	}

	router := gin.New()
	store := cookie.NewStore([]byte("test-secret"))
	router.Use(sessions.Sessions("kcauth_admin_session", store))
	router.GET("/seed", func(c *gin.Context) {
		session := sessions.Default(c)
		rolesJSON, _ := json.Marshal([]string{"organization_admin"})
		sourcesJSON, _ := json.Marshal([]string{})
		session.Set(sessionUserIDKey, "usr_org_admin")
		session.Set(sessionUsernameKey, "org-admin")
		session.Set(sessionNicknameKey, "Org Admin")
		session.Set(sessionRoleKey, string(rolesJSON))
		session.Set(sessionSourceKey, string(sourcesJSON))
		if err := session.Save(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Status(http.StatusOK)
	})
	protected := router.Group("")
	protected.Use(server.authMiddleware())
	protected.GET("/verify", server.handleVerifySession)
	protected.GET("/organizations", server.handleListOrganizations)
	protected.GET("/organizations/:id", server.handleGetOrganization)
	protected.GET("/stats", server.globalAdminMiddleware(), server.handleGetStats)

	seedReq := httptest.NewRequest(http.MethodGet, "/seed", nil)
	seedResp := httptest.NewRecorder()
	router.ServeHTTP(seedResp, seedReq)
	if seedResp.Code != http.StatusOK {
		t.Fatalf("failed to seed org admin session: %d %s", seedResp.Code, seedResp.Body.String())
	}
	cookies := seedResp.Result().Cookies()

	verifyReq := httptest.NewRequest(http.MethodGet, "/verify", nil)
	for _, cookie := range cookies {
		verifyReq.AddCookie(cookie)
	}
	verifyResp := httptest.NewRecorder()
	router.ServeHTTP(verifyResp, verifyReq)
	if verifyResp.Code != http.StatusOK {
		t.Fatalf("expected verify status 200, got %d: %s", verifyResp.Code, verifyResp.Body.String())
	}
	var verifyBody struct {
		GlobalAdmin          bool     `json:"global_admin"`
		Roles                []string `json:"roles"`
		OrganizationAdminIDs []string `json:"organization_admin_ids"`
	}
	if err := json.Unmarshal(verifyResp.Body.Bytes(), &verifyBody); err != nil {
		t.Fatalf("failed to decode verify body: %v", err)
	}
	if verifyBody.GlobalAdmin || len(verifyBody.OrganizationAdminIDs) != 1 || verifyBody.OrganizationAdminIDs[0] != "org_allowed0000000" {
		t.Fatalf("unexpected organization admin verify body: %#v", verifyBody)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/organizations", nil)
	for _, cookie := range cookies {
		listReq.AddCookie(cookie)
	}
	listResp := httptest.NewRecorder()
	router.ServeHTTP(listResp, listReq)
	if listResp.Code != http.StatusOK {
		t.Fatalf("expected organization list status 200, got %d: %s", listResp.Code, listResp.Body.String())
	}
	var listBody struct {
		Organizations []iam.Organization `json:"organizations"`
		Total         int64              `json:"total"`
	}
	if err := json.Unmarshal(listResp.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("failed to decode organization list body: %v", err)
	}
	if listBody.Total != 1 || len(listBody.Organizations) != 1 || listBody.Organizations[0].OrganizationID != "org_allowed0000000" {
		t.Fatalf("expected only assigned organization, got %#v", listBody)
	}

	allowedReq := httptest.NewRequest(http.MethodGet, "/organizations/allowed", nil)
	for _, cookie := range cookies {
		allowedReq.AddCookie(cookie)
	}
	allowedResp := httptest.NewRecorder()
	router.ServeHTTP(allowedResp, allowedReq)
	if allowedResp.Code != http.StatusOK {
		t.Fatalf("expected assigned organization status 200, got %d: %s", allowedResp.Code, allowedResp.Body.String())
	}

	deniedReq := httptest.NewRequest(http.MethodGet, "/organizations/denied", nil)
	for _, cookie := range cookies {
		deniedReq.AddCookie(cookie)
	}
	deniedResp := httptest.NewRecorder()
	router.ServeHTTP(deniedResp, deniedReq)
	if deniedResp.Code != http.StatusForbidden {
		t.Fatalf("expected unrelated organization status 403, got %d: %s", deniedResp.Code, deniedResp.Body.String())
	}

	statsReq := httptest.NewRequest(http.MethodGet, "/stats", nil)
	for _, cookie := range cookies {
		statsReq.AddCookie(cookie)
	}
	statsResp := httptest.NewRecorder()
	router.ServeHTTP(statsResp, statsReq)
	if statsResp.Code != http.StatusForbidden {
		t.Fatalf("expected global stats status 403, got %d: %s", statsResp.Code, statsResp.Body.String())
	}
}
