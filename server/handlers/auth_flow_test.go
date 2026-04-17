package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
)

type fakeEmailService struct {
	verificationEmails []emailVerificationCall
}

type emailVerificationCall struct {
	Email   string
	Token   string
	Title   string
	Content string
}

func (f *fakeEmailService) SendVerificationEmail(email, token, title, content string) error {
	f.verificationEmails = append(f.verificationEmails, emailVerificationCall{
		Email:   email,
		Token:   token,
		Title:   title,
		Content: content,
	})
	return nil
}

func (f *fakeEmailService) SendPasswordResetEmail(email, token, title, content string) error {
	return nil
}

func (f *fakeEmailService) SendLoginNotificationEmail(email, ip, title, content string) error {
	return nil
}

type fakeSMSService struct {
	verificationSMS []smsVerificationCall
}

type smsVerificationCall struct {
	Phone string
	Code  string
}

func (f *fakeSMSService) SendVerificationSMS(phone, code string) error {
	f.verificationSMS = append(f.verificationSMS, smsVerificationCall{
		Phone: phone,
		Code:  code,
	})
	return nil
}

func (f *fakeSMSService) SendPasswordResetSMS(phone, code string) error {
	return nil
}

func (f *fakeSMSService) SendLoginNotificationSMS(phone, ip string) error {
	return nil
}

type authTestEnv struct {
	router       *gin.Engine
	db           *gorm.DB
	emailService *fakeEmailService
	smsService   *fakeSMSService
	redisClient  *redis.Client
	redisServer  *miniredis.Miniredis
}

func newAuthTestEnv(t *testing.T) *authTestEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}

	redisClient := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	accountRedis := auth.NewAccountRedisStore(redisClient)
	redisStore := auth.NewRedisStoreFromClient(redisClient)
	sessionMgr := auth.NewSessionManager(auth.NewSessionRedisStore(redisClient))

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

	emailService := &fakeEmailService{}
	emailAuth := auth.NewEmailAuth(db, auth.EmailAutnConfig{
		VerificationExpiry: time.Hour,
		EmailService:       emailService,
		Redis:              accountRedis,
	})
	if err := emailAuth.AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate email tables: %v", err)
	}

	smsService := &fakeSMSService{}
	phoneAuth := auth.NewPhoneAuth(db, auth.PhoneAuthConfig{
		VerificationExpiry: time.Hour,
		SMSService:         smsService,
		Redis:              accountRedis,
	})
	if err := phoneAuth.AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate phone tables: %v", err)
	}

	cfg := &config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "http://127.0.0.1:8080",
		},
	}

	handler := NewAuthHandler(
		true,
		accountAuth,
		emailAuth,
		nil,
		nil,
		nil,
		phoneAuth,
		sessionMgr,
		redisStore,
		nil,
		nil,
		nil,
		cfg,
	)

	router := gin.New()
	handler.RegisterRoutes(router.Group(config.API_ROUTER_PATH), cfg)

	return &authTestEnv{
		router:       router,
		db:           db,
		emailService: emailService,
		smsService:   smsService,
		redisClient:  redisClient,
		redisServer:  redisServer,
	}
}

func (e *authTestEnv) Close() {
	_ = e.redisClient.Close()
	e.redisServer.Close()
}

func performJSONRequest(t *testing.T, router http.Handler, method, path string, body interface{}, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("failed to marshal request body: %v", err)
		}
	}

	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("User-Agent", "auth-handler-test")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func findCookie(recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func requireCookie(t *testing.T, recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()

	cookie := findCookie(recorder, name)
	if cookie == nil {
		t.Fatalf("expected cookie %s to be set", name)
	}
	return cookie
}

func decodeBodyMap(t *testing.T, recorder *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()

	var body map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response body %q: %v", recorder.Body.String(), err)
	}
	return body
}

func requireEmailPreregister(t *testing.T, env *authTestEnv, email, password string) string {
	t.Helper()

	resp := performJSONRequest(t, env.router, http.MethodPost, "/api/email/register", map[string]string{
		"email":    email,
		"password": password,
		"title":    "Verify",
		"content":  "Please verify your account",
	}, nil, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected email preregister status 200, got %d with body %s", resp.Code, resp.Body.String())
	}

	body := decodeBodyMap(t, resp)
	normalizedEmail, ok := body["email"].(string)
	if !ok || normalizedEmail == "" {
		t.Fatalf("expected normalized email in response, got %#v", body["email"])
	}

	return normalizedEmail
}

func requireVerifiedEmailUser(t *testing.T, env *authTestEnv, email, password string) string {
	t.Helper()

	initialVerificationCount := len(env.emailService.verificationEmails)
	normalizedEmail := requireEmailPreregister(t, env, email, password)
	if len(env.emailService.verificationEmails) != initialVerificationCount+1 {
		t.Fatalf("expected a verification email to be sent, got %d total", len(env.emailService.verificationEmails))
	}

	token := env.emailService.verificationEmails[len(env.emailService.verificationEmails)-1].Token
	verifyResp := performJSONRequest(t, env.router, http.MethodGet, "/api/email/verify?token="+token, nil, nil, nil)
	if verifyResp.Code != http.StatusOK {
		t.Fatalf("expected email verify status 200, got %d with body %s", verifyResp.Code, verifyResp.Body.String())
	}

	return normalizedEmail
}

func requirePhonePreregister(t *testing.T, env *authTestEnv, phone, password string) string {
	t.Helper()

	resp := performJSONRequest(t, env.router, http.MethodPost, "/api/phone/preregister", map[string]string{
		"phone":    phone,
		"password": password,
		"nickname": "demo",
	}, nil, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected phone preregister status 200, got %d with body %s", resp.Code, resp.Body.String())
	}

	body := decodeBodyMap(t, resp)
	normalizedPhone, ok := body["phone"].(string)
	if !ok || normalizedPhone == "" {
		t.Fatalf("expected normalized phone in response, got %#v", body["phone"])
	}

	return normalizedPhone
}

func requireVerifiedPhoneUser(t *testing.T, env *authTestEnv, phone, password string) string {
	t.Helper()

	initialSMSCount := len(env.smsService.verificationSMS)
	normalizedPhone := requirePhonePreregister(t, env, phone, password)
	if len(env.smsService.verificationSMS) != initialSMSCount+1 {
		t.Fatalf("expected a verification SMS to be sent, got %d total", len(env.smsService.verificationSMS))
	}

	code := env.smsService.verificationSMS[len(env.smsService.verificationSMS)-1].Code
	verifyResp := performJSONRequest(t, env.router, http.MethodPost, "/api/phone/verify-register", map[string]string{
		"phone": phone,
		"code":  code,
	}, nil, nil)
	if verifyResp.Code != http.StatusOK {
		t.Fatalf("expected phone verify-register status 200, got %d with body %s", verifyResp.Code, verifyResp.Body.String())
	}

	return normalizedPhone
}

func TestAccountRegisterCreatesBrowserSessionAndLogoutRequiresSameOrigin(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	registerResp := performJSONRequest(t, env.router, http.MethodPost, "/api/account/register", map[string]string{
		"username": "  Demo_User  ",
		"password": "demo12345",
	}, nil, nil)
	if registerResp.Code != http.StatusOK {
		t.Fatalf("expected register status 200, got %d with body %s", registerResp.Code, registerResp.Body.String())
	}

	body := decodeBodyMap(t, registerResp)
	if body["user_id"] != "Demo_User" {
		t.Fatalf("expected normalized user_id Demo_User, got %#v", body["user_id"])
	}

	sessionCookie := requireCookie(t, registerResp, auth.OIDCSessionCookieName)
	if sessionCookie.Value == "" {
		t.Fatalf("expected %s cookie value to be set", auth.OIDCSessionCookieName)
	}

	var user auth.User
	if err := env.db.First(&user, "user_id = ?", "Demo_User").Error; err != nil {
		t.Fatalf("expected normalized user to be stored: %v", err)
	}

	logoutResp := performJSONRequest(t, env.router, http.MethodPost, "/api/logout", nil, sessionCookie, nil)
	if logoutResp.Code != http.StatusForbidden {
		t.Fatalf("expected logout without same-origin headers to be forbidden, got %d with body %s", logoutResp.Code, logoutResp.Body.String())
	}

	logoutResp = performJSONRequest(t, env.router, http.MethodPost, "/api/logout", nil, sessionCookie, map[string]string{
		"Origin": "http://127.0.0.1:8080",
	})
	if logoutResp.Code != http.StatusOK {
		t.Fatalf("expected logout with matching Origin to succeed, got %d with body %s", logoutResp.Code, logoutResp.Body.String())
	}
}

func TestAccountRegisterRejectsCrossOriginSessionCreation(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	resp := performJSONRequest(t, env.router, http.MethodPost, "/api/account/register", map[string]string{
		"username": "cross_origin_user",
		"password": "demo12345",
	}, nil, map[string]string{
		"Origin": "https://evil.example.com",
	})
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected cross-origin register to be forbidden, got %d with body %s", resp.Code, resp.Body.String())
	}

	var count int64
	if err := env.db.Model(&auth.User{}).Where("user_id = ?", "cross_origin_user").Count(&count).Error; err != nil {
		t.Fatalf("failed to count users: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected cross-origin register not to create user, found %d", count)
	}

	resp = performJSONRequest(t, env.router, http.MethodPost, "/api/account/register", map[string]string{
		"username": "same_origin_user",
		"password": "demo12345",
	}, nil, map[string]string{
		"Origin": "http://127.0.0.1:8080",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("expected same-origin register to succeed, got %d with body %s", resp.Code, resp.Body.String())
	}
	requireCookie(t, resp, auth.OIDCSessionCookieName)
}

func TestBrowserSessionEndpointReturnsAuthenticatedUser(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	registerResp := performJSONRequest(t, env.router, http.MethodPost, "/api/account/register", map[string]string{
		"username": "demo_user",
		"password": "demo12345",
	}, nil, nil)
	if registerResp.Code != http.StatusOK {
		t.Fatalf("expected register status 200, got %d with body %s", registerResp.Code, registerResp.Body.String())
	}

	sessionCookie := requireCookie(t, registerResp, auth.OIDCSessionCookieName)
	resp := performJSONRequest(t, env.router, http.MethodGet, "/api/browser-session", nil, sessionCookie, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected browser session status 200, got %d with body %s", resp.Code, resp.Body.String())
	}

	body := decodeBodyMap(t, resp)
	if body["authenticated"] != true {
		t.Fatalf("expected authenticated=true, got %#v", body["authenticated"])
	}
	if body["user_id"] != "demo_user" {
		t.Fatalf("expected user_id demo_user, got %#v", body["user_id"])
	}

	refreshedCookie := requireCookie(t, resp, auth.OIDCSessionCookieName)
	if refreshedCookie.Value != sessionCookie.Value {
		t.Fatalf("expected browser session cookie to be refreshed without rotation, got %q want %q", refreshedCookie.Value, sessionCookie.Value)
	}
}

func TestDisabledUserInvalidatesBrowserSession(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	registerResp := performJSONRequest(t, env.router, http.MethodPost, "/api/account/register", map[string]string{
		"username": "disabled_user",
		"password": "demo12345",
	}, nil, nil)
	if registerResp.Code != http.StatusOK {
		t.Fatalf("expected register status 200, got %d with body %s", registerResp.Code, registerResp.Body.String())
	}

	sessionCookie := requireCookie(t, registerResp, auth.OIDCSessionCookieName)
	if err := env.db.Model(&auth.User{}).
		Where("user_id = ?", "disabled_user").
		Update("status", auth.UserStatusInactive).Error; err != nil {
		t.Fatalf("failed to disable user: %v", err)
	}

	browserSessionResp := performJSONRequest(t, env.router, http.MethodGet, "/api/browser-session", nil, sessionCookie, nil)
	if browserSessionResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected browser session status 401 for disabled user, got %d with body %s", browserSessionResp.Code, browserSessionResp.Body.String())
	}

	clearedCookie := requireCookie(t, browserSessionResp, auth.OIDCSessionCookieName)
	if clearedCookie.Value != "" || clearedCookie.MaxAge >= 0 {
		t.Fatalf("expected browser session cookie to be cleared, got value=%q maxAge=%d", clearedCookie.Value, clearedCookie.MaxAge)
	}

	userResp := performJSONRequest(t, env.router, http.MethodGet, "/api/user", nil, sessionCookie, nil)
	if userResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected authenticated API call to fail for disabled user, got %d with body %s", userResp.Code, userResp.Body.String())
	}
}

func TestAccountLoginRateLimitUsesNormalizedIdentifier(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	password := "demo12345"
	hashedPasswordBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	hashedPassword := string(hashedPasswordBytes)

	user := &auth.User{
		UserID:       "Demo_User",
		Password:     hashedPassword,
		TokenVersion: auth.DefaultTokenVersion,
		Status:       auth.UserStatusActive,
		Nickname:     "Demo_User",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := env.db.Create(user).Error; err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	variants := []string{
		"Demo_User",
		"  Demo_User",
		"Demo_User  ",
		"  Demo_User  ",
		"Demo_User",
	}
	for i, username := range variants {
		resp := performJSONRequest(t, env.router, http.MethodPost, "/api/account/login", map[string]string{
			"username": username,
			"password": "wrong-password",
		}, nil, nil)
		if resp.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d expected 401, got %d with body %s", i+1, resp.Code, resp.Body.String())
		}
	}

	resp := performJSONRequest(t, env.router, http.MethodPost, "/api/account/login", map[string]string{
		"username": "Demo_User",
		"password": "wrong-password",
	}, nil, nil)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("expected normalized login attempts to hit shared rate limit, got %d with body %s", resp.Code, resp.Body.String())
	}
}

func TestEmailFlowsNormalizeEmail(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	registerResp := performJSONRequest(t, env.router, http.MethodPost, "/api/email/register", map[string]string{
		"email":    "  USER@Example.COM  ",
		"password": "demo12345",
		"title":    "Verify",
		"content":  "Please verify your account",
	}, nil, nil)
	if registerResp.Code != http.StatusOK {
		t.Fatalf("expected email register status 200, got %d with body %s", registerResp.Code, registerResp.Body.String())
	}

	registerBody := decodeBodyMap(t, registerResp)
	if registerBody["email"] != "user@example.com" {
		t.Fatalf("expected normalized email in response, got %#v", registerBody["email"])
	}
	if len(env.emailService.verificationEmails) != 1 {
		t.Fatalf("expected one verification email, got %d", len(env.emailService.verificationEmails))
	}
	if env.emailService.verificationEmails[0].Email != "user@example.com" {
		t.Fatalf("expected verification email to use normalized address, got %s", env.emailService.verificationEmails[0].Email)
	}

	verifyResp := performJSONRequest(t, env.router, http.MethodGet, "/api/email/verify?token="+env.emailService.verificationEmails[0].Token, nil, nil, nil)
	if verifyResp.Code != http.StatusOK {
		t.Fatalf("expected email verify status 200, got %d with body %s", verifyResp.Code, verifyResp.Body.String())
	}

	loginResp := performJSONRequest(t, env.router, http.MethodPost, "/api/email/login", map[string]string{
		"email":    "  USER@Example.COM  ",
		"password": "demo12345",
	}, nil, nil)
	if loginResp.Code != http.StatusOK {
		t.Fatalf("expected email login status 200, got %d with body %s", loginResp.Code, loginResp.Body.String())
	}

	var emailUser auth.EmailUser
	if err := env.db.First(&emailUser, "email = ?", "user@example.com").Error; err != nil {
		t.Fatalf("expected normalized email to be stored: %v", err)
	}
}

func TestEmailRegisterRateLimitUsesNormalizedIdentifier(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	variants := []string{
		"  USER@Example.COM  ",
		"user@example.com",
		"USER@example.com",
		" user@example.com",
		"user@example.com ",
	}

	for i, email := range variants {
		resp := performJSONRequest(t, env.router, http.MethodPost, "/api/email/register", map[string]string{
			"email":    email,
			"password": "demo12345",
			"title":    "Verify",
			"content":  "Please verify your account",
		}, nil, nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("attempt %d expected 200, got %d with body %s", i+1, resp.Code, resp.Body.String())
		}
	}

	resp := performJSONRequest(t, env.router, http.MethodPost, "/api/email/register", map[string]string{
		"email":    "USER@example.com",
		"password": "demo12345",
		"title":    "Verify",
		"content":  "Please verify your account",
	}, nil, nil)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("expected normalized email register attempts to hit shared rate limit, got %d with body %s", resp.Code, resp.Body.String())
	}
}

func TestEmailResendVerificationRateLimitUsesNormalizedIdentifier(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	requireEmailPreregister(t, env, "  USER@Example.COM  ", "demo12345")

	variants := []string{
		"user@example.com",
		" USER@example.com",
		"user@example.com ",
		"User@Example.com",
		"  user@example.com  ",
	}

	for i, email := range variants {
		resp := performJSONRequest(t, env.router, http.MethodPost, "/api/email/resend-verification", map[string]string{
			"email":   email,
			"title":   "Verify",
			"content": "Please verify your account",
		}, nil, nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("attempt %d expected 200, got %d with body %s", i+1, resp.Code, resp.Body.String())
		}
	}

	resp := performJSONRequest(t, env.router, http.MethodPost, "/api/email/resend-verification", map[string]string{
		"email":   "USER@example.com",
		"title":   "Verify",
		"content": "Please verify your account",
	}, nil, nil)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("expected normalized email resend attempts to hit shared rate limit, got %d with body %s", resp.Code, resp.Body.String())
	}
}

func TestEmailPasswordResetRateLimitUsesNormalizedIdentifier(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	requireVerifiedEmailUser(t, env, "  USER@Example.COM  ", "demo12345")

	variants := []string{
		"user@example.com",
		" USER@example.com",
		"user@example.com ",
		"User@Example.com",
		"  user@example.com  ",
	}

	for i, email := range variants {
		resp := performJSONRequest(t, env.router, http.MethodPost, "/api/email/password/reset", map[string]string{
			"email":   email,
			"title":   "Reset",
			"content": "Reset your password",
		}, nil, nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("attempt %d expected 200, got %d with body %s", i+1, resp.Code, resp.Body.String())
		}
	}

	resp := performJSONRequest(t, env.router, http.MethodPost, "/api/email/password/reset", map[string]string{
		"email":   "USER@example.com",
		"title":   "Reset",
		"content": "Reset your password",
	}, nil, nil)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("expected normalized email password reset attempts to hit shared rate limit, got %d with body %s", resp.Code, resp.Body.String())
	}
}

func TestPhoneFlowsNormalizePhone(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	preregisterResp := performJSONRequest(t, env.router, http.MethodPost, "/api/phone/preregister", map[string]string{
		"phone":    "+86 138-0013-8000",
		"password": "demo12345",
		"nickname": "demo",
	}, nil, nil)
	if preregisterResp.Code != http.StatusOK {
		t.Fatalf("expected phone preregister status 200, got %d with body %s", preregisterResp.Code, preregisterResp.Body.String())
	}

	preregisterBody := decodeBodyMap(t, preregisterResp)
	if preregisterBody["phone"] != "+8613800138000" {
		t.Fatalf("expected normalized phone in response, got %#v", preregisterBody["phone"])
	}
	if len(env.smsService.verificationSMS) != 1 {
		t.Fatalf("expected one verification SMS, got %d", len(env.smsService.verificationSMS))
	}
	if env.smsService.verificationSMS[0].Phone != "+8613800138000" {
		t.Fatalf("expected verification SMS to use normalized phone, got %s", env.smsService.verificationSMS[0].Phone)
	}

	verifyResp := performJSONRequest(t, env.router, http.MethodPost, "/api/phone/verify-register", map[string]string{
		"phone": "+86 (138) 0013-8000",
		"code":  env.smsService.verificationSMS[0].Code,
	}, nil, nil)
	if verifyResp.Code != http.StatusOK {
		t.Fatalf("expected phone verify-register status 200, got %d with body %s", verifyResp.Code, verifyResp.Body.String())
	}

	loginResp := performJSONRequest(t, env.router, http.MethodPost, "/api/phone/login", map[string]string{
		"phone":    "+86 138 0013 8000",
		"password": "demo12345",
	}, nil, nil)
	if loginResp.Code != http.StatusOK {
		t.Fatalf("expected phone login status 200, got %d with body %s", loginResp.Code, loginResp.Body.String())
	}

	var phoneUser auth.PhoneUser
	if err := env.db.First(&phoneUser, "phone = ?", "+8613800138000").Error; err != nil {
		t.Fatalf("expected normalized phone to be stored: %v", err)
	}
}

func TestPhonePreregisterRateLimitUsesNormalizedIdentifier(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	variants := []string{
		"+86 138-0013-8000",
		"+8613800138000",
		"+86 (138) 0013-8000",
		"+86 138 0013 8000",
		" +8613800138000 ",
	}

	for i, phone := range variants {
		resp := performJSONRequest(t, env.router, http.MethodPost, "/api/phone/preregister", map[string]string{
			"phone":    phone,
			"password": "demo12345",
			"nickname": "demo",
		}, nil, nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("attempt %d expected 200, got %d with body %s", i+1, resp.Code, resp.Body.String())
		}
	}

	resp := performJSONRequest(t, env.router, http.MethodPost, "/api/phone/preregister", map[string]string{
		"phone":    "+8613800138000",
		"password": "demo12345",
		"nickname": "demo",
	}, nil, nil)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("expected normalized phone preregister attempts to hit shared rate limit, got %d with body %s", resp.Code, resp.Body.String())
	}
}

func TestPhoneResendVerificationRateLimitUsesNormalizedIdentifier(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	requirePhonePreregister(t, env, "+86 138-0013-8000", "demo12345")

	variants := []string{
		"+8613800138000",
		"+86 (138) 0013-8000",
		"+86 138 0013 8000",
		" +8613800138000 ",
		"+86-138-0013-8000",
	}

	for i, phone := range variants {
		resp := performJSONRequest(t, env.router, http.MethodPost, "/api/phone/resend-verification", map[string]string{
			"phone": phone,
		}, nil, nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("attempt %d expected 200, got %d with body %s", i+1, resp.Code, resp.Body.String())
		}
	}

	resp := performJSONRequest(t, env.router, http.MethodPost, "/api/phone/resend-verification", map[string]string{
		"phone": "+8613800138000",
	}, nil, nil)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("expected normalized phone resend attempts to hit shared rate limit, got %d with body %s", resp.Code, resp.Body.String())
	}
}

func TestPhoneSendLoginCodeRateLimitUsesNormalizedIdentifier(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	requireVerifiedPhoneUser(t, env, "+86 138-0013-8000", "demo12345")

	variants := []string{
		"+8613800138000",
		"+86 (138) 0013-8000",
		"+86 138 0013 8000",
		" +8613800138000 ",
		"+86-138-0013-8000",
	}

	for i, phone := range variants {
		resp := performJSONRequest(t, env.router, http.MethodPost, "/api/phone/send-login-code", map[string]string{
			"phone": phone,
		}, nil, nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("attempt %d expected 200, got %d with body %s", i+1, resp.Code, resp.Body.String())
		}
	}

	resp := performJSONRequest(t, env.router, http.MethodPost, "/api/phone/send-login-code", map[string]string{
		"phone": "+8613800138000",
	}, nil, nil)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("expected normalized phone send-login-code attempts to hit shared rate limit, got %d with body %s", resp.Code, resp.Body.String())
	}
}

func TestPhonePasswordResetInitRateLimitUsesNormalizedIdentifier(t *testing.T) {
	env := newAuthTestEnv(t)
	defer env.Close()

	requireVerifiedPhoneUser(t, env, "+86 138-0013-8000", "demo12345")

	variants := []string{
		"+8613800138000",
		"+86 (138) 0013-8000",
		"+86 138 0013 8000",
		" +8613800138000 ",
		"+86-138-0013-8000",
	}

	for i, phone := range variants {
		resp := performJSONRequest(t, env.router, http.MethodPost, "/api/phone/reset-password/init", map[string]string{
			"phone": phone,
		}, nil, nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("attempt %d expected 200, got %d with body %s", i+1, resp.Code, resp.Body.String())
		}
	}

	resp := performJSONRequest(t, env.router, http.MethodPost, "/api/phone/reset-password/init", map[string]string{
		"phone": "+8613800138000",
	}, nil, nil)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("expected normalized phone password reset init attempts to hit shared rate limit, got %d with body %s", resp.Code, resp.Body.String())
	}
}
