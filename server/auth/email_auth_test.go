package auth

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/glebarez/sqlite"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

type testEmailService struct {
	loginCodes []string
}

func (s *testEmailService) SendVerificationEmail(email, token, title, content string) error {
	return nil
}

func (s *testEmailService) SendLoginCodeEmail(email, code, title, content string) error {
	s.loginCodes = append(s.loginCodes, code)
	return nil
}

func (s *testEmailService) SendPasswordResetEmail(email, token, title, content string) error {
	return nil
}

func (s *testEmailService) SendLoginNotificationEmail(email, ip, title, content string) error {
	return nil
}

func newTestEmailAuth(t *testing.T, db *gorm.DB) (*EmailAuth, *testEmailService, *miniredis.Miniredis) {
	t.Helper()

	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	redisClient := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	emailService := &testEmailService{}
	emailAuth := NewEmailAuth(db, EmailAutnConfig{
		VerificationExpiry: time.Hour,
		EmailService:       emailService,
		Redis:              NewAccountRedisStore(redisClient),
	})
	if err := emailAuth.AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate email tables: %v", err)
	}
	return emailAuth, emailService, redisServer
}

func TestEmailCodeLoginCanUseVerifiedGoogleEmail(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:email-code-google-link?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}

	googleOAuth, err := NewGoogleOAuth(GoogleOAuthConfig{
		ClientID:     "test-google-client-id",
		ClientSecret: "test-google-client-secret",
		RedirectURL:  "https://auth.example.com/api/google/callback",
		DB:           db,
	})
	if err != nil {
		t.Fatalf("failed to create google oauth: %v", err)
	}
	if err := googleOAuth.AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate google tables: %v", err)
	}
	googleUser, err := googleOAuth.CreateUserFromGoogle(&GoogleUserInfo{
		ID:            "google-subject-email-code",
		Email:         "USER@Example.COM",
		EmailVerified: true,
		Name:          "Google Email",
	})
	if err != nil {
		t.Fatalf("failed to create google user: %v", err)
	}

	emailAuth, emailService, redisServer := newTestEmailAuth(t, db)
	defer redisServer.Close()

	if _, err := emailAuth.SendLoginCode(" user@example.com ", "Login", "Code: {{.Code}}"); err != nil {
		t.Fatalf("failed to send email login code: %v", err)
	}
	if len(emailService.loginCodes) != 1 {
		t.Fatalf("expected one login code, got %d", len(emailService.loginCodes))
	}

	loggedInUser, err := emailAuth.EmailCodeLogin("USER@example.com", emailService.loginCodes[0])
	if err != nil {
		t.Fatalf("email code login failed: %v", err)
	}
	if loggedInUser.UserID != googleUser.UserID {
		t.Fatalf("expected email login to use google-created account %s, got %s", googleUser.UserID, loggedInUser.UserID)
	}
}

func TestEmailPreregisterAllowsRandomPassword(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:email-random-password?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}
	emailAuth, _, redisServer := newTestEmailAuth(t, db)
	defer redisServer.Close()

	token, err := emailAuth.EmailPreregister("no-password@example.com", "", "No Password", "Verify", "Token: {{.Token}}")
	if err != nil {
		t.Fatalf("expected email preregister without password to succeed, got %v", err)
	}
	user, err := emailAuth.VerifyEmail(token)
	if err != nil {
		t.Fatalf("expected email verify to create user: %v", err)
	}
	if user.UserID == "" || user.Password == "" {
		t.Fatalf("expected user with generated id and random password hash")
	}
}
