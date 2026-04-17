/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

/*
 * Copyright (c) 2023-2024 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
)

// GoogleUserInfo represents user information retrieved from Google
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// GoogleOAuthConfig configuration options
type GoogleOAuthConfig struct {
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	Scopes        []string
	Timeout       time.Duration
	DB            *gorm.DB       // Added database connection
	AvatarService *AvatarService // Added avatar service
}

// GoogleOAuth merged structure that handles both OAuth and user management
type GoogleOAuth struct {
	config        *oauth2.Config
	httpClient    *http.Client
	db            *gorm.DB
	avatarService *AvatarService // Added avatar service
	certsURL      string
	certsMu       sync.RWMutex
	certs         map[string]*rsa.PublicKey
	certsExpiry   time.Time
}

const googleCertsURL = "https://www.googleapis.com/oauth2/v1/certs"

type googleIDTokenClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	jwt.RegisteredClaims
}

// NewGoogleOAuth creates a new Google OAuth handler
func NewGoogleOAuth(cfg GoogleOAuthConfig) (*GoogleOAuth, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURL == "" {
		return nil, fmt.Errorf("missing required configuration")
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		}
	}

	return &GoogleOAuth{
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
			Endpoint:     google.Endpoint,
		},
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		db:            cfg.DB,
		avatarService: cfg.AvatarService,
		certsURL:      googleCertsURL,
	}, nil
}

// AutoMigrate automatically migrate database table structure
func (g *GoogleOAuth) AutoMigrate() error {
	if g.db == nil {
		return fmt.Errorf("database not initialized")
	}

	if err := g.db.AutoMigrate(
		&User{},
		&GoogleUser{},
	); err != nil {
		return err
	}
	return nil
}

func (g *GoogleOAuth) VerifyIDToken(ctx context.Context, idToken string) (*GoogleUserInfo, error) {
	if strings.TrimSpace(idToken) == "" {
		return nil, fmt.Errorf("missing id token")
	}

	claims := &googleIDTokenClaims{}
	token, err := jwt.ParseWithClaims(idToken, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		kid, _ := token.Header["kid"].(string)
		return g.googlePublicKey(ctx, kid)
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithAudience(g.config.ClientID),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid google id token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid google id token")
	}
	if !isGoogleIssuer(claims.Issuer) {
		return nil, fmt.Errorf("invalid google token issuer")
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return nil, fmt.Errorf("missing google subject")
	}

	return &GoogleUserInfo{
		ID:            claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		Picture:       claims.Picture,
	}, nil
}

func isGoogleIssuer(issuer string) bool {
	switch issuer {
	case "https://accounts.google.com", "accounts.google.com":
		return true
	default:
		return false
	}
}

func canLinkGoogleEmail(email string, emailVerified bool) bool {
	return strings.TrimSpace(email) != "" && emailVerified
}

func (g *GoogleOAuth) googlePublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if strings.TrimSpace(kid) == "" {
		return nil, fmt.Errorf("missing google key id")
	}

	g.certsMu.RLock()
	if len(g.certs) > 0 && time.Now().Before(g.certsExpiry) {
		if key := g.certs[kid]; key != nil {
			g.certsMu.RUnlock()
			return key, nil
		}
	}
	g.certsMu.RUnlock()

	return g.refreshGoogleCerts(ctx, kid)
}

func (g *GoogleOAuth) refreshGoogleCerts(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	g.certsMu.Lock()
	defer g.certsMu.Unlock()

	if len(g.certs) > 0 && time.Now().Before(g.certsExpiry) {
		if key := g.certs[kid]; key != nil {
			return key, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.certsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create google cert request: %w", err)
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch google certs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch google certs: status=%d", resp.StatusCode)
	}

	var certs map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
		return nil, fmt.Errorf("failed to decode google certs: %w", err)
	}

	parsedCerts := make(map[string]*rsa.PublicKey, len(certs))
	for keyID, rawCert := range certs {
		publicKey, err := parseGoogleRSAPublicKey(rawCert)
		if err != nil {
			return nil, fmt.Errorf("failed to parse google cert %s: %w", keyID, err)
		}
		parsedCerts[keyID] = publicKey
	}

	g.certs = parsedCerts
	g.certsExpiry = time.Now().Add(parseGoogleCertCacheTTL(resp.Header.Get("Cache-Control")))

	if key := g.certs[kid]; key != nil {
		return key, nil
	}

	return nil, fmt.Errorf("google signing key not found")
}

func parseGoogleCertCacheTTL(cacheControl string) time.Duration {
	const defaultTTL = time.Hour
	for _, directive := range strings.Split(cacheControl, ",") {
		directive = strings.TrimSpace(directive)
		if !strings.HasPrefix(strings.ToLower(directive), "max-age=") {
			continue
		}
		seconds, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(directive, "max-age=")))
		if err != nil || seconds <= 0 {
			return defaultTTL
		}
		return time.Duration(seconds) * time.Second
	}
	return defaultTTL
}

func parseGoogleRSAPublicKey(raw string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("invalid pem data")
	}

	if block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("certificate does not contain rsa public key")
		}
		return publicKey, nil
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(raw))
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

// GetUserByGoogleID gets a user by Google ID or, when safe, a verified email match.
func (g *GoogleOAuth) GetUserByGoogleID(googleID, email string, emailVerified bool) (*User, error) {
	if g.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	// First query Google user table
	var googleUser GoogleUser
	var userID string
	err := g.db.Where("google_id = ?", googleID).First(&googleUser).Error
	switch err {
	case nil:
		userID = googleUser.UserID
	case gorm.ErrRecordNotFound:
		if !canLinkGoogleEmail(email, emailVerified) {
			return nil, nil
		}
		var googleUserWithSameEmail EmailUser
		err = g.db.Where("email = ?", email).First(&googleUserWithSameEmail).Error
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				return nil, nil
			}
			return nil, err
		}
		userID = googleUserWithSameEmail.UserID
	default:
		return nil, err
	}

	// Then query the corresponding User record
	var user User
	if err := g.db.Where("user_id = ?", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "User does not exist", err)
		}
		return nil, err
	}

	return &user, nil
}

// CreateUserFromGoogle creates a user from Google information
func (g *GoogleOAuth) CreateUserFromGoogle(googleInfo *GoogleUserInfo) (*User, error) {
	if g.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	// Generate random UserID
	userID, err := GenerateUserID(g.db)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random ID: %v", err)
	}

	// Download and upload avatar
	avatarURL, err := g.avatarService.DownloadAndUploadAvatar(userID, googleInfo.Picture)
	if err != nil {
		return nil, fmt.Errorf("failed to process avatar: %w", err)
	}

	// Use transaction to ensure data consistency
	tx := g.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Generate random password (user cannot directly login with password)
	randomPassword := make([]byte, 16)
	if _, err := rand.Read(randomPassword); err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to generate random password: %v", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(randomPassword, bcrypt.DefaultCost)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("password encryption failed: %v", err)
	}

	// Extract username as nickname
	nickname := googleInfo.Name
	if nickname == "" {
		// If no name, use email prefix as default nickname
		if googleInfo.Email != "" {
			parts := strings.Split(googleInfo.Email, "@")
			nickname = parts[0]
		} else {
			nickname = userID
		}
	}

	// Create basic user record
	now := time.Now()
	user := &User{
		UserID:       userID,
		Password:     string(hashedPassword),
		TokenVersion: DefaultTokenVersion,
		Status:       UserStatusActive,
		Nickname:     nickname,
		Avatar:       avatarURL,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	// Create Google user association record
	googleUser := &GoogleUser{
		UserID:        userID,
		GoogleID:      googleInfo.ID,
		Email:         googleInfo.Email,
		VerifiedEmail: googleInfo.EmailVerified,
		Name:          googleInfo.Name,
		Picture:       avatarURL,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := tx.Create(googleUser).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create Google user association: %v", err)
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to save data: %v", err)
	}

	return user, nil
}

// UpdateGoogleUserInfo updates Google user information
func (g *GoogleOAuth) UpdateGoogleUserInfo(userID string, googleInfo *GoogleUserInfo) error {
	if g.db == nil {
		return fmt.Errorf("database not initialized")
	}

	// Download and upload avatar
	avatarURL, err := g.avatarService.DownloadAndUploadAvatar(userID, googleInfo.Picture)
	if err != nil {
		return fmt.Errorf("failed to process avatar: %w", err)
	}

	// Update Google user table information
	var googleUser GoogleUser
	if err := g.db.Where("user_id = ?", userID).First(&googleUser).Error; err != nil {
		return err
	}

	googleUser.Name = googleInfo.Name
	googleUser.Email = googleInfo.Email
	googleUser.VerifiedEmail = googleInfo.EmailVerified
	googleUser.Picture = avatarURL
	googleUser.UpdatedAt = time.Now()

	if err := g.db.Save(&googleUser).Error; err != nil {
		return err
	}

	// Extract username as nickname
	nickname := googleInfo.Name
	if nickname == "" {
		// If no name, use email prefix as default nickname
		if googleInfo.Email != "" {
			parts := strings.Split(googleInfo.Email, "@")
			nickname = parts[0]
		}
	}

	// Update user profile
	var user User
	if err := g.db.Where("user_id = ?", userID).First(&user).Error; err != nil {
		return err
	}

	user.Nickname = nickname
	user.Avatar = avatarURL
	user.UpdatedAt = time.Now()

	return g.db.Save(&user).Error
}

// GetClientID 获取 Google OAuth 客户端 ID
func (g *GoogleOAuth) GetClientID() string {
	return g.config.ClientID
}
