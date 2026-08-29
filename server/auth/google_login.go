/*
 * Licensed under the MIT License.
 */

/*
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
	"errors"
	"fmt"
	"log"
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
	"gorm.io/gorm/clause"
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
		&EmailUser{},
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
		normalizedEmail, err := NormalizeEmailAddress(email)
		if err != nil {
			return nil, nil
		}
		var googleUserWithSameEmail EmailUser
		err = g.db.Where("email = ?", normalizedEmail).First(&googleUserWithSameEmail).Error
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

	avatarURL := g.downloadAndUploadAvatarIfAvailable(userID, googleInfo.Picture)

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
		Email:         normalizeGoogleEmailForStorage(googleInfo.Email),
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
	if err := g.ensureEmailUserForVerifiedGoogle(tx, userID, googleInfo.Email, googleInfo.EmailVerified); err != nil {
		tx.Rollback()
		return nil, err
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to save data: %v", err)
	}

	return user, nil
}

// LinkGoogleUser links a verified Google identity to an existing Auth user.
func (g *GoogleOAuth) LinkGoogleUser(userID string, googleInfo *GoogleUserInfo) error {
	if g.db == nil {
		return fmt.Errorf("database not initialized")
	}
	if strings.TrimSpace(userID) == "" || googleInfo == nil || strings.TrimSpace(googleInfo.ID) == "" {
		return ErrInvalidInput("Google identity link requires user and Google subject")
	}

	tx := g.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	now := time.Now()
	var byGoogleID GoogleUser
	err := tx.First(&byGoogleID, "google_id = ?", googleInfo.ID).Error
	switch {
	case err == nil:
		if byGoogleID.UserID != userID {
			tx.Rollback()
			return ErrDuplicateUser("Google account is already linked to another user")
		}
		byGoogleID.Email = normalizeGoogleEmailForStorage(googleInfo.Email)
		byGoogleID.VerifiedEmail = googleInfo.EmailVerified
		byGoogleID.Name = googleInfo.Name
		byGoogleID.UpdatedAt = now
		if err := tx.Save(&byGoogleID).Error; err != nil {
			tx.Rollback()
			return err
		}
	case errors.Is(err, gorm.ErrRecordNotFound):
		var byUserID GoogleUser
		userErr := tx.First(&byUserID, "user_id = ?", userID).Error
		switch {
		case userErr == nil:
			if byUserID.GoogleID != googleInfo.ID {
				tx.Rollback()
				return ErrDuplicateUser("User is already linked to another Google account")
			}
			byUserID.Email = normalizeGoogleEmailForStorage(googleInfo.Email)
			byUserID.VerifiedEmail = googleInfo.EmailVerified
			byUserID.Name = googleInfo.Name
			byUserID.UpdatedAt = now
			if err := tx.Save(&byUserID).Error; err != nil {
				tx.Rollback()
				return err
			}
		case errors.Is(userErr, gorm.ErrRecordNotFound):
			if err := tx.Create(&GoogleUser{
				UserID:        userID,
				GoogleID:      googleInfo.ID,
				Email:         normalizeGoogleEmailForStorage(googleInfo.Email),
				VerifiedEmail: googleInfo.EmailVerified,
				Name:          googleInfo.Name,
				Picture:       g.downloadAndUploadAvatarIfAvailable(userID, googleInfo.Picture),
				CreatedAt:     now,
				UpdatedAt:     now,
			}).Error; err != nil {
				tx.Rollback()
				return err
			}
		default:
			tx.Rollback()
			return userErr
		}
	default:
		tx.Rollback()
		return err
	}

	if err := g.ensureEmailUserForVerifiedGoogle(tx, userID, googleInfo.Email, googleInfo.EmailVerified); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}

// UpdateGoogleUserInfo updates Google user information
func (g *GoogleOAuth) UpdateGoogleUserInfo(userID string, googleInfo *GoogleUserInfo) error {
	if g.db == nil {
		return fmt.Errorf("database not initialized")
	}

	avatarURL := g.downloadAndUploadAvatarIfAvailable(userID, googleInfo.Picture)

	// Update Google user table information
	var googleUser GoogleUser
	if err := g.db.Where("user_id = ?", userID).First(&googleUser).Error; err != nil {
		return err
	}

	googleUser.Name = googleInfo.Name
	googleUser.Email = normalizeGoogleEmailForStorage(googleInfo.Email)
	googleUser.VerifiedEmail = googleInfo.EmailVerified
	if avatarURL != "" {
		googleUser.Picture = avatarURL
	}
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
	if avatarURL != "" {
		user.Avatar = avatarURL
	}
	user.UpdatedAt = time.Now()

	return g.db.Save(&user).Error
}

func (g *GoogleOAuth) ensureEmailUserForVerifiedGoogle(tx *gorm.DB, userID, email string, emailVerified bool) error {
	if !canLinkGoogleEmail(email, emailVerified) {
		return nil
	}
	normalizedEmail, err := NormalizeEmailAddress(email)
	if err != nil {
		return nil
	}
	var existing EmailUser
	err = tx.First(&existing, "email = ?", normalizedEmail).Error
	switch {
	case err == nil:
		if existing.UserID == userID {
			return nil
		}
		return ErrDuplicateUser("Email is already in use")
	case errors.Is(err, gorm.ErrRecordNotFound):
	default:
		return err
	}
	now := time.Now()
	return tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&EmailUser{
		UserID:    userID,
		Email:     normalizedEmail,
		CreatedAt: now,
		UpdatedAt: now,
	}).Error
}

func normalizeGoogleEmailForStorage(email string) string {
	normalized, err := NormalizeEmailAddress(email)
	if err != nil {
		return strings.TrimSpace(strings.ToLower(email))
	}
	return normalized
}

func (g *GoogleOAuth) downloadAndUploadAvatarIfAvailable(userID, pictureURL string) string {
	if g == nil || g.avatarService == nil || strings.TrimSpace(pictureURL) == "" {
		return ""
	}
	avatarURL, err := g.avatarService.DownloadAndUploadAvatar(userID, pictureURL)
	if err != nil {
		log.Printf("failed to process Google avatar for user %s: %v", userID, err)
		return ""
	}
	return avatarURL
}

// GetClientID 获取 Google OAuth 客户端 ID
func (g *GoogleOAuth) GetClientID() string {
	return g.config.ClientID
}
