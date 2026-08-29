/*
 * Licensed under the MIT License.
 */

package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"example.com/auth/server/common"
)

const (
	RedisPrefixEmailPreregister = common.RedisKeyEmailPreregister
)

const (
	VerificationTypeEmailLogin VerificationType = "email_login"
)

// Extended AccountAuth
type EmailAuth struct {
	db *gorm.DB
	// maxLoginAttempts   int
	// loginLockDuration  time.Duration
	verificationExpiry time.Duration
	emailService       EmailService
	redis              *AccountRedisStore
}

// EmailService Email service interface
type EmailService interface {
	SendVerificationEmail(email, token, title, content string) error
	SendLoginCodeEmail(email, code, title, content string) error
	SendPasswordResetEmail(email, token, title, content string) error
	SendLoginNotificationEmail(email, ip, title, content string) error
}

// Pre-registration information, stored in Redis
type EmailPreregisterInfo struct {
	Email     string    `json:"email"`
	Password  string    `json:"password"` // Encrypted password
	Nickname  string    `json:"nickname"`
	CreatedAt time.Time `json:"created_at"`
}

// Configuration options
type EmailAutnConfig struct {
	VerificationExpiry time.Duration
	EmailService       EmailService
	Redis              *AccountRedisStore
}

func NewEmailAuth(db *gorm.DB, config EmailAutnConfig) *EmailAuth {
	return &EmailAuth{
		db:                 db,
		verificationExpiry: config.VerificationExpiry,
		emailService:       config.EmailService,
		redis:              config.Redis, // Use pointer directly
	}
}

// AutoMigrate Automatically migrate database table structure
func (a *EmailAuth) AutoMigrate() error {
	if err := a.db.AutoMigrate(
		&User{},
		&EmailUser{},
	); err != nil {
		return err
	}
	return nil
}

// Generate verification token
func generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// InitiatePasswordReset Initiate password reset
func (a *EmailAuth) InitiatePasswordReset(email, title, content string) (string, error) {
	var err error
	email, err = NormalizeEmailAddress(email)
	if err != nil {
		return "", err
	}

	user, err := a.GetUserByEmail(email)
	if err != nil {
		return "", err
	}

	// Generate reset token
	token, err := generateToken()
	if err != nil {
		return "", err
	}

	// Store verification record in Redis with expiration time
	if err := a.redis.StoreVerification(VerificationTypePassword, email, token, user.UserID, a.verificationExpiry); err != nil {
		return "", fmt.Errorf("failed to store password reset verification information: %w", err)
	}

	// Send reset email
	if err := a.emailService.SendPasswordResetEmail(email, token, title, content); err != nil {
		return "", err
	}

	return token, nil
}

// CompletePasswordReset Complete password reset
func (a *EmailAuth) CompletePasswordReset(token, newPassword string) (string, error) {
	// Get verification record from Redis
	verification, err := a.redis.GetVerificationByToken(VerificationTypePassword, token)
	if err != nil {
		return "", ErrInvalidToken("Password reset token is invalid or expired")
	}

	// Validate new password strength
	if len(newPassword) < 8 {
		return "", ErrWeakPassword("Password must be at least 8 characters")
	}

	// Encrypt new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	var user User
	if err := a.db.Where("user_id = ?", verification.UserID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrInvalidToken("Invalid user ID")
		}
		return "", err
	}

	// Update password in User table
	result := a.db.Model(&user).Updates(map[string]interface{}{
		"password":      string(hashedPassword),
		"token_version": EffectiveUserTokenVersion(&user) + 1,
		"updated_at":    time.Now(),
	})

	if result.Error != nil {
		return "", result.Error
	}

	if result.RowsAffected == 0 {
		return "", ErrInvalidToken("Invalid user ID")
	}

	// Delete token after use
	if err := a.redis.DeleteVerification(VerificationTypePassword, verification.Identifier, token); err != nil {
		fmt.Printf("Failed to delete password reset verification: %v\n", err)
	}

	return verification.UserID, nil
}

// EmailPreregister Email pre-registration, sends verification email but doesn't create user
func (a *EmailAuth) EmailPreregister(email, password, nickname, title, content string) (string, error) {
	var err error
	email, err = NormalizeEmailAddress(email)
	if err != nil {
		return "", err
	}

	// Check if email is duplicate
	if err := a.CheckDuplicateEmail(email); err != nil {
		return "", err
	}

	// If nickname is not provided, use email prefix as default nickname
	if nickname == "" {
		parts := strings.Split(email, "@")
		nickname = parts[0]
	}

	hashedPassword, err := hashEmailPasswordOrRandom(password)
	if err != nil {
		return "", err
	}

	// Generate verification token
	token, err := generateToken()
	if err != nil {
		return "", err
	}
	// log.Println("email preregister token:", token)
	// Create pre-registration information
	preregInfo := &EmailPreregisterInfo{
		Email:     email,
		Password:  string(hashedPassword),
		Nickname:  nickname,
		CreatedAt: time.Now(),
	}

	// Store pre-registration information in Redis
	preregKey := fmt.Sprintf("%s%s:%s", RedisPrefixEmailPreregister, email, token)
	if err := a.redis.Set(preregKey, preregInfo, a.verificationExpiry); err != nil {
		return "", fmt.Errorf("failed to store pre-registration information: %w", err)
	}

	// Associate verification token with email
	if err := a.redis.StoreVerification(VerificationTypeEmail, email, token, "", a.verificationExpiry); err != nil {
		return "", fmt.Errorf("failed to store email verification information: %w", err)
	}

	// Send verification email
	if err := a.emailService.SendVerificationEmail(email, token, title, content); err != nil {
		return "", fmt.Errorf("failed to send verification email: %w", err)
	}

	return token, nil
}

func (a *EmailAuth) ResentEmailVerification(email, title, content string) (bool, error) {
	var err error
	email, err = NormalizeEmailAddress(email)
	if err != nil {
		return false, err
	}

	verification, err := a.redis.GetVerification(VerificationTypeEmail, email)
	if err != nil {
		return false, err
	}

	// Send verification email
	if err := a.emailService.SendVerificationEmail(email, verification.Token, title, content); err != nil {
		return false, fmt.Errorf("failed to send verification email: %w", err)
	}

	return true, nil
}

// RegisterEmailUser Email user registration - this function is now used internally, called after verification
func (a *EmailAuth) RegisterEmailUser(email, password, nickname string) (*User, error) {
	var err error
	email, err = NormalizeEmailAddress(email)
	if err != nil {
		return nil, err
	}

	// Check if email is duplicate
	if err := a.CheckDuplicateEmail(email); err != nil {
		return nil, err
	}

	// Generate random UserID
	userID, err := GenerateUserID(a.db)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random ID: %v", err)
	}

	// If nickname is not provided, use email prefix as default nickname
	if nickname == "" {
		parts := strings.Split(email, "@")
		nickname = parts[0]
	}

	// Start transaction
	tx := a.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Create basic user record
	now := time.Now()
	user := &User{
		UserID:       userID,
		Password:     password, // Already encrypted password
		TokenVersion: DefaultTokenVersion,
		Status:       UserStatusActive,
		Nickname:     nickname,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	// Create email user association record
	emailUser := &EmailUser{
		UserID: userID,
		Email:  email,
		// Verified:  true, // Email is verified
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := tx.Create(emailUser).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create email user association: %v", err)
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to save data: %v", err)
	}

	return user, nil
}

// AttachEmailToUser links a verified email address to an existing user.
func (a *EmailAuth) AttachEmailToUser(userID, email string) error {
	if a == nil || a.db == nil {
		return fmt.Errorf("database not initialized")
	}
	email, err := NormalizeEmailAddress(email)
	if err != nil {
		return err
	}
	if strings.TrimSpace(userID) == "" {
		return ErrInvalidInput("User ID is required")
	}

	var existing EmailUser
	err = a.db.First(&existing, "email = ?", email).Error
	switch {
	case err == nil:
		if existing.UserID == userID {
			return nil
		}
		return ErrDuplicateUser("Email is already in use")
	case errors.Is(err, gorm.ErrRecordNotFound):
		now := time.Now()
		return a.db.Create(&EmailUser{
			UserID:    userID,
			Email:     email,
			CreatedAt: now,
			UpdatedAt: now,
		}).Error
	default:
		return err
	}
}

// VerifyEmail Verify email and complete registration
func (a *EmailAuth) VerifyEmail(token string) (*User, error) {
	// Get verification record from Redis
	verification, err := a.redis.GetVerificationByToken(VerificationTypeEmail, token)
	if err != nil {
		return nil, ErrInvalidToken("Email verification token is invalid or expired")
	}

	email := verification.Identifier

	// Try to get pre-registration information
	preregKey := fmt.Sprintf("%s%s:%s", RedisPrefixEmailPreregister, email, token)
	var preregInfo EmailPreregisterInfo
	if err := a.redis.Get(preregKey, &preregInfo); err != nil {
		return nil, ErrInvalidToken("Pre-registration information not found or expired, please register again")
	}

	// Complete registration
	user, err := a.RegisterEmailUser(email, preregInfo.Password, preregInfo.Nickname)
	if err != nil {
		return nil, fmt.Errorf("failed to complete registration: %w", err)
	}

	// Delete token after use
	if err := a.redis.DeleteVerification(VerificationTypeEmail, email, token); err != nil {
		// Only log error, doesn't affect registration process
		fmt.Printf("Failed to delete verification token: %v\n", err)
	}

	// Delete pre-registration information
	if err := a.redis.Delete(preregKey); err != nil {
		// Only log error, doesn't affect registration process
		fmt.Printf("Failed to delete pre-registration information: %v\n", err)
	}

	return user, nil
}

// SendVerificationEmail Send verification email - now used for registered users to re-verify email
// func (a *EmailAuth) SendVerificationEmail(userID, title, content string) error {
// 	// Query EmailUser record
// 	var emailUser EmailUser
// 	if err := a.db.Where("user_id = ?", userID).First(&emailUser).Error; err != nil {
// 		return err
// 	}

// 	if emailUser.Verified {
// 		return errors.New("User email has already been verified")
// 	}

// 	token, err := generateToken()
// 	if err != nil {
// 		return err
// 	}

// 	// Store verification record in Redis with expiration time
// 	if err := a.redis.StoreVerification(VerificationTypeEmail, emailUser.Email, token, userID, a.verificationExpiry); err != nil {
// 		return fmt.Errorf("Failed to store email verification information: %w", err)
// 	}

// 	return a.emailService.SendVerificationEmail(emailUser.Email, token, title, content)
// }

// EmailLogin Email user login
func (a *EmailAuth) EmailLogin(email, password string) (*User, error) {
	var err error
	email, err = NormalizeEmailAddress(email)
	if err != nil {
		return nil, err
	}

	// First query the corresponding email user
	var emailUser EmailUser
	err = a.db.Where("email = ?", email).First(&emailUser).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidPassword("Invalid email or password")
		}
		return nil, err
	}

	// Query associated User information through UserID
	var user User
	if err := a.db.Where("user_id = ?", emailUser.UserID).First(&user).Error; err != nil {
		return nil, err
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidPassword("Invalid email or password")
	}
	if err := EnsureUserCanAuthenticate(&user); err != nil {
		return nil, err
	}

	// Update last login time
	now := time.Now()
	user.LastLogin = &now
	if err := a.db.Save(&user).Error; err != nil {
		return nil, err
	}

	return &user, nil
}

// SendLoginCode sends a short-lived code for passwordless email login.
func (a *EmailAuth) SendLoginCode(email, title, content string) (string, error) {
	var err error
	email, err = NormalizeEmailAddress(email)
	if err != nil {
		return "", err
	}

	userID, err := a.findUserIDByVerifiedEmail(email)
	if err != nil {
		return "", err
	}

	code, err := generateVerificationCode()
	if err != nil {
		return "", err
	}

	if err := a.redis.StoreVerification(VerificationTypeEmailLogin, email, code, userID, 5*time.Minute); err != nil {
		return "", fmt.Errorf("failed to store email login verification code: %w", err)
	}

	if err := a.emailService.SendLoginCodeEmail(email, code, title, content); err != nil {
		return "", fmt.Errorf("failed to send email login verification code: %w", err)
	}

	return code, nil
}

// EmailCodeLogin logs in with an email verification code and links the email to
// a verified Google account when the Google account was created first.
func (a *EmailAuth) EmailCodeLogin(email, code string) (*User, error) {
	var err error
	email, err = NormalizeEmailAddress(email)
	if err != nil {
		return nil, err
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, ErrInvalidToken("Invalid or expired verification code")
	}

	verification, err := a.redis.GetVerification(VerificationTypeEmailLogin, email)
	if err != nil {
		return nil, ErrInvalidToken("Invalid or expired verification code")
	}
	if verification.Token != code {
		return nil, ErrInvalidToken("Invalid or expired verification code")
	}

	userID := strings.TrimSpace(verification.UserID)
	if userID == "" {
		userID, err = a.findUserIDByVerifiedEmail(email)
		if err != nil {
			return nil, err
		}
	}

	var user User
	if err := a.db.First(&user, "user_id = ?", userID).Error; err != nil {
		return nil, err
	}
	if err := EnsureUserCanAuthenticate(&user); err != nil {
		return nil, err
	}

	if err := a.AttachEmailToUser(user.UserID, email); err != nil {
		return nil, err
	}

	now := time.Now()
	user.LastLogin = &now
	user.UpdatedAt = now
	if err := a.db.Save(&user).Error; err != nil {
		return nil, err
	}

	_ = a.redis.DeleteVerification(VerificationTypeEmailLogin, email, verification.Token)
	return &user, nil
}

// GetUserByEmail Get user by email
func (a *EmailAuth) GetUserByEmail(email string) (*User, error) {
	var err error
	email, err = NormalizeEmailAddress(email)
	if err != nil {
		return nil, err
	}

	// First query EmailUser record
	var emailUser EmailUser
	if err := a.db.Where("email = ?", email).First(&emailUser).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "User does not exist", err)
		}
		return nil, err
	}

	// Then query User record through UserID
	var user User
	if err := a.db.Where("user_id = ?", emailUser.UserID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "User does not exist", err)
		}
		return nil, err
	}

	return &user, nil
}

func (a *EmailAuth) findUserIDByVerifiedEmail(email string) (string, error) {
	var emailUser EmailUser
	if err := a.db.First(&emailUser, "email = ?", email).Error; err == nil {
		return emailUser.UserID, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", err
	}

	var googleUser GoogleUser
	if err := a.db.First(&googleUser, "LOWER(email) = ? AND verified_email = ?", strings.ToLower(email), true).Error; err == nil {
		return googleUser.UserID, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", err
	}

	return "", ErrUserNotFound("User not found for this email address")
}

// CheckDuplicateEmail Check if email is duplicate
func (a *EmailAuth) CheckDuplicateEmail(email string) error {
	var err error
	email, err = NormalizeEmailAddress(email)
	if err != nil {
		return err
	}

	var count int64
	if err := a.db.Model(&EmailUser{}).Where("email = ?", email).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrDuplicateUser("Email is already in use")
	}
	return nil
}

// ValidatePassword Validate password strength
func (a *EmailAuth) ValidatePassword(password string) error {
	if len(password) < 8 {
		return ErrWeakPassword("Password must be at least 8 characters")
	}
	return nil
}

func hashEmailPasswordOrRandom(password string) (string, error) {
	password = strings.TrimSpace(password)
	if password != "" {
		if len(password) < 8 {
			return "", ErrWeakPassword("Password must be at least 8 characters")
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt password: %w", err)
		}
		return string(hashedPassword), nil
	}

	randomPassword := make([]byte, 32)
	if _, err := rand.Read(randomPassword); err != nil {
		return "", fmt.Errorf("failed to generate random password: %w", err)
	}
	hashedPassword, err := bcrypt.GenerateFromPassword(randomPassword, bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt random password: %w", err)
	}
	return string(hashedPassword), nil
}
