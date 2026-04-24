/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package auth

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// User Roles
type UserRole string

const (
	RoleAdmin UserRole = "admin"
	RoleUser  UserRole = "user"
	RoleGuest UserRole = "guest"
)

// Permissions
type Permission string

const (
	PermReadBasic   Permission = "read:basic"
	PermReadAdmin   Permission = "read:admin"
	PermWriteBasic  Permission = "write:basic"
	PermWriteAdmin  Permission = "write:admin"
	PermDeleteBasic Permission = "delete:basic"
	PermDeleteAdmin Permission = "delete:admin"
)

// Verification Types
type VerificationType string

const (
	VerificationTypeEmail     VerificationType = "email"
	VerificationTypePassword  VerificationType = "password"
	VerificationTypeTwoFactor VerificationType = "2fa"
)

// Login Attempt Record
type LoginAttempt struct {
	UserID    string `gorm:"primarykey"`
	IP        string `gorm:"size:45"`
	Success   bool
	CreatedAt time.Time
}

// Extended AccountAuth
type AccountAuth struct {
	db                *gorm.DB
	maxLoginAttempts  int
	loginLockDuration time.Duration
	redis             *AccountRedisStore // Using AccountRedisStore
}

// Configuration Options
type AccountAuthConfig struct {
	MaxLoginAttempts  int
	LoginLockDuration time.Duration
	Redis             *AccountRedisStore // Using AccountRedisStore
}

// NewAccountAuth Create account authentication instance
func NewAccountAuth(db *gorm.DB, config AccountAuthConfig) *AccountAuth {
	return &AccountAuth{
		db:                db,
		maxLoginAttempts:  config.MaxLoginAttempts,
		loginLockDuration: config.LoginLockDuration,
		redis:             config.Redis,
	}
}

func (a *AccountAuth) DB() *gorm.DB {
	if a == nil {
		return nil
	}
	return a.db
}

// AutoMigrate Automatically migrate database table structure
func (a *AccountAuth) AutoMigrate() error {
	// Ensure UserRole type is registered first
	if err := a.db.AutoMigrate(
		&User{},
		&AccountUser{},
	); err != nil {
		return err
	}

	return nil
}

// RecordLoginAttempt Record login attempt
func (a *AccountAuth) RecordLoginAttempt(userID string, ip string, success bool) error {
	// Only increase count on login failure
	if !success {
		// Increase failure count
		_, err := a.redis.IncrLoginAttempts(userID, ip, a.loginLockDuration)
		if err != nil {
			return fmt.Errorf("failed to record login attempt: %w", err)
		}

		// Can log login failures here
		return nil
	}

	// If login successful, reset failure count
	if success {
		return a.redis.ResetLoginAttempts(userID, ip)
	}

	return nil
}

// CheckLoginAttempts Check login attempt count
func (a *AccountAuth) CheckLoginAttempts(userID string, ip string) error {
	// Get failure attempt count for specified user IP
	count, err := a.redis.GetLoginAttempts(userID, ip)
	if err != nil {
		return fmt.Errorf("failed to check login attempt count: %w", err)
	}

	if count >= a.maxLoginAttempts {
		return NewAppError(ErrCodeTooManyRequests, "Too many login attempts, please try again later", nil)
	}

	return nil
}

// RecordRateLimitedRequest increments the rate-limit bucket for a request-scoped identifier.
func (a *AccountAuth) RecordRateLimitedRequest(identifier string, ip string) error {
	_, err := a.redis.IncrLoginAttempts(identifier, ip, a.loginLockDuration)
	if err != nil {
		return fmt.Errorf("failed to record rate-limited request: %w", err)
	}
	return nil
}

// CheckRequestRateLimit checks whether a request-scoped identifier has exceeded its request budget.
func (a *AccountAuth) CheckRequestRateLimit(identifier string, ip string) error {
	count, err := a.redis.GetLoginAttempts(identifier, ip)
	if err != nil {
		return fmt.Errorf("failed to check request rate limit: %w", err)
	}

	if count >= a.maxLoginAttempts {
		return NewAppError(ErrCodeTooManyRequests, "Too many requests, please try again later", nil)
	}

	return nil
}

// Login authenticates a regular username/password account.
func (a *AccountAuth) Login(username string, password string) (*User, error) {
	username, err := NormalizeAccountID(username)
	if err != nil {
		return nil, err
	}

	accountUser, err := a.GetAccountUserByUsername(username)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidPassword("Invalid account or password")
		}
		return nil, err
	}

	user, err := a.GetUserByID(accountUser.UserID)
	if err != nil {
		return nil, err
	}
	user.Username = accountUser.Username

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidPassword("Invalid account or password")
	}
	if err := EnsureUserCanAuthenticate(user); err != nil {
		return nil, err
	}

	now := time.Now()
	user.LastLogin = &now
	if err := a.db.Save(user).Error; err != nil {
		return nil, err
	}

	return user, nil
}

// UpdateUser Update user information
func (a *AccountAuth) UpdateUser(user *User) error {
	user.UpdatedAt = time.Now()
	return a.db.Save(user).Error
}

// GetUserByID Get user by ID
func (a *AccountAuth) GetUserByID(id string) (*User, error) {
	var user User
	if err := a.db.First(&user, "user_id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, NewAppError(ErrCodeUserNotFound, "User not found", err)
		}
		return nil, err
	}
	_ = a.PopulateAccountUsername(&user)
	return &user, nil
}

// GetAccountUserByUsername returns the regular account mapping for a normalized username.
func (a *AccountAuth) GetAccountUserByUsername(username string) (*AccountUser, error) {
	username, err := NormalizeAccountID(username)
	if err != nil {
		return nil, err
	}

	var accountUser AccountUser
	if err := a.db.First(&accountUser, "username = ?", username).Error; err != nil {
		return nil, err
	}
	return &accountUser, nil
}

// PopulateAccountUsername attaches the regular-account username to a public User response when one exists.
func (a *AccountAuth) PopulateAccountUsername(user *User) error {
	if user == nil || user.UserID == "" || user.Username != "" {
		return nil
	}

	var accountUser AccountUser
	if err := a.db.First(&accountUser, "user_id = ?", user.UserID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	user.Username = accountUser.Username
	return nil
}

// PreferredUsername returns a human-facing username without exposing it as the stable subject.
func (a *AccountAuth) PreferredUsername(user *User) string {
	if user == nil {
		return ""
	}
	_ = a.PopulateAccountUsername(user)
	if user.Username != "" {
		return user.Username
	}
	if user.Nickname != "" {
		return user.Nickname
	}
	return user.UserID
}

// UpdateProfile Update user profile
func (a *AccountAuth) UpdateProfile(userID string, updates map[string]interface{}) error {
	// Check if user exists
	user, err := a.GetUserByID(userID)
	if err != nil {
		return err
	}

	// Check if user ID is already taken
	if newUserID, ok := updates["user_id"]; ok && newUserID != user.UserID {
		// var count int64
		// if err := a.db.Model(&User{}).Where("user_id = ?", newUserID).Count(&count).Error; err != nil {
		// 	return err
		// }
		// if count > 0 {
		// 	return ErrUserIDTaken("Account ID is already taken")
		// }
		return fmt.Errorf("user_id 不可变更")
	}

	updates["updated_at"] = time.Now()
	return a.db.Model(user).Updates(updates).Error
}

// ChangePassword Change user password
func (a *AccountAuth) ChangePassword(userID string, oldPassword, newPassword string) error {
	user, err := a.GetUserByID(userID)
	if err != nil {
		return err
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword)); err != nil {
		return ErrInvalidPassword("Invalid old password")
	}

	// Validate new password strength
	if len(newPassword) < 8 {
		return ErrWeakPassword("Password must be at least 8 characters long")
	}

	// Encrypt new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return a.db.Model(user).Updates(map[string]interface{}{
		"password":      string(hashedPassword),
		"token_version": EffectiveUserTokenVersion(user) + 1,
		"updated_at":    time.Now(),
	}).Error
}

// Register creates a regular username/password account.
func (a *AccountAuth) Register(username string, password string, nickname string) (*User, error) {
	var err error
	username, err = NormalizeAccountID(username)
	if err != nil {
		return nil, err
	}

	// Check if username is duplicate
	if err := a.CheckDuplicateUsername(username); err != nil {
		return nil, err
	}

	if err := a.ValidatePassword(password); err != nil {
		return nil, err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %v", err)
	}

	userID, err := GenerateUserID(a.db)
	if err != nil {
		return nil, fmt.Errorf("failed to generate user ID: %v", err)
	}

	now := time.Now()
	if nickname == "" {
		nickname = username
	}
	user := &User{
		UserID:       userID,
		Username:     username,
		Password:     string(hashedPassword),
		TokenVersion: DefaultTokenVersion,
		Status:       UserStatusActive,
		// LastAttempt: now,
		CreatedAt: now,
		UpdatedAt: now,
		Nickname:  nickname,
	}

	tx := a.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	accountUser := &AccountUser{
		Username:  username,
		UserID:    userID,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := tx.Create(accountUser).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create account mapping: %v", err)
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return user, nil
}

// ValidateToken Validate token
func (a *AccountAuth) ValidateToken(token string) error {
	if token == "" {
		return ErrInvalidToken("Token cannot be empty")
	}
	return nil
}

// ValidatePassword Validate password
func (a *AccountAuth) ValidatePassword(password string) error {
	if len(password) < 8 {
		return ErrWeakPassword("Password must be at least 8 characters long")
	}
	return nil
}

// CheckDuplicateUsername Check if username is duplicate
func (a *AccountAuth) CheckDuplicateUsername(username string) error {
	var err error
	username, err = NormalizeAccountID(username)
	if err != nil {
		return err
	}

	var count int64
	if err := a.db.Model(&AccountUser{}).Where("username = ?", username).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrDuplicateUser("Username is already in use")
	}
	return nil
}

// CleanExpiredVerifications Clean expired verification records
func (a *AccountAuth) CleanExpiredVerifications() error {
	// Manual cleanup of expired verification records not needed when using Redis, Redis will handle this automatically
	// This method is kept for compatibility
	return nil
}

// GetUserByUserID Get user by UserID
// func (a *AccountAuth) GetUserByUserID(userID string) (*User, error) {
// 	var user User
// 	if err := a.db.Where("user_id = ?", userID).First(&user).Error; err != nil {
// 		if err == gorm.ErrRecordNotFound {
// 			return nil, NewAppError(ErrCodeUserNotFound, "User not found", err)
// 		}
// 		return nil, err
// 	}
// 	return &user, nil
// }

// CheckDuplicateUserID Check if UserID is duplicate
func (a *AccountAuth) CheckDuplicateUserID(userID string) error {
	var count int64
	if err := a.db.Model(&User{}).Where("user_id = ?", userID).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrDuplicateUser("Account ID is already in use")
	}
	return nil
}

// SetNickname Set nickname
func (a *AccountAuth) SetNickname(userID string, nickname string) error {
	user, err := a.GetUserByID(userID)
	if err != nil {
		return err
	}
	// todo 审核
	user.Nickname = nickname
	return a.db.Save(user).Error
}

// SetAvatar Set avatar
func (a *AccountAuth) SetAvatar(userID string, avatar string) error {
	user, err := a.GetUserByID(userID)
	if err != nil {
		return err
	}
	// todo 审核
	// todo 存oss
	user.Avatar = avatar
	return a.db.Save(user).Error
}

// GetUsersByIDs 批量获取用户信息
func (a *AccountAuth) GetUsersByIDs(ids []string) ([]User, error) {
	var users []User
	if err := a.db.Where("user_id IN ?", ids).Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}
