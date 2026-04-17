/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
)

// User registration type constants
type UserType string

const (
	UserTypeRegular UserType = "regular" // Regular account
	UserTypeEmail   UserType = "email"   // Email account
)

// Register Regular username/password registration
func (h *AuthHandler) Register(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		// Email    string `json:"email"`
		// Nickname string `json:"nickname"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	normalizedUsername, err := auth.NormalizeAccountID(req.Username)
	if err != nil {
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}
	req.Username = normalizedUsername

	// Create user
	user := &auth.User{
		UserID:   req.Username,
		Password: req.Password,
		Status:   auth.UserStatusActive,
		Nickname: req.Username,
	}

	if err := h.accountAuth.Register(user.UserID, user.Password, user.Nickname); err != nil {
		var appErr *auth.AppError
		if errors.As(err, &appErr) {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Directly return login information
	// Check login attempt limits
	// if err := h.accountAuth.CheckLoginAttempts(req.Username, clientIP); err != nil {
	// 	c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
	// 	return
	// }

	// user, err := h.accountAuth.Login(req.Username, req.Password)
	// if err != nil {
	// 	// Record failed login attempt
	// 	h.accountAuth.RecordLoginAttempt(req.Username, clientIP, false)
	// 	c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
	// 	return
	// }

	// Record successful login attempt
	// h.accountAuth.RecordLoginAttempt(req.Username, clientIP, true)

	h.completeBrowserLogin(c, user, "")
}

// Login Regular login
func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"` // Username or email
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	normalizedUsername, err := auth.NormalizeAccountID(req.Username)
	if err != nil {
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}
	req.Username = normalizedUsername

	// Check login attempt limits
	clientIP := c.ClientIP()
	if err := h.accountAuth.CheckLoginAttempts(req.Username, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}

	user, err := h.accountAuth.Login(req.Username, req.Password)
	if err != nil {
		// Record failed login attempt
		h.accountAuth.RecordLoginAttempt(req.Username, clientIP, false)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Record successful login attempt
	h.accountAuth.RecordLoginAttempt(req.Username, clientIP, true)

	h.completeBrowserLogin(c, user, "")
}

// Logout Logout handling
func (h *AuthHandler) Logout(c *gin.Context) {
	// Clear browser session cookie
	h.clearBrowserSession(c)

	userID, hasUserID := c.Get("user_id")
	sessionID, hasSessionID := c.Get("session_id")
	if hasUserID && hasSessionID {
		if err := h.sessionMgr.DeleteSession(userID.(string), sessionID.(string)); err != nil {
			h.logger.Printf("Failed to delete session: %v", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

// RefreshSession Refresh session
// func (h *AuthHandler) RefreshSession(c *gin.Context) {
// 	sessionID := c.GetHeader("Session-ID")
// 	if sessionID == "" {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Session ID not provided"})
// 		return
// 	}

// 	// Refresh session, extend validity to 7 days
// 	if err := h.sessionMgr.RefreshSession(sessionID, auth.SessionExpiration); err != nil {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to refresh session"})
// 		return
// 	}

// 	// Get refreshed session
// 	session, err := h.sessionMgr.GetSession(sessionID)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get session"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{
// 		"session_id": session.ID,
// 		"expires_at": session.ExpiresAt,
// 	})
// }

// ResetPassword Reset password
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8,max=32"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}

	userIDStr := userID.(string)
	if err := h.accountAuth.ChangePassword(userIDStr, req.OldPassword, req.NewPassword); err != nil {
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to change password"})
		return
	}
	h.revokeUserSessions(c, userIDStr)

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully, please sign in again"})

}

// GetUserInfo Get user information
func (h *AuthHandler) GetUserInfo(c *gin.Context) {
	// Get user ID from Session or JWT
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}

	// Convert userID to string
	userIDStr := ""
	switch v := userID.(type) {
	case string:
		userIDStr = v
	case uint:
		userIDStr = strconv.FormatUint(uint64(v), 10)
	case int:
		userIDStr = strconv.Itoa(v)
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID type"})
		return
	}

	user, err := h.accountAuth.GetUserByID(userIDStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := h.populateAvatarURL(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, user)
}

// GetUserInfo Get user information
func (h *AuthHandler) GetUserInfoById(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Need id param"})
		return
	}

	// Convert userID to string
	// userIDStr := ""
	// switch v := userID.(type) {
	// case string:
	// 	userIDStr = v
	// case uint:
	// 	userIDStr = strconv.FormatUint(uint64(v), 10)
	// case int:
	// 	userIDStr = strconv.Itoa(v)
	// default:
	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID type"})
	// 	return
	// }

	user, err := h.accountAuth.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := h.populateAvatarURL(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, user)
}

// 批量获取用户信息
func (h *AuthHandler) GetUsersInfo(c *gin.Context) {
	// 获取用户ID列表
	var req struct {
		UserIDs []string `json:"user_ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数"})
		return
	}

	trustedClient, exists := c.Get("trusted_client")
	if !exists {
		c.JSON(http.StatusForbidden, gin.H{"error": "权限不足"})
		c.Abort()
		return
	}
	// 验证权限范围
	hasReadScope := trustedClient.(*config.TrustedClient).HasScope("read:users")
	if !hasReadScope {
		c.JSON(http.StatusForbidden, gin.H{"error": "权限不足"})
		c.Abort()
		return
	}

	// 批量获取用户信息
	users, err := h.accountAuth.GetUsersByIDs(req.UserIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	for i := range users {
		if err := h.populateAvatarURL(&users[i]); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
	})
}

// UpdateUserInfo Update user information
func (h *AuthHandler) UpdateUserInfo(c *gin.Context) {
	var req struct {
		UserID   string `json:"user_id"`
		Nickname string `json:"nickname"`
		Avatar   string `json:"avatar"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Get user ID from Session or JWT
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}

	// Convert userID to string
	userIDStr := ""
	switch v := userID.(type) {
	case string:
		userIDStr = v
	case uint:
		userIDStr = strconv.FormatUint(uint64(v), 10)
	case int:
		userIDStr = strconv.Itoa(v)
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID type"})
		return
	}

	// Get existing user information
	user, err := h.accountAuth.GetUserByID(userIDStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Prepare update data
	updates := make(map[string]interface{})

	if user.Nickname != req.Nickname {
		updates["nickname"] = req.Nickname
		user.Nickname = req.Nickname
	}

	// If there are fields to update
	if len(updates) > 0 {
		if err := h.accountAuth.UpdateUser(user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "User information updated"})
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "No information to update"})
	}
}

// AuthRequired Verify if user is logged in
func (h *AuthHandler) AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h.authenticateBrowserSession(c) {
			c.Next()
			return
		}

		if err := h.authenticateOIDCAccessToken(c); err == nil {
			c.Next()
			return
		}

		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		c.Abort()
	}
}
