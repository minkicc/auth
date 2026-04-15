/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package handlers

import (
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

	// Create user
	user := &auth.User{
		UserID:   req.Username,
		Password: req.Password,
		// Status:   auth.UserStatusActive,
		Nickname: req.Username,
	}

	if err := h.accountAuth.Register(user.UserID, user.Password, user.Nickname); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Directly return login information
	// Check login attempt limits
	clientIP := c.ClientIP()
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

	// Create JWT token
	// token, err := h.jwtService.GenerateJWT(user.UserID, "", "")

	// Or create session
	session, err := h.sessionMgr.CreateUserSession(user.UserID, clientIP, c.Request.UserAgent(), auth.SessionExpiration)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	accessToken, err := h.jwtService.GenerateAccessToken(user.UserID, session.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}
	if err := h.setBrowserSession(c, session); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to establish browser session"})
		return
	}

	// // avata转换为url
	// if user.Avatar != "" {
	// 	url, err := h.avatarService.GetAvatarURL(user.Avatar)
	// 	if err != nil {
	// 		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	// 		return
	// 	}
	// 	user.Avatar = url
	// }

	c.JSON(http.StatusOK, gin.H{
		"user_id":     user.UserID,
		"token":       accessToken,
		"nickname":    user.Nickname,
		"avatar":      user.Avatar,
		"expire_time": auth.TokenExpiration,
	})
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

	// Create JWT token
	// token, err := h.jwtService.GenerateJWT(user.UserID, "", "")

	// Or create session
	session, err := h.sessionMgr.CreateUserSession(user.UserID, clientIP, c.Request.UserAgent(), auth.SessionExpiration)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	accessToken, err := h.jwtService.GenerateAccessToken(user.UserID, session.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.setBrowserSession(c, session); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to establish browser session"})
		return
	}

	// avata转换为url
	if user.Avatar != "" {
		url, err := h.avatarService.GetAvatarURL(user.Avatar)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		user.Avatar = url
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":     user.UserID,
		"token":       accessToken,
		"nickname":    user.Nickname,
		"avatar":      user.Avatar,
		"expire_time": auth.TokenExpiration,
	})
}

// Logout Logout handling
func (h *AuthHandler) Logout(c *gin.Context) {

	// Get session ID
	sessionID, ok := c.Get("session_id")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session ID not found"})
		return
	}

	// Get user information from context
	userID, ok := c.Get("user_id")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID not found"})
		return
	}

	// Revoke access token
	if err := h.jwtService.RevokeJWTByID(userID.(string), sessionID.(string)); err != nil {
		h.logger.Printf("Failed to revoke access token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke access token"})
		return
	}

	// Clear browser session cookie
	h.clearBrowserSession(c)

	// Delete session
	if err := h.sessionMgr.DeleteSession(userID.(string), sessionID.(string)); err != nil {
		// Even if session deletion fails, continue trying to revoke token
		h.logger.Printf("Failed to delete session: %v", err)
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
// 		"session_id":  session.ID,
// 		"expire_time": session.ExpiresAt,
// 	})
// }

// ResetPassword Reset password
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=6,max=32"`
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

	if err := h.accountAuth.ChangePassword(userID.(string), req.OldPassword, req.NewPassword); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})

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

	// avata转换为url
	if user.Avatar != "" {
		url, err := h.avatarService.GetAvatarURL(user.Avatar)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		user.Avatar = url
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

	// avata转换为url
	if user.Avatar != "" {
		url, err := h.avatarService.GetAvatarURL(user.Avatar)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		user.Avatar = url
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

	// 处理用户头像URL
	for i := range users {
		if users[i].Avatar != "" {
			url, err := h.avatarService.GetAvatarURL(users[i].Avatar)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			users[i].Avatar = url
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
		// Get session ID from request header
		// sessionID := c.GetHeader("Session-ID")
		// if sessionID != "" {
		// 	// Validate session
		// 	session, err := h.sessionMgr.GetSession(sessionID)
		// 	if err == nil && session != nil {
		// 		// Session valid, set user ID and continue
		// 		c.Set("user_id", session.UserID)
		// 		c.Next()
		// 		return
		// 	}
		// }

		var err error
		// No valid session, try to validate JWT
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			token := authHeader[7:]
			var claims *auth.CustomClaims
			// Validate JWT
			claims, err = h.jwtService.ValidateJWT(token)
			if err == nil && claims != nil {
				// JWT valid, set user ID
				// Note: claims.Subject should contain user ID
				c.Set("user_id", claims.UserID)
				c.Set("session_id", claims.SessionID)
				c.Next()
				return
			} else {
				// JWT invalid, deny access
				c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
				c.Abort()
				return
			}
		} else {
			// Not authenticated, deny access
			c.JSON(http.StatusUnauthorized, gin.H{"error": "no Authorization header"})
			c.Abort()
			return
		}

		// Not authenticated, deny access
		// c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed, please log in"})
		// c.Abort()
	}
}
