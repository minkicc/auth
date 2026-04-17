/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"minki.cc/mkauth/server/auth"
)

// EmailLogin Email login
func (h *AuthHandler) EmailLogin(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Check login attempt limits
	clientIP := c.ClientIP()
	if err := h.accountAuth.CheckLoginAttempts(req.Email, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}

	// Use email to login
	user, err := h.emailAuth.EmailLogin(req.Email, req.Password)
	if err != nil {
		// Record failed login attempt
		h.accountAuth.RecordLoginAttempt(req.Email, clientIP, false)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Record successful login attempt
	h.accountAuth.RecordLoginAttempt(req.Email, clientIP, true)

	h.completeBrowserLogin(c, user, "")
}

// EmailRegister Email pre-registration
func (h *AuthHandler) EmailRegister(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
		Nickname string `json:"nickname"`
		Title    string `json:"title" binding:"required"`
		Content  string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Pre-register email user, only send verification email, don't create user
	_, err := h.emailAuth.EmailPreregister(req.Email, req.Password, req.Nickname, req.Title, req.Content)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Verification email has been sent, please check and click the verification link to complete registration",
		"email":   req.Email,
	})
}

// EmailVerify Email verification and complete registration
func (h *AuthHandler) EmailVerify(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing verification token"})
		return
	}
	// Verify email and complete registration
	user, err := h.emailAuth.VerifyEmail(token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.completeBrowserLogin(c, user, "Email verification successful, registration complete")
}

// ResendEmailVerification Resend email verification
func (h *AuthHandler) ResendEmailVerification(c *gin.Context) {
	var req struct {
		Email   string `json:"email" binding:"required,email"`
		Title   string `json:"title" binding:"required"`
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	_, err := h.emailAuth.ResentEmailVerification(req.Email, req.Title, req.Content)
	if err != nil {
		var appErr *auth.AppError
		if !errors.As(err, &appErr) || appErr.Code != auth.ErrCodeUserNotFound {
			if h.logger != nil {
				h.logger.Printf("Resend email verification failed for %s: %v", req.Email, err)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Verification email has been resent, please check"})
}

// EmailPasswordReset Email password reset
func (h *AuthHandler) EmailPasswordReset(c *gin.Context) {
	var req struct {
		Email   string `json:"email" binding:"required,email"`
		Title   string `json:"title" binding:"required"`
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Initiate password reset
	_, err := h.emailAuth.InitiatePasswordReset(req.Email, req.Title, req.Content)
	if err != nil {
		var appErr *auth.AppError
		if !errors.As(err, &appErr) || appErr.Code != auth.ErrCodeUserNotFound {
			if h.logger != nil {
				h.logger.Printf("Email password reset request failed for %s: %v", req.Email, err)
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process password reset request"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "If the email address exists, a password reset email has been sent",
	})
}

// CompleteEmailPasswordReset Complete email password reset
func (h *AuthHandler) CompleteEmailPasswordReset(c *gin.Context) {
	var req struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Complete password reset
	userID, err := h.emailAuth.CompletePasswordReset(req.Token, req.NewPassword)
	if err != nil {
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
		return
	}
	h.revokeUserSessions(c, userID)

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successful, please sign in again"})
}
