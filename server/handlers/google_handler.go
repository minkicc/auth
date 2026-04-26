/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/iam"
)

// handleGoogleUser processes a Google user and reports whether a new MKAuth user was created.
func (h *AuthHandler) handleGoogleUser(googleUserInfo *auth.GoogleUserInfo) (*auth.User, bool, error) {
	if h.googleOAuth == nil {
		return nil, false, fmt.Errorf("google OAuth is not enabled")
	}

	// Find existing user
	user, err := h.googleOAuth.GetUserByGoogleID(googleUserInfo.ID, googleUserInfo.Email, googleUserInfo.EmailVerified)
	if err != nil {
		return nil, false, err
	}
	created := user == nil
	if user == nil {
		user, err = h.googleOAuth.CreateUserFromGoogle(googleUserInfo)
		if err != nil {
			return nil, false, fmt.Errorf("failed to create Google user: %w", err)
		}
	} else {
		// Update user information
		// if err := h.googleOAuth.UpdateGoogleUserInfo(user.UserID, googleUserInfo); err != nil {
		// 	h.logger.Printf("Failed to update Google user information: %v", err)
		// 	// Does not affect login flow, just log the error
		// }
	}

	return user, created, nil
}

func (h *AuthHandler) GoogleCredential(c *gin.Context) {
	// 解析请求体
	var req struct {
		Credential string `json:"credential" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	googleUser, err := h.googleOAuth.VerifyIDToken(c.Request.Context(), req.Credential)
	if err != nil {
		h.logger.Printf("Failed to verify Google token: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Google token"})
		return
	}

	if err := h.runHook(c, iam.HookPreAuthenticate, nil, "google", nil, map[string]string{
		"identifier":     googleUser.Email,
		"google_subject": googleUser.ID,
		"email_verified": fmt.Sprintf("%t", googleUser.EmailVerified),
	}); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	// 创建或查找用户
	user, created, err := h.handleGoogleUser(googleUser)
	if err != nil {
		h.logger.Printf("Failed to process Google user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process user information"})
		return
	}
	if created {
		if err := h.runHook(c, iam.HookPostRegister, user, "google", nil, map[string]string{
			"identifier":     googleUser.Email,
			"google_subject": googleUser.ID,
			"email_verified": fmt.Sprintf("%t", googleUser.EmailVerified),
		}); err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
	}

	h.completeBrowserLoginWithProvider(c, user, "", "google")
}

func (h *AuthHandler) GetGoogleClientID(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"client_id": h.googleOAuth.GetClientID()})
}
