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

// PhoneRegisterRequest Phone registration request
type PhoneRegisterRequest struct {
	Phone    string `json:"phone" binding:"required"`
	Password string `json:"password" binding:"required"`
	Nickname string `json:"nickname"`
}

// PhoneLoginRequest Phone password login request
type PhoneLoginRequest struct {
	Phone    string `json:"phone" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// PhoneCodeLoginRequest Phone verification code login request
type PhoneCodeLoginRequest struct {
	Phone string `json:"phone" binding:"required"`
	Code  string `json:"code" binding:"required"`
}

// SendVerificationCodeRequest Send verification code request
type SendVerificationCodeRequest struct {
	Phone string `json:"phone" binding:"required"`
}

// VerifyPhoneRequest Verify phone number request
type VerifyPhoneRequest struct {
	Phone string `json:"phone" binding:"required"`
	Code  string `json:"code" binding:"required"`
}

// PhoneResetPasswordRequest Phone reset password request
type PhoneResetPasswordRequest struct {
	Phone       string `json:"phone" binding:"required"`
	Code        string `json:"code" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

const (
	verifyCodeTTL = 300 // Default 5 minutes
)

func phoneAttemptKey(scope, phone string) string {
	return "phone:" + scope + ":" + phone
}

// PhoneCodeLogin Phone number + verification code login
func (h *AuthHandler) PhoneCodeLogin(c *gin.Context) {
	var req PhoneCodeLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	clientIP := c.ClientIP()
	attemptKey := phoneAttemptKey("code_login", req.Phone)
	if err := h.accountAuth.CheckLoginAttempts(attemptKey, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}

	// Try verification code login
	user, err := h.phoneAuth.PhoneCodeLogin(req.Phone, req.Code)
	if err != nil {
		_ = h.accountAuth.RecordLoginAttempt(attemptKey, clientIP, false)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid phone number or verification code"})
		return
	}
	_ = h.accountAuth.RecordLoginAttempt(attemptKey, clientIP, true)

	h.completeBrowserLogin(c, user, "Login successful")
}

// SendVerificationCode Handle send verification code request
func (h *AuthHandler) SendVerificationCode(c *gin.Context) {
	var req SendVerificationCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate phone number format
	if err := h.phoneAuth.ValidatePhoneFormat(req.Phone); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Send verification code
	// Different types of verification codes can be sent for different scenarios
	// For example: login verification code, registration verification code, etc.
	_, err := h.phoneAuth.SendLoginSMS(req.Phone)
	if err != nil {
		var appErr *auth.AppError
		if !errors.As(err, &appErr) || appErr.Code != auth.ErrCodeUserNotFound {
			if h.logger != nil {
				h.logger.Printf("Failed to send phone verification code to %s: %v", req.Phone, err)
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification code"})
			return
		}
	}

	// Send successful
	c.JSON(http.StatusOK, gin.H{
		"message":    "If the phone number is registered, a verification code has been sent",
		"expires_in": verifyCodeTTL,
	})
}

// VerifyPhone Handle verify phone number request
func (h *AuthHandler) VerifyPhone(c *gin.Context) {
	var req VerifyPhoneRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Verify phone number
	if err := h.phoneAuth.VerifyPhone(req.Phone, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired verification code"})
		return
	}

	// Verification successful
	c.JSON(http.StatusOK, gin.H{"message": "Phone number verification successful"})
}

// PhoneInitiatePasswordReset Initiate password reset
func (h *AuthHandler) PhoneInitiatePasswordReset(c *gin.Context) {
	var req struct {
		Phone string `json:"phone" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate phone number format
	if err := h.phoneAuth.ValidatePhoneFormat(req.Phone); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Initiate password reset
	_, err := h.phoneAuth.InitiatePasswordReset(req.Phone)
	if err != nil {
		var appErr *auth.AppError
		if !errors.As(err, &appErr) || appErr.Code != auth.ErrCodeUserNotFound {
			if h.logger != nil {
				h.logger.Printf("Failed to initiate phone password reset for %s: %v", req.Phone, err)
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process password reset request"})
			return
		}
	}

	// Send successful
	c.JSON(http.StatusOK, gin.H{
		"message":    "If the phone number exists, a password reset verification code has been sent",
		"expires_in": verifyCodeTTL,
	})
}

// PhonePreregister Phone pre-registration - send verification code
func (h *AuthHandler) PhonePreregister(c *gin.Context) {
	var req struct {
		Phone    string `json:"phone" binding:"required"`
		Password string `json:"password" binding:"required"`
		Nickname string `json:"nickname"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Pre-register phone user, send verification code
	_, err := h.phoneAuth.PhonePreregister(req.Phone, req.Password, req.Nickname)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Verification code has been sent, please check and enter the code to complete registration",
		"phone":   req.Phone,
	})
}

// ResendPhoneVerification Resend phone verification code
func (h *AuthHandler) ResendPhoneVerification(c *gin.Context) {
	var req struct {
		Phone string `json:"phone" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Resend verification code
	_, err := h.phoneAuth.ResendPhoneVerification(req.Phone)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Verification code has been resent, please check",
	})
}

// VerifyPhoneAndRegister Verify phone number and complete registration
func (h *AuthHandler) VerifyPhoneAndRegister(c *gin.Context) {
	var req struct {
		Phone string `json:"phone" binding:"required"`
		Code  string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	clientIP := c.ClientIP()
	attemptKey := phoneAttemptKey("register_verify", req.Phone)
	if err := h.accountAuth.CheckLoginAttempts(attemptKey, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}

	// Verify phone number and complete registration
	user, err := h.phoneAuth.VerifyPhoneAndRegister(req.Phone, req.Code)
	if err != nil {
		_ = h.accountAuth.RecordLoginAttempt(attemptKey, clientIP, false)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_ = h.accountAuth.RecordLoginAttempt(attemptKey, clientIP, true)

	h.completeBrowserLogin(c, user, "Phone verification successful, registration complete")
}

// PhoneLogin Phone number + password login
func (h *AuthHandler) PhoneLogin(c *gin.Context) {
	var req PhoneLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	clientIP := c.ClientIP()
	attemptKey := phoneAttemptKey("password_login", req.Phone)
	if err := h.accountAuth.CheckLoginAttempts(attemptKey, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}

	// Try to login
	user, err := h.phoneAuth.PhoneLogin(req.Phone, req.Password)
	if err != nil {
		_ = h.accountAuth.RecordLoginAttempt(attemptKey, clientIP, false)
		// Return appropriate status code and message based on error type
		status := http.StatusUnauthorized
		message := "Invalid phone number or password"

		if appErr, ok := err.(*auth.AppError); ok {
			if appErr.Code == auth.ErrCodeEmailNotVerified {
				message = "Phone number not verified, please verify first"
			}
		}

		c.JSON(status, gin.H{"error": message})
		return
	}
	_ = h.accountAuth.RecordLoginAttempt(attemptKey, clientIP, true)

	h.completeBrowserLogin(c, user, "Login successful")
}

// SendLoginSMS Send login verification code
func (h *AuthHandler) SendLoginSMS(c *gin.Context) {
	var req struct {
		Phone string `json:"phone" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Validate phone number format
	if err := h.phoneAuth.ValidatePhoneFormat(req.Phone); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Send login verification code
	_, err := h.phoneAuth.SendLoginSMS(req.Phone)
	if err != nil {
		var appErr *auth.AppError
		if !errors.As(err, &appErr) || appErr.Code != auth.ErrCodeUserNotFound {
			if h.logger != nil {
				h.logger.Printf("Failed to send phone login code to %s: %v", req.Phone, err)
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send login verification code"})
			return
		}
	}

	// Send successful
	c.JSON(http.StatusOK, gin.H{
		"message":    "If the phone number is registered, a login verification code has been sent",
		"expires_in": verifyCodeTTL,
	})
}

// CompletePasswordReset Complete password reset
func (h *AuthHandler) PhoneCompletePasswordReset(c *gin.Context) {
	var req PhoneResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	clientIP := c.ClientIP()
	attemptKey := phoneAttemptKey("reset_password", req.Phone)
	if err := h.accountAuth.CheckLoginAttempts(attemptKey, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}

	// Complete password reset
	userID, err := h.phoneAuth.CompletePasswordReset(req.Code, req.Phone, req.NewPassword)
	if err != nil {
		var status int
		var message string

		switch appErr := err.(type) {
		case *auth.AppError:
			switch appErr.Code {
			case auth.ErrCodeInvalidToken:
				_ = h.accountAuth.RecordLoginAttempt(attemptKey, clientIP, false)
				status = http.StatusBadRequest
				message = "Invalid or expired verification code"
			case auth.ErrCodeWeakPassword:
				status = http.StatusBadRequest
				message = "Password too weak, please use a stronger password"
			default:
				status = http.StatusInternalServerError
				message = "Failed to reset password, please try again later"
			}
		default:
			status = http.StatusInternalServerError
			message = "Failed to reset password, please try again later"
		}

		c.JSON(status, gin.H{"error": message})
		return
	}
	_ = h.accountAuth.RecordLoginAttempt(attemptKey, clientIP, true)
	h.revokeUserSessions(c, userID)

	// Reset successful
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successful, please sign in again"})
}
