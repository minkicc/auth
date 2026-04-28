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
	"minki.cc/mkauth/server/iam"
)

// PhoneRegisterRequest Phone registration request
type PhoneRegisterRequest struct {
	Phone          string `json:"phone" binding:"required"`
	Password       string `json:"password" binding:"required"`
	Nickname       string `json:"nickname"`
	ClientID       string `json:"client_id"`
	InvitationCode string `json:"invitation_code"`
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

	normalizedPhone, err := auth.NormalizePhoneNumber(req.Phone)
	if err != nil {
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}
	req.Phone = normalizedPhone

	clientIP := c.ClientIP()
	attemptKey := phoneAttemptKey("code_login", req.Phone)
	if err := h.accountAuth.CheckLoginAttempts(attemptKey, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}

	if err := h.runHook(c, iam.HookPreAuthenticate, nil, "phone", nil, map[string]string{
		"identifier":   req.Phone,
		"login_method": "code",
	}); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
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

	h.completeBrowserLoginWithProvider(c, user, "Login successful", "phone")
}

// SendVerificationCode Handle send verification code request
func (h *AuthHandler) SendVerificationCode(c *gin.Context) {
	var req SendVerificationCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	normalizedPhone, err := auth.NormalizePhoneNumber(req.Phone)
	if err != nil {
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}
	req.Phone = normalizedPhone

	// Validate phone number format
	if err := h.phoneAuth.ValidatePhoneFormat(req.Phone); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Send verification code
	// Different types of verification codes can be sent for different scenarios
	// For example: login verification code, registration verification code, etc.
	_, err = h.phoneAuth.SendLoginSMS(req.Phone)
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

	normalizedPhone, err := auth.NormalizePhoneNumber(req.Phone)
	if err != nil {
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}
	req.Phone = normalizedPhone

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

	normalizedPhone, err := auth.NormalizePhoneNumber(req.Phone)
	if err != nil {
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}
	req.Phone = normalizedPhone

	clientIP := c.ClientIP()
	attemptKey := phoneAttemptKey("reset_init", req.Phone)
	if err := h.accountAuth.CheckRequestRateLimit(attemptKey, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}

	// Validate phone number format
	if err := h.phoneAuth.ValidatePhoneFormat(req.Phone); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Initiate password reset
	_, err = h.phoneAuth.InitiatePasswordReset(req.Phone)
	_ = h.accountAuth.RecordRateLimitedRequest(attemptKey, clientIP)
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
		Phone          string `json:"phone" binding:"required"`
		Password       string `json:"password" binding:"required"`
		Nickname       string `json:"nickname"`
		ClientID       string `json:"client_id"`
		InvitationCode string `json:"invitation_code"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	normalizedPhone, err := auth.NormalizePhoneNumber(req.Phone)
	if err != nil {
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}
	req.Phone = normalizedPhone

	if h.rejectRegistrationIfDisabled(c, "phone") {
		return
	}
	clientIP := c.ClientIP()
	attemptKey := phoneAttemptKey("preregister", req.Phone)
	if err := h.accountAuth.CheckRequestRateLimit(attemptKey, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}
	if err := h.phoneAuth.CheckDuplicatePhone(req.Phone); err != nil {
		var appErr *auth.AppError
		if errors.As(err, &appErr) {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	if len(req.Password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters"})
		return
	}

	if err := h.runHook(c, iam.HookPreRegister, nil, "phone", nil, map[string]string{
		"identifier": req.Phone,
	}); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	redemption, ok := h.beginRegistrationInvitation(c, "phone", req.Phone, "", req.ClientID, req.InvitationCode)
	if !ok {
		return
	}
	// Pre-register phone user, send verification code
	_, err = h.phoneAuth.PhonePreregister(req.Phone, req.Password, req.Nickname)
	if err != nil {
		h.cancelRegistrationInvitation(redemption)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !h.storePendingRegistrationInvitation(c, pendingPhoneInvitationKey(req.Phone), redemption) {
		return
	}
	_ = h.accountAuth.RecordRateLimitedRequest(attemptKey, clientIP)

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

	normalizedPhone, err := auth.NormalizePhoneNumber(req.Phone)
	if err != nil {
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}
	req.Phone = normalizedPhone

	clientIP := c.ClientIP()
	attemptKey := phoneAttemptKey("resend_verification", req.Phone)
	if err := h.accountAuth.CheckRequestRateLimit(attemptKey, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}

	// Resend verification code
	_, err = h.phoneAuth.ResendPhoneVerification(req.Phone)
	_ = h.accountAuth.RecordRateLimitedRequest(attemptKey, clientIP)
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

	normalizedPhone, err := auth.NormalizePhoneNumber(req.Phone)
	if err != nil {
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}
	req.Phone = normalizedPhone

	clientIP := c.ClientIP()
	attemptKey := phoneAttemptKey("register_verify", req.Phone)
	if err := h.accountAuth.CheckLoginAttempts(attemptKey, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}

	redemption, ok := h.loadPendingRegistrationInvitation(c, "phone", pendingPhoneInvitationKey(req.Phone))
	if !ok {
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
	if !h.completeRegistrationInvitation(c, redemption, user.UserID) {
		return
	}
	h.deletePendingRegistrationInvitation(pendingPhoneInvitationKey(req.Phone))

	if err := h.runHook(c, iam.HookPostRegister, user, "phone", nil, map[string]string{
		"identifier":   req.Phone,
		"verification": "phone",
	}); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	h.completeBrowserLoginWithProvider(c, user, "Phone verification successful, registration complete", "phone")
}

// PhoneLogin Phone number + password login
func (h *AuthHandler) PhoneLogin(c *gin.Context) {
	var req PhoneLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	normalizedPhone, err := auth.NormalizePhoneNumber(req.Phone)
	if err != nil {
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}
	req.Phone = normalizedPhone

	clientIP := c.ClientIP()
	attemptKey := phoneAttemptKey("password_login", req.Phone)
	if err := h.accountAuth.CheckLoginAttempts(attemptKey, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}

	if err := h.runHook(c, iam.HookPreAuthenticate, nil, "phone", nil, map[string]string{
		"identifier":   req.Phone,
		"login_method": "password",
	}); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
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

	h.completeBrowserLoginWithProvider(c, user, "Login successful", "phone")
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

	normalizedPhone, err := auth.NormalizePhoneNumber(req.Phone)
	if err != nil {
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}
	req.Phone = normalizedPhone

	clientIP := c.ClientIP()
	attemptKey := phoneAttemptKey("send_login_code", req.Phone)
	if err := h.accountAuth.CheckRequestRateLimit(attemptKey, clientIP); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}

	// Validate phone number format
	if err := h.phoneAuth.ValidatePhoneFormat(req.Phone); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Send login verification code
	_, err = h.phoneAuth.SendLoginSMS(req.Phone)
	_ = h.accountAuth.RecordRateLimitedRequest(attemptKey, clientIP)
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

	normalizedPhone, err := auth.NormalizePhoneNumber(req.Phone)
	if err != nil {
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}
	req.Phone = normalizedPhone

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
