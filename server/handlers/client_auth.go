package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"cc.minki/auth/server/auth"
	"cc.minki/auth/server/config"
	"cc.minki/auth/server/iam"
)

type clientPhoneLoginRequest struct {
	Phone string `json:"phone" binding:"required"`
	Code  string `json:"code" binding:"required"`
}

type clientPhoneSendCodeRequest struct {
	Phone string `json:"phone" binding:"required"`
}

func (h *AuthHandler) authenticateConfidentialClient(c *gin.Context) (oidcClient config.OIDCClientConfig, ok bool) {
	if h == nil || h.oidcProvider == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "oidc is not enabled"})
		return config.OIDCClientConfig{}, false
	}
	clientID, clientSecret, hasBasic := c.Request.BasicAuth()
	if !hasBasic {
		clientID = strings.TrimSpace(c.PostForm("client_id"))
		clientSecret = c.PostForm("client_secret")
	}
	client, valid := h.oidcProvider.AuthenticateConfidentialClient(clientID, clientSecret)
	if !valid || !hasGrant(client.GrantTypes, "phone_code") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return config.OIDCClientConfig{}, false
	}
	return client, true
}

func hasGrant(grants []string, wanted string) bool {
	for _, grant := range grants {
		if strings.EqualFold(strings.TrimSpace(grant), wanted) {
			return true
		}
	}
	return false
}

func (h *AuthHandler) ClientPhoneSendLoginCode(c *gin.Context) {
	_, ok := h.authenticateConfidentialClient(c)
	if !ok {
		return
	}
	var req clientPhoneSendCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	normalized, err := auth.NormalizePhoneNumber(req.Phone)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid phone number"})
		return
	}
	if err := h.phoneAuth.ValidatePhoneFormat(normalized); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := h.phoneAuth.SendLoginSMS(normalized); err != nil {
		var appErr *auth.AppError
		if !errors.As(err, &appErr) || appErr.Code != auth.ErrCodeUserNotFound {
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed to send login verification code"})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "If the phone number is registered, a login verification code has been sent", "expires_in": verifyCodeTTL})
}

func (h *AuthHandler) ClientPhoneCodeLogin(c *gin.Context) {
	client, ok := h.authenticateConfidentialClient(c)
	if !ok {
		return
	}
	var req clientPhoneLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	normalized, err := auth.NormalizePhoneNumber(req.Phone)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid phone number"})
		return
	}
	attemptKey := phoneAttemptKey("client_code_login", normalized)
	if err := h.accountAuth.CheckLoginAttempts(attemptKey, c.ClientIP()); err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	}
	if err := h.runHook(c, iam.HookPreAuthenticate, nil, "phone", nil, map[string]string{
		"identifier":   normalized,
		"login_method": "client_code",
		"client_id":    client.ClientID,
	}); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	user, err := h.phoneAuth.PhoneCodeLogin(normalized, strings.TrimSpace(req.Code))
	if err != nil {
		_ = h.accountAuth.RecordLoginAttempt(attemptKey, c.ClientIP(), false)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid phone number or verification code"})
		return
	}
	_ = h.accountAuth.RecordLoginAttempt(attemptKey, c.ClientIP(), true)
	tokens, err := h.oidcProvider.IssueUserTokens(c, user, client, "openid profile email")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue login token"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, tokens)
}
