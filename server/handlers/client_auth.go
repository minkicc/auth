package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"cc.minki/auth/server/auth"
	"cc.minki/auth/server/config"
	"cc.minki/auth/server/iam"
	"github.com/gin-gonic/gin"
)

type clientPhoneLoginRequest struct {
	Phone string `json:"phone" binding:"required"`
	Code  string `json:"code" binding:"required"`
}

type clientPhoneSendCodeRequest struct {
	Phone string `json:"phone" binding:"required"`
}

type clientWeixinUnionIDLoginRequest struct {
	UnionID   string `json:"union_id" binding:"required"`
	OpenID    string `json:"open_id"`
	Nickname  string `json:"nickname"`
	AvatarURL string `json:"avatar_url"`
}

func (h *AuthHandler) authenticateConfidentialClient(c *gin.Context) (oidcClient config.OIDCClientConfig, ok bool) {
	return h.authenticateConfidentialClientWithGrant(c, "phone_code")
}

func (h *AuthHandler) authenticateConfidentialClientWithGrant(c *gin.Context, grant string) (oidcClient config.OIDCClientConfig, ok bool) {
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
	if !valid || !hasGrant(client.GrantTypes, grant) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return config.OIDCClientConfig{}, false
	}
	return client, true
}

// ClientWeixinUnionIDLogin exchanges a server-verified WeChat UnionID for
// standard OIDC tokens. The WeChat app secret stays in the K12 backend; Auth
// only trusts this endpoint when called by a configured confidential client.
func (h *AuthHandler) ClientWeixinUnionIDLogin(c *gin.Context) {
	client, ok := h.authenticateConfidentialClientWithGrant(c, "phone_code")
	if !ok {
		return
	}
	if h.weixinLogin == nil || h.oidcProvider == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "weixin login is not enabled"})
		return
	}
	var req clientWeixinUnionIDLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.UnionID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	info := &auth.WeixinUserInfo{
		UnionID:    strings.TrimSpace(req.UnionID),
		OpenID:     strings.TrimSpace(req.OpenID),
		Nickname:   strings.TrimSpace(req.Nickname),
		HeadImgURL: strings.TrimSpace(req.AvatarURL),
	}
	user, err := h.weixinLogin.GetUserByWeixinID(info.UnionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "weixin login failed"})
		return
	}
	created := user == nil
	if created {
		if h.rejectRegistrationIfDisabled(c, "weixin") {
			return
		}
		redemption, invitationOK := h.beginRegistrationInvitation(c, "weixin", info.UnionID, "", client.ClientID, "")
		if !invitationOK {
			return
		}
		user, err = h.weixinLogin.CreateUserFromWeixin(info)
		if err != nil {
			h.cancelRegistrationInvitation(redemption)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "weixin login failed"})
			return
		}
		if !h.completeRegistrationInvitation(c, redemption, user.UserID) {
			return
		}
	} else if err := auth.EnsureUserCanAuthenticate(user); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "account is not available"})
		return
	}
	if !created {
		_ = h.accountAuth.DB().Model(&auth.User{}).Where("user_id = ?", user.UserID).Update("last_login", time.Now()).Error
	}
	tokens, err := h.oidcProvider.IssueUserTokens(c, user, client, "openid profile email")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue login token"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, tokens)
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
		if h.rejectRegistrationIfDisabled(c, "phone") {
			return
		}
		if _, err := h.phoneAuth.PhonePreregister(normalized, "", ""); err != nil {
			h.respondSMSDeliveryError(c, "trusted phone registration", normalized, err)
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "A verification code has been sent", "expires_in": verifyCodeTTL})
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
	user, err := h.phoneAuth.GetUserByPhone(normalized)
	created := false
	if err != nil {
		var appErr *auth.AppError
		if !errors.As(err, &appErr) || appErr.Code != auth.ErrCodeUserNotFound {
			_ = h.accountAuth.RecordLoginAttempt(attemptKey, c.ClientIP(), false)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid phone number or verification code"})
			return
		}
		if h.rejectRegistrationIfDisabled(c, "phone") {
			return
		}
		user, err = h.phoneAuth.VerifyPhoneAndRegister(normalized, strings.TrimSpace(req.Code))
		created = err == nil
	} else {
		user, err = h.phoneAuth.PhoneCodeLogin(normalized, strings.TrimSpace(req.Code))
	}
	if err != nil {
		_ = h.accountAuth.RecordLoginAttempt(attemptKey, c.ClientIP(), false)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid phone number or verification code"})
		return
	}
	_ = h.accountAuth.RecordLoginAttempt(attemptKey, c.ClientIP(), true)
	if created {
		if err := h.runHook(c, iam.HookPostRegister, user, "phone", nil, map[string]string{
			"identifier":   normalized,
			"verification": "phone",
			"client_id":    client.ClientID,
		}); err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
	}
	tokens, err := h.oidcProvider.IssueUserTokens(c, user, client, "openid profile email")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue login token"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, tokens)
}
