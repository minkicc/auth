package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/iam"
)

func (h *AuthHandler) completeBrowserLogin(c *gin.Context, user *auth.User, message string) {
	session, err := h.createBrowserSession(c, user)
	if err != nil {
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := h.populateAvatarURL(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := gin.H{
		"authenticated": true,
		"user_id":       user.UserID,
		"nickname":      user.Nickname,
		"avatar":        user.Avatar,
		"expires_at":    session.ExpiresAt,
	}
	if user.Username != "" {
		response["username"] = user.Username
	}
	if message != "" {
		response["message"] = message
	}

	c.JSON(http.StatusOK, response)
}

func (h *AuthHandler) createBrowserSession(c *gin.Context, user *auth.User) (*auth.Session, error) {
	if err := auth.EnsureUserCanAuthenticate(user); err != nil {
		return nil, err
	}
	if err := h.runHook(c, iam.HookPostAuthenticate, user, nil); err != nil {
		return nil, auth.NewPermissionDeniedError(err.Error())
	}

	session, err := h.sessionMgr.CreateUserSession(user.UserID, c.ClientIP(), c.Request.UserAgent(), auth.SessionExpiration)
	if err != nil {
		return nil, fmt.Errorf("Failed to create session")
	}

	if err := h.setBrowserSession(c, session); err != nil {
		return nil, fmt.Errorf("Failed to establish browser session")
	}

	return session, nil
}

func (h *AuthHandler) runHook(c *gin.Context, event iam.HookEvent, user *auth.User, claims map[string]any) error {
	if h == nil || h.hookRegistry == nil {
		return nil
	}
	return h.hookRegistry.Run(c.Request.Context(), event, &iam.HookContext{
		User:      user,
		IP:        c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		Claims:    claims,
		Metadata: map[string]string{
			"path":   c.Request.URL.Path,
			"method": c.Request.Method,
		},
	})
}

func (h *AuthHandler) revokeUserSessions(c *gin.Context, userID string) {
	if userID == "" {
		h.clearBrowserSession(c)
		return
	}
	if h.sessionMgr != nil {
		if _, err := h.sessionMgr.DeleteUserSessions(userID); err != nil && h.logger != nil {
			h.logger.Printf("Failed to revoke sessions for user %s: %v", userID, err)
		}
	}
	h.clearBrowserSession(c)
}

func (h *AuthHandler) populateAvatarURL(user *auth.User) error {
	if user == nil || user.Avatar == "" {
		return nil
	}

	url, err := h.avatarService.GetAvatarURL(user.Avatar)
	if err != nil {
		return err
	}
	user.Avatar = url
	return nil
}

func (h *AuthHandler) authenticateBrowserSession(c *gin.Context) bool {
	browserSessionID, err := c.Cookie(auth.OIDCSessionCookieName)
	if err != nil || browserSessionID == "" {
		return false
	}

	_, session, err := auth.ResolveBrowserSession(h.redisStore, h.sessionMgr, browserSessionID)
	if err != nil || session == nil {
		h.clearBrowserSession(c)
		return false
	}

	user, err := h.accountAuth.GetUserByID(session.UserID)
	if err != nil || auth.EnsureUserCanAuthenticate(user) != nil {
		h.clearBrowserSession(c)
		return false
	}

	h.refreshBrowserSessionCookie(c, browserSessionID, session)
	c.Set("user_id", session.UserID)
	c.Set("session_id", session.ID)
	c.Set("auth_method", "browser_session")
	return true
}

func (h *AuthHandler) authenticateOIDCAccessToken(c *gin.Context) error {
	if h.oidcProvider == nil {
		return fmt.Errorf("invalid_token")
	}

	token := bearerToken(c.GetHeader("Authorization"))
	if token == "" {
		return fmt.Errorf("missing bearer token")
	}

	claims, err := h.oidcProvider.ParseAccessToken(token)
	if err != nil || claims.TokenType != "access_token" {
		return fmt.Errorf("invalid_token")
	}

	user, err := h.accountAuth.GetUserByID(claims.Subject)
	if err != nil || auth.EnsureUserCanAuthenticate(user) != nil {
		return fmt.Errorf("invalid_token")
	}
	if auth.NormalizeTokenVersion(claims.TokenVersion) != auth.EffectiveUserTokenVersion(user) {
		return fmt.Errorf("invalid_token")
	}

	c.Set("user_id", user.UserID)
	c.Set("auth_method", "access_token")
	c.Set("client_id", claims.ClientID)
	c.Set("scope", claims.Scope)
	if claims.OrgID != "" {
		c.Set("org_id", claims.OrgID)
	}
	if claims.OrgSlug != "" {
		c.Set("org_slug", claims.OrgSlug)
	}
	return nil
}

func bearerToken(header string) string {
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}
