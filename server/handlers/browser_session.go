package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/common"
)

func setLaxCookie(c *gin.Context, name, value string, maxAge int, path, domain string, secure, httpOnly bool) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(name, value, maxAge, path, domain, secure, httpOnly)
}

func (h *AuthHandler) setBrowserSession(c *gin.Context, session *auth.Session) error {
	browserSessionID, err := auth.CreateBrowserSession(h.redisStore, session)
	if err != nil {
		return err
	}
	h.refreshBrowserSessionCookie(c, browserSessionID, session)
	return nil
}

func (h *AuthHandler) refreshBrowserSessionCookie(c *gin.Context, browserSessionID string, session *auth.Session) {
	maxAge := int(time.Until(session.ExpiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	setLaxCookie(c, auth.OIDCSessionCookieName, browserSessionID, maxAge, "/", "", h.browserSessionCookieSecure(c), true)
}

func (h *AuthHandler) clearBrowserSession(c *gin.Context) {
	if browserSessionID, err := c.Cookie(auth.OIDCSessionCookieName); err == nil && browserSessionID != "" {
		_ = auth.DeleteBrowserSession(h.redisStore, browserSessionID)
	}
	setLaxCookie(c, auth.OIDCSessionCookieName, "", -1, "/", "", h.browserSessionCookieSecure(c), true)
}

func (h *AuthHandler) browserSessionCookieSecure(c *gin.Context) bool {
	configuredIssuer := ""
	if h.config != nil {
		configuredIssuer = h.config.OIDC.Issuer
	}
	return common.IsSecureRequest(c.Request, configuredIssuer)
}

func (h *AuthHandler) GetBrowserSession(c *gin.Context) {
	browserSessionID, err := c.Cookie(auth.OIDCSessionCookieName)
	if err != nil || browserSessionID == "" {
		h.clearBrowserSession(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "browser session not found"})
		return
	}

	_, session, err := auth.ResolveBrowserSession(h.redisStore, h.sessionMgr, browserSessionID)
	if err != nil || session == nil {
		h.clearBrowserSession(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "browser session not found"})
		return
	}

	user, err := h.accountAuth.GetUserByID(session.UserID)
	if err != nil || auth.EnsureUserCanAuthenticate(user) != nil {
		h.clearBrowserSession(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "browser session not found"})
		return
	}

	if user.Avatar != "" {
		avatarURL, avatarErr := h.avatarService.GetAvatarURL(user.Avatar)
		if avatarErr == nil {
			user.Avatar = avatarURL
		}
	}

	h.refreshBrowserSessionCookie(c, browserSessionID, session)
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
	c.JSON(http.StatusOK, response)
}
