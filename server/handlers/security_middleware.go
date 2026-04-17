package handlers

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"minki.cc/mkauth/server/common"
)

func (h *AuthHandler) RequireSameOriginForBrowserSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		authMethod, _ := c.Get("auth_method")
		if authMethod != "browser_session" {
			c.Next()
			return
		}

		if !h.isSameOriginBrowserRequest(c, true) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

func (h *AuthHandler) RejectCrossOriginBrowserSessionCreation() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !h.isSameOriginBrowserRequest(c, false) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

func (h *AuthHandler) isSameOriginBrowserRequest(c *gin.Context, requireBrowserSignal bool) bool {
	expectedOrigin := common.RequestOrigin(c.Request, h.publicBaseURL())
	if expectedOrigin == "" {
		return false
	}

	origin := c.GetHeader("Origin")
	if origin != "" {
		return origin == expectedOrigin
	}

	referer := c.GetHeader("Referer")
	if referer != "" {
		refererURL, err := url.Parse(referer)
		if err != nil || refererURL.Scheme == "" || refererURL.Host == "" {
			return false
		}
		return refererURL.Scheme+"://"+refererURL.Host == expectedOrigin
	}

	if isCrossOriginFetchSite(c.GetHeader("Sec-Fetch-Site")) {
		return false
	}

	return !requireBrowserSignal
}

func isCrossOriginFetchSite(fetchSite string) bool {
	switch strings.ToLower(strings.TrimSpace(fetchSite)) {
	case "cross-site", "same-site":
		return true
	default:
		return false
	}
}
