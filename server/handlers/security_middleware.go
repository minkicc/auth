package handlers

import (
	"net/http"
	"net/url"

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

		expectedOrigin := common.RequestOrigin(c.Request, h.publicBaseURL())
		if expectedOrigin == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}

		origin := c.GetHeader("Origin")
		if origin != "" {
			if origin != expectedOrigin {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
				return
			}
			c.Next()
			return
		}

		referer := c.GetHeader("Referer")
		if referer == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}

		refererURL, err := url.Parse(referer)
		if err != nil || refererURL.Scheme == "" || refererURL.Host == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		if refererURL.Scheme+"://"+refererURL.Host != expectedOrigin {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}

		c.Next()
	}
}
