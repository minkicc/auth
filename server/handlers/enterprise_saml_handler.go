package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/common"
	"minki.cc/mkauth/server/iam"
)

const enterpriseSAMLStateTTL = 15 * time.Minute

type enterpriseSAMLState struct {
	ProviderSlug string    `json:"provider_slug"`
	RequestID    string    `json:"request_id"`
	ReturnURI    string    `json:"return_uri,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

func (h *AuthHandler) EnterpriseSAMLLogin(c *gin.Context) {
	if h.enterpriseSAML == nil || !h.enterpriseSAML.HasProviders() {
		c.JSON(http.StatusNotFound, gin.H{"error": "enterprise saml is not enabled"})
		return
	}

	relayState, err := auth.GenerateReadableRandomString(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create enterprise saml state"})
		return
	}

	flow, err := h.enterpriseSAML.StartAuthFlow(c.Param("slug"), relayState)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	stateData := enterpriseSAMLState{
		ProviderSlug: c.Param("slug"),
		RequestID:    flow.RequestID,
		ReturnURI:    h.safeEnterpriseOIDCReturnURI(c.Query("return_uri")),
		CreatedAt:    time.Now(),
	}
	if stateData.ReturnURI == "" {
		stateData.ReturnURI = h.safeEnterpriseOIDCReturnURI(c.Query("redirect_uri"))
	}
	if err := h.redisStore.Set(common.RedisKeyEnterpriseSAMLState+relayState, stateData, enterpriseSAMLStateTTL); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store enterprise saml state"})
		return
	}

	if flow.RedirectURL != "" {
		c.Redirect(http.StatusFound, flow.RedirectURL)
		return
	}

	c.Header("Content-Security-Policy", ""+
		"default-src; "+
		"script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; "+
		"reflected-xss block; referrer no-referrer;")
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, "<!DOCTYPE html><html><body>%s</body></html>", flow.PostForm)
}

func (h *AuthHandler) EnterpriseSAMLACS(c *gin.Context) {
	if h.enterpriseSAML == nil || !h.enterpriseSAML.HasProviders() {
		c.JSON(http.StatusNotFound, gin.H{"error": "enterprise saml is not enabled"})
		return
	}

	if err := c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid enterprise saml response"})
		return
	}

	relayState := strings.TrimSpace(c.Request.Form.Get("RelayState"))
	stateKey := common.RedisKeyEnterpriseSAMLState + relayState
	var stateData enterpriseSAMLState
	if relayState != "" {
		if err := h.redisStore.Get(stateKey, &stateData); err == nil && stateData.ProviderSlug != "" {
			_ = h.redisStore.Delete(stateKey)
		}
	}

	callbackSlug := strings.TrimSpace(c.Param("slug"))
	if stateData.ProviderSlug != "" && callbackSlug != stateData.ProviderSlug {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enterprise saml state provider mismatch"})
		return
	}

	if err := h.runHook(c, iam.HookPreAuthenticate, nil, "enterprise_saml", nil, map[string]string{
		"provider_slug": callbackSlug,
	}); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	possibleRequestIDs := []string{}
	if stateData.RequestID != "" {
		possibleRequestIDs = append(possibleRequestIDs, stateData.RequestID)
	}

	result, err := h.enterpriseSAML.AuthenticateWithResult(c.Request, callbackSlug, possibleRequestIDs)
	if err != nil {
		h.logger.Printf("Enterprise SAML ACS failed: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "enterprise saml authentication failed"})
		return
	}
	user := result.User
	if result.Created {
		if err := h.runHook(c, iam.HookPostRegister, user, "enterprise_saml", nil, map[string]string{
			"provider_slug": callbackSlug,
		}); err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
	}

	returnURI := stateData.ReturnURI
	if returnURI == "" {
		returnURI = "/profile"
	}
	if _, err := h.createBrowserSessionWithProvider(c, user, "enterprise_saml"); err != nil {
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Redirect(http.StatusFound, returnURI)
}

func (h *AuthHandler) EnterpriseSAMLMetadata(c *gin.Context) {
	if h.enterpriseSAML == nil || !h.enterpriseSAML.HasProviders() {
		c.JSON(http.StatusNotFound, gin.H{"error": "enterprise saml is not enabled"})
		return
	}
	data, err := h.enterpriseSAML.MetadataXML(c.Param("slug"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.Data(http.StatusOK, "application/samlmetadata+xml", data)
}
