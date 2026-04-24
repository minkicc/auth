package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/common"
	"minki.cc/mkauth/server/iam"
)

const enterpriseOIDCStateTTL = 15 * time.Minute

type enterpriseOIDCState struct {
	ProviderSlug string    `json:"provider_slug"`
	Nonce        string    `json:"nonce"`
	ReturnURI    string    `json:"return_uri,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

func (h *AuthHandler) GetEnterpriseOIDCProviders(c *gin.Context) {
	if h.enterpriseOIDC == nil || !h.enterpriseOIDC.HasProviders() {
		c.JSON(http.StatusNotFound, gin.H{"error": "enterprise oidc is not enabled"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"providers": h.enterpriseOIDC.Providers()})
}

func (h *AuthHandler) DiscoverEnterpriseOIDC(c *gin.Context) {
	email := strings.TrimSpace(c.Query("email"))
	domain := strings.TrimSpace(c.Query("domain"))
	if email == "" && domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email or domain is required"})
		return
	}

	if h.enterpriseOIDC == nil {
		c.JSON(http.StatusOK, iam.EnterpriseOIDCDiscoveryResult{
			Status:    iam.EnterpriseOIDCDiscoveryNoProvider,
			Email:     strings.ToLower(email),
			Domain:    strings.ToLower(domain),
			Providers: []iam.EnterpriseOIDCProviderSummary{},
		})
		return
	}

	var (
		result iam.EnterpriseOIDCDiscoveryResult
		err    error
	)
	if email != "" {
		result, err = h.enterpriseOIDC.DiscoverByEmail(email)
	} else {
		result, err = h.enterpriseOIDC.DiscoverByDomain(domain)
	}
	if err != nil {
		if errors.Is(err, iam.ErrInvalidEnterpriseOIDCEmail) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email is invalid"})
			return
		}
		if errors.Is(err, iam.ErrInvalidEnterpriseOIDCDomain) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "domain is invalid"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *AuthHandler) EnterpriseOIDCLogin(c *gin.Context) {
	if h.enterpriseOIDC == nil || !h.enterpriseOIDC.HasProviders() {
		c.JSON(http.StatusNotFound, gin.H{"error": "enterprise oidc is not enabled"})
		return
	}

	state, err := auth.GenerateReadableRandomString(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create enterprise oidc state"})
		return
	}
	nonce, err := auth.GenerateReadableRandomString(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create enterprise oidc nonce"})
		return
	}

	authURL, err := h.enterpriseOIDC.AuthCodeURL(c.Request.Context(), c.Param("slug"), state, nonce)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	stateData := enterpriseOIDCState{
		ProviderSlug: c.Param("slug"),
		Nonce:        nonce,
		ReturnURI:    h.safeEnterpriseOIDCReturnURI(c.Query("return_uri")),
		CreatedAt:    time.Now(),
	}
	if stateData.ReturnURI == "" {
		stateData.ReturnURI = h.safeEnterpriseOIDCReturnURI(c.Query("redirect_uri"))
	}
	if err := h.redisStore.Set(common.RedisKeyEnterpriseOIDCState+state, stateData, enterpriseOIDCStateTTL); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store enterprise oidc state"})
		return
	}

	c.Redirect(http.StatusFound, authURL)
}

func (h *AuthHandler) EnterpriseOIDCCallback(c *gin.Context) {
	if h.enterpriseOIDC == nil || !h.enterpriseOIDC.HasProviders() {
		c.JSON(http.StatusNotFound, gin.H{"error": "enterprise oidc is not enabled"})
		return
	}

	state := strings.TrimSpace(c.Query("state"))
	code := strings.TrimSpace(c.Query("code"))
	if state == "" || code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing enterprise oidc code or state"})
		return
	}

	var stateData enterpriseOIDCState
	stateKey := common.RedisKeyEnterpriseOIDCState + state
	if err := h.redisStore.Get(stateKey, &stateData); err != nil || stateData.ProviderSlug == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid enterprise oidc state"})
		return
	}
	_ = h.redisStore.Delete(stateKey)

	if callbackSlug := strings.TrimSpace(c.Param("slug")); callbackSlug != stateData.ProviderSlug {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enterprise oidc state provider mismatch"})
		return
	}

	user, err := h.enterpriseOIDC.Authenticate(c.Request.Context(), stateData.ProviderSlug, code, stateData.Nonce)
	if err != nil {
		h.logger.Printf("Enterprise OIDC callback failed: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "enterprise oidc authentication failed"})
		return
	}

	if stateData.ReturnURI != "" {
		if _, err := h.createBrowserSession(c, user); err != nil {
			if appErr, ok := err.(*auth.AppError); ok {
				c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Redirect(http.StatusFound, stateData.ReturnURI)
		return
	}

	h.completeBrowserLogin(c, user, "")
}

func (h *AuthHandler) safeEnterpriseOIDCReturnURI(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return raw
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	issuer, err := url.Parse(h.publicBaseURL())
	if err != nil || issuer.Scheme == "" || issuer.Host == "" {
		return ""
	}
	if parsed.Scheme == issuer.Scheme && parsed.Host == issuer.Host {
		return raw
	}
	return ""
}
