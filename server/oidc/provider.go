package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/common"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

const (
	defaultCodeTTL        = 5 * time.Minute
	defaultAccessTokenTTL = 15 * time.Minute
	defaultIDTokenTTL     = 15 * time.Minute
)

var defaultScopes = []string{"openid", "profile", "email"}

type Provider struct {
	cfg         config.OIDCConfig
	db          *gorm.DB
	redis       *auth.RedisStore
	accountAuth *auth.AccountAuth
	sessionMgr  *auth.SessionManager
	signer      *tokenSigner
	hooks       *iam.HookRegistry
}

type tokenSigner struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
}

type authCode struct {
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	ClientID            string    `json:"client_id"`
	Nonce               string    `json:"nonce,omitempty"`
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	UserID              string    `json:"user_id"`
	CreatedAt           time.Time `json:"created_at"`
}

type AccessTokenClaims struct {
	Scope        string `json:"scope"`
	ClientID     string `json:"client_id"`
	TokenType    string `json:"token_type"`
	TokenVersion int    `json:"token_version,omitempty"`
	jwt.RegisteredClaims
}

type idTokenClaims struct {
	Nonce             string   `json:"nonce,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Name              string   `json:"name,omitempty"`
	Picture           string   `json:"picture,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     *bool    `json:"email_verified,omitempty"`
	OrgID             string   `json:"org_id,omitempty"`
	OrgSlug           string   `json:"org_slug,omitempty"`
	OrgRoles          []string `json:"org_roles,omitempty"`
	jwt.RegisteredClaims
}

type organizationClaims struct {
	OrgID    string
	OrgSlug  string
	OrgRoles []string
}

func NewProvider(cfg config.OIDCConfig, db *gorm.DB, redis *auth.RedisStore, accountAuth *auth.AccountAuth) (*Provider, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if redis == nil {
		return nil, fmt.Errorf("oidc requires redis storage")
	}
	if accountAuth == nil {
		return nil, fmt.Errorf("oidc requires account auth")
	}
	if len(cfg.Clients) == 0 {
		return nil, fmt.Errorf("oidc is enabled but no clients are configured")
	}

	for _, client := range cfg.Clients {
		if strings.TrimSpace(client.ClientID) == "" {
			return nil, fmt.Errorf("oidc client_id is required")
		}
		if len(client.RedirectURIs) == 0 {
			return nil, fmt.Errorf("oidc client %s must define at least one redirect_uri", client.ClientID)
		}
		if !client.Public && strings.TrimSpace(client.ClientSecret) == "" {
			return nil, fmt.Errorf("oidc confidential client %s must define client_secret", client.ClientID)
		}
	}

	signer, err := newTokenSigner(cfg)
	if err != nil {
		return nil, err
	}

	return &Provider{
		cfg:         cfg,
		db:          db,
		redis:       redis,
		accountAuth: accountAuth,
		sessionMgr:  auth.NewSessionManager(auth.NewSessionRedisStore(redis.GetClient())),
		signer:      signer,
	}, nil
}

func (p *Provider) SetHookRegistry(hooks *iam.HookRegistry) {
	if p != nil {
		p.hooks = hooks
	}
}

func (p *Provider) RegisterRoutes(r *gin.Engine) {
	r.GET("/.well-known/openid-configuration", p.discovery)
	r.GET("/oauth2/jwks", p.jwks)
	r.GET("/oauth2/authorize", p.authorize)
	r.POST("/oauth2/token", p.token)
	r.GET("/oauth2/logout", p.logout)
	r.GET("/oauth2/userinfo", p.userInfo)
	r.POST("/oauth2/userinfo", p.userInfo)
}

func (p *Provider) discovery(c *gin.Context) {
	issuer := p.issuer(c)
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth2/authorize",
		"token_endpoint":                        issuer + "/oauth2/token",
		"end_session_endpoint":                  issuer + "/oauth2/logout",
		"userinfo_endpoint":                     issuer + "/oauth2/userinfo",
		"jwks_uri":                              issuer + "/oauth2/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      defaultScopes,
		"claims_supported":                      []string{"sub", "preferred_username", "name", "picture", "email", "email_verified", "org_id", "org_slug", "org_roles"},
		"grant_types_supported":                 []string{"authorization_code"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (p *Provider) jwks(c *gin.Context) {
	n := base64.RawURLEncoding.EncodeToString(p.signer.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.signer.publicKey.E)).Bytes())
	c.JSON(http.StatusOK, gin.H{
		"keys": []gin.H{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": p.signer.keyID,
			"n":   n,
			"e":   e,
		}},
	})
}

func (p *Provider) authorize(c *gin.Context) {
	client, redirectURI, ok := p.validAuthorizeRequest(c)
	if !ok {
		return
	}

	user, err := p.currentUser(c)
	if err != nil {
		var appErr *auth.AppError
		if errors.As(err, &appErr) && (appErr.Code == auth.ErrCodeUserDisabled || appErr.Code == auth.ErrCodeUserLocked) {
			p.redirectAuthorizeError(c, redirectURI, "access_denied", c.Query("state"))
			return
		}
		if c.Query("prompt") == "none" {
			p.redirectAuthorizeError(c, redirectURI, "login_required", c.Query("state"))
			return
		}
		loginURL := "/login?client_id=" + url.QueryEscape(client.ClientID) + "&redirect_uri=" + url.QueryEscape(p.currentRequestURL(c))
		if loginHint := strings.TrimSpace(c.Query("login_hint")); loginHint != "" {
			loginURL += "&login_hint=" + url.QueryEscape(loginHint)
		}
		if domainHint := strings.TrimSpace(c.Query("domain_hint")); domainHint != "" {
			loginURL += "&domain_hint=" + url.QueryEscape(domainHint)
		}
		c.Redirect(http.StatusFound, loginURL)
		return
	}

	code := randomToken(32)
	codeData := authCode{
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.DefaultQuery("code_challenge_method", "S256"),
		ClientID:            client.ClientID,
		Nonce:               c.Query("nonce"),
		RedirectURI:         redirectURI,
		Scope:               strings.Join(strings.Fields(c.Query("scope")), " "),
		UserID:              user.UserID,
		CreatedAt:           time.Now(),
	}

	if err := p.redis.Set(common.RedisKeyOIDCAuthCode+code, codeData, p.codeTTL()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "failed to create authorization code"})
		return
	}

	values := url.Values{}
	values.Set("code", code)
	if state := c.Query("state"); state != "" {
		values.Set("state", state)
	}

	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	c.Redirect(http.StatusFound, redirectURI+sep+values.Encode())
}

func (p *Provider) token(c *gin.Context) {
	client, ok := p.authenticateClient(c)
	if !ok {
		return
	}

	if c.PostForm("grant_type") != "authorization_code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
		return
	}

	code := strings.TrimSpace(c.PostForm("code"))
	redirectURI := strings.TrimSpace(c.PostForm("redirect_uri"))
	if code == "" || redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "missing code or redirect_uri"})
		return
	}

	var stored authCode
	if err := p.redis.Get(common.RedisKeyOIDCAuthCode+code, &stored); err != nil || stored.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}
	defer p.redis.Delete(common.RedisKeyOIDCAuthCode + code)

	if stored.ClientID != client.ClientID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}
	if redirectURI != stored.RedirectURI {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}
	if !verifyPKCE(c.PostForm("code_verifier"), stored.CodeChallenge, stored.CodeChallengeMethod) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "pkce verification failed"})
		return
	}

	user, err := p.accountAuth.GetUserByID(stored.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}
	if err := auth.EnsureUserCanAuthenticate(user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	accessToken, expiresIn, err := p.signAccessToken(c, user, client, stored.Scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	idToken, err := p.signIDToken(c, user, client, stored.Scope, stored.Nonce)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   int(expiresIn.Seconds()),
		"scope":        stored.Scope,
	})
}

func (p *Provider) userInfo(c *gin.Context) {
	token := bearerToken(c.GetHeader("Authorization"))
	if token == "" {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	claims, err := p.ParseAccessToken(token)
	if err != nil || claims.TokenType != "access_token" {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	user, err := p.accountAuth.GetUserByID(claims.Subject)
	if err != nil || auth.EnsureUserCanAuthenticate(user) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	if auth.NormalizeTokenVersion(claims.TokenVersion) != auth.EffectiveUserTokenVersion(user) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	scopes := strings.Fields(claims.Scope)
	resp := gin.H{"sub": user.UserID}
	if containsString(scopes, "profile") {
		resp["preferred_username"] = p.accountAuth.PreferredUsername(user)
		resp["name"] = user.Nickname
		if user.Avatar != "" {
			resp["picture"] = user.Avatar
		}
		orgClaims := p.lookupOrganizationClaims(user.UserID)
		if orgClaims.OrgID != "" {
			resp["org_id"] = orgClaims.OrgID
		}
		if orgClaims.OrgSlug != "" {
			resp["org_slug"] = orgClaims.OrgSlug
		}
		if len(orgClaims.OrgRoles) > 0 {
			resp["org_roles"] = orgClaims.OrgRoles
		}
	}
	if containsString(scopes, "email") {
		email, verified := p.lookupEmail(user.UserID)
		if email != "" {
			resp["email"] = email
			resp["email_verified"] = verified
		}
	}
	if err := p.runHook(c, iam.HookBeforeUserInfo, user, claims.ClientID, resp); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "access_denied"})
		return
	}
	resp["sub"] = user.UserID

	c.JSON(http.StatusOK, resp)
}

func (p *Provider) logout(c *gin.Context) {
	postLogoutRedirectURI := strings.TrimSpace(c.Query("post_logout_redirect_uri"))
	clientID := strings.TrimSpace(c.Query("client_id"))
	if !p.validPostLogoutRedirect(clientID, postLogoutRedirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "invalid post_logout_redirect_uri",
		})
		return
	}

	if browserSessionID, err := c.Cookie(auth.OIDCSessionCookieName); err == nil && browserSessionID != "" {
		if data, session, resolveErr := auth.ResolveBrowserSession(p.redis, p.sessionMgr, browserSessionID); resolveErr == nil && session != nil {
			_ = p.sessionMgr.DeleteSession(data.UserID, data.SessionID)
		}
		_ = auth.DeleteBrowserSession(p.redis, browserSessionID)
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(auth.OIDCSessionCookieName, "", -1, "/", "", p.browserSessionCookieSecure(c), true)

	if postLogoutRedirectURI != "" {
		c.Redirect(http.StatusFound, postLogoutRedirectURI)
		return
	}

	c.JSON(http.StatusOK, gin.H{"logged_out": true})
}

func (p *Provider) signAccessToken(c *gin.Context, user *auth.User, client config.OIDCClientConfig, scope string) (string, time.Duration, error) {
	now := time.Now()
	ttl := p.accessTokenTTL()
	claims := AccessTokenClaims{
		Scope:        scope,
		ClientID:     client.ClientID,
		TokenType:    "access_token",
		TokenVersion: auth.EffectiveUserTokenVersion(user),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.issuer(c),
			Subject:   user.UserID,
			Audience:  jwt.ClaimStrings{client.ClientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	value, err := p.signer.sign(claims)
	return value, ttl, err
}

func (p *Provider) signIDToken(c *gin.Context, user *auth.User, client config.OIDCClientConfig, scope, nonce string) (string, error) {
	now := time.Now()
	scopes := strings.Fields(scope)
	claims := idTokenClaims{
		Nonce: nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.issuer(c),
			Subject:   user.UserID,
			Audience:  jwt.ClaimStrings{client.ClientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(p.idTokenTTL())),
		},
	}
	if containsString(scopes, "profile") {
		claims.PreferredUsername = p.accountAuth.PreferredUsername(user)
		claims.Name = user.Nickname
		claims.Picture = user.Avatar
		orgClaims := p.lookupOrganizationClaims(user.UserID)
		claims.OrgID = orgClaims.OrgID
		claims.OrgSlug = orgClaims.OrgSlug
		claims.OrgRoles = orgClaims.OrgRoles
	}
	if containsString(scopes, "email") {
		email, verified := p.lookupEmail(user.UserID)
		if email != "" {
			claims.Email = email
			claims.EmailVerified = &verified
		}
	}
	claimMap := idTokenClaimMap(claims)
	if err := p.runHook(c, iam.HookBeforeTokenIssue, user, client.ClientID, claimMap); err != nil {
		return "", err
	}
	protectIDTokenClaims(claimMap, claims)
	return p.signer.sign(jwt.MapClaims(claimMap))
}

func (p *Provider) ParseAccessToken(token string) (*AccessTokenClaims, error) {
	parsed, err := jwt.ParseWithClaims(token, &AccessTokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return p.signer.publicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	if err != nil {
		return nil, err
	}
	claims, ok := parsed.Claims.(*AccessTokenClaims)
	if !ok || !parsed.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

func (p *Provider) runHook(c *gin.Context, event iam.HookEvent, user *auth.User, clientID string, claims map[string]any) error {
	if p == nil || p.hooks == nil {
		return nil
	}
	return p.hooks.Run(c.Request.Context(), event, &iam.HookContext{
		User:      user,
		ClientID:  clientID,
		Claims:    claims,
		IP:        c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		Metadata: map[string]string{
			"path":   c.Request.URL.Path,
			"method": c.Request.Method,
		},
	})
}

func idTokenClaimMap(claims idTokenClaims) map[string]any {
	result := map[string]any{
		"iss": claims.Issuer,
		"sub": claims.Subject,
		"aud": []string(claims.Audience),
	}
	if claims.IssuedAt != nil {
		result["iat"] = claims.IssuedAt.Unix()
	}
	if claims.ExpiresAt != nil {
		result["exp"] = claims.ExpiresAt.Unix()
	}
	if claims.NotBefore != nil {
		result["nbf"] = claims.NotBefore.Unix()
	}
	if claims.ID != "" {
		result["jti"] = claims.ID
	}
	if claims.Nonce != "" {
		result["nonce"] = claims.Nonce
	}
	if claims.PreferredUsername != "" {
		result["preferred_username"] = claims.PreferredUsername
	}
	if claims.Name != "" {
		result["name"] = claims.Name
	}
	if claims.Picture != "" {
		result["picture"] = claims.Picture
	}
	if claims.Email != "" {
		result["email"] = claims.Email
	}
	if claims.EmailVerified != nil {
		result["email_verified"] = *claims.EmailVerified
	}
	if claims.OrgID != "" {
		result["org_id"] = claims.OrgID
	}
	if claims.OrgSlug != "" {
		result["org_slug"] = claims.OrgSlug
	}
	if len(claims.OrgRoles) > 0 {
		result["org_roles"] = claims.OrgRoles
	}
	return result
}

func protectIDTokenClaims(claimMap map[string]any, claims idTokenClaims) {
	claimMap["iss"] = claims.Issuer
	claimMap["sub"] = claims.Subject
	claimMap["aud"] = []string(claims.Audience)
	if claims.IssuedAt != nil {
		claimMap["iat"] = claims.IssuedAt.Unix()
	}
	if claims.ExpiresAt != nil {
		claimMap["exp"] = claims.ExpiresAt.Unix()
	}
	if claims.Nonce != "" {
		claimMap["nonce"] = claims.Nonce
	}
}

func (p *Provider) currentUser(c *gin.Context) (*auth.User, error) {
	browserSessionID, err := c.Cookie(auth.OIDCSessionCookieName)
	if err != nil || browserSessionID == "" {
		return nil, errors.New("not authenticated")
	}
	_, session, err := auth.ResolveBrowserSession(p.redis, p.sessionMgr, browserSessionID)
	if err != nil || session == nil {
		p.clearBrowserSession(c)
		return nil, errors.New("invalid browser session")
	}
	user, err := p.accountAuth.GetUserByID(session.UserID)
	if err != nil {
		p.clearBrowserSession(c)
		return nil, errors.New("invalid browser session")
	}
	if err := auth.EnsureUserCanAuthenticate(user); err != nil {
		p.clearBrowserSession(c)
		return nil, err
	}

	maxAge := int(time.Until(session.ExpiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(auth.OIDCSessionCookieName, browserSessionID, maxAge, "/", "", p.browserSessionCookieSecure(c), true)
	return user, nil
}

func (p *Provider) validAuthorizeRequest(c *gin.Context) (config.OIDCClientConfig, string, bool) {
	clientID := strings.TrimSpace(c.Query("client_id"))
	redirectURI := strings.TrimSpace(c.Query("redirect_uri"))
	responseType := strings.TrimSpace(c.Query("response_type"))
	requestedScopes := strings.Fields(c.Query("scope"))
	codeChallenge := strings.TrimSpace(c.Query("code_challenge"))
	method := strings.TrimSpace(c.DefaultQuery("code_challenge_method", "S256"))

	client, ok := p.findClient(clientID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return config.OIDCClientConfig{}, "", false
	}
	if redirectURI == "" || !containsString(client.RedirectURIs, redirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid redirect_uri"})
		return config.OIDCClientConfig{}, "", false
	}
	if responseType != "code" {
		p.redirectAuthorizeError(c, redirectURI, "unsupported_response_type", c.Query("state"))
		return config.OIDCClientConfig{}, "", false
	}
	if len(requestedScopes) == 0 || !containsString(requestedScopes, "openid") {
		p.redirectAuthorizeError(c, redirectURI, "invalid_scope", c.Query("state"))
		return config.OIDCClientConfig{}, "", false
	}

	allowedScopes := p.allowedScopes(client)
	for _, scope := range requestedScopes {
		if !containsString(allowedScopes, scope) {
			p.redirectAuthorizeError(c, redirectURI, "invalid_scope", c.Query("state"))
			return config.OIDCClientConfig{}, "", false
		}
	}

	if codeChallenge != "" && method != "S256" {
		p.redirectAuthorizeError(c, redirectURI, "invalid_request", c.Query("state"))
		return config.OIDCClientConfig{}, "", false
	}
	if client.Public || client.RequirePKCE {
		if codeChallenge == "" || method != "S256" {
			p.redirectAuthorizeError(c, redirectURI, "invalid_request", c.Query("state"))
			return config.OIDCClientConfig{}, "", false
		}
	}

	return client, redirectURI, true
}

func (p *Provider) authenticateClient(c *gin.Context) (config.OIDCClientConfig, bool) {
	clientID, clientSecret, hasBasic := c.Request.BasicAuth()
	if !hasBasic {
		clientID = strings.TrimSpace(c.PostForm("client_id"))
		clientSecret = c.PostForm("client_secret")
	}
	if clientID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return config.OIDCClientConfig{}, false
	}

	client, ok := p.findClient(clientID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return config.OIDCClientConfig{}, false
	}
	if client.Public {
		if clientSecret != "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return config.OIDCClientConfig{}, false
		}
		return client, true
	}
	if !matchSecret(client.ClientSecret, clientSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return config.OIDCClientConfig{}, false
	}
	return client, true
}

func (p *Provider) redirectAuthorizeError(c *gin.Context, redirectURI, errCode, state string) {
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": errCode})
		return
	}
	values := url.Values{}
	values.Set("error", errCode)
	if state != "" {
		values.Set("state", state)
	}
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	c.Redirect(http.StatusFound, redirectURI+sep+values.Encode())
}

func (p *Provider) issuer(c *gin.Context) string {
	if p.cfg.Issuer != "" {
		return strings.TrimRight(p.cfg.Issuer, "/")
	}
	scheme := "https"
	if c.Request.TLS == nil {
		scheme = "http"
	}
	if forwarded := c.GetHeader("X-Forwarded-Proto"); forwarded != "" {
		scheme = forwarded
	}
	return scheme + "://" + c.Request.Host
}

func (p *Provider) currentRequestURL(c *gin.Context) string {
	return p.issuer(c) + c.Request.URL.RequestURI()
}

func (p *Provider) browserSessionCookieSecure(c *gin.Context) bool {
	return common.IsSecureRequest(c.Request, p.cfg.Issuer)
}

func (p *Provider) clearBrowserSession(c *gin.Context) {
	if browserSessionID, err := c.Cookie(auth.OIDCSessionCookieName); err == nil && browserSessionID != "" {
		_ = auth.DeleteBrowserSession(p.redis, browserSessionID)
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(auth.OIDCSessionCookieName, "", -1, "/", "", p.browserSessionCookieSecure(c), true)
}

func (p *Provider) findClient(clientID string) (config.OIDCClientConfig, bool) {
	for _, client := range p.cfg.Clients {
		if client.ClientID == clientID {
			return client, true
		}
	}
	return config.OIDCClientConfig{}, false
}

func (p *Provider) validPostLogoutRedirect(clientID string, redirectURI string) bool {
	if redirectURI == "" {
		return true
	}
	if clientID == "" {
		return false
	}
	client, ok := p.findClient(clientID)
	if !ok {
		return false
	}
	return containsString(client.RedirectURIs, redirectURI)
}

func (p *Provider) allowedScopes(client config.OIDCClientConfig) []string {
	if len(client.Scopes) == 0 {
		return append([]string(nil), defaultScopes...)
	}
	return client.Scopes
}

func (p *Provider) lookupEmail(userID string) (string, bool) {
	if p.db == nil {
		return "", false
	}

	var emailUser auth.EmailUser
	if err := p.db.Where("user_id = ?", userID).First(&emailUser).Error; err == nil && emailUser.Email != "" {
		return emailUser.Email, true
	}

	var googleUser auth.GoogleUser
	if err := p.db.Where("user_id = ?", userID).First(&googleUser).Error; err == nil && googleUser.Email != "" {
		return googleUser.Email, googleUser.VerifiedEmail
	}

	return "", false
}

func (p *Provider) lookupOrganizationClaims(userID string) organizationClaims {
	if p.db == nil || userID == "" || !p.db.Migrator().HasTable(&iam.OrganizationMembership{}) {
		return organizationClaims{}
	}

	var membership iam.OrganizationMembership
	err := p.db.
		Where("user_id = ? AND status = ?", userID, iam.MembershipStatusActive).
		Order("created_at ASC").
		First(&membership).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return organizationClaims{}
		}
		return organizationClaims{}
	}

	claims := organizationClaims{
		OrgID:    membership.OrganizationID,
		OrgRoles: parseOrganizationRoles(membership.RolesJSON),
	}

	if p.db.Migrator().HasTable(&iam.Organization{}) {
		var org iam.Organization
		if err := p.db.First(&org, "organization_id = ?", membership.OrganizationID).Error; err == nil {
			claims.OrgSlug = org.Slug
		}
	}

	return claims
}

func parseOrganizationRoles(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	var roles []string
	if err := json.Unmarshal([]byte(raw), &roles); err != nil {
		return nil
	}
	filtered := roles[:0]
	for _, role := range roles {
		role = strings.TrimSpace(role)
		if role != "" {
			filtered = append(filtered, role)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func (p *Provider) codeTTL() time.Duration {
	if p.cfg.CodeTTLSeconds > 0 {
		return time.Duration(p.cfg.CodeTTLSeconds) * time.Second
	}
	return defaultCodeTTL
}

func (p *Provider) accessTokenTTL() time.Duration {
	if p.cfg.AccessTokenTTLSeconds > 0 {
		return time.Duration(p.cfg.AccessTokenTTLSeconds) * time.Second
	}
	return defaultAccessTokenTTL
}

func (p *Provider) idTokenTTL() time.Duration {
	if p.cfg.IDTokenTTLSeconds > 0 {
		return time.Duration(p.cfg.IDTokenTTLSeconds) * time.Second
	}
	return defaultIDTokenTTL
}

func newTokenSigner(cfg config.OIDCConfig) (*tokenSigner, error) {
	keyPEM := strings.TrimSpace(cfg.PrivateKeyPEM)
	if keyPEM == "" && cfg.PrivateKeyFile != "" {
		content, err := os.ReadFile(cfg.PrivateKeyFile)
		if err != nil {
			return nil, err
		}
		keyPEM = string(content)
	}
	if keyPEM == "" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		return &tokenSigner{privateKey: key, publicKey: &key.PublicKey, keyID: defaultString(cfg.KeyID, "mkauth-dev")}, nil
	}

	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode oidc private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		pkcs1Key, pkcs1Err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if pkcs1Err != nil {
			return nil, err
		}
		return &tokenSigner{privateKey: pkcs1Key, publicKey: &pkcs1Key.PublicKey, keyID: defaultString(cfg.KeyID, "mkauth")}, nil
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("oidc private key must be RSA")
	}
	return &tokenSigner{privateKey: rsaKey, publicKey: &rsaKey.PublicKey, keyID: defaultString(cfg.KeyID, "mkauth")}, nil
}

func (s *tokenSigner) sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID
	return token.SignedString(s.privateKey)
}

func verifyPKCE(verifier, challenge, method string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	if method == "" {
		method = "S256"
	}
	if method != "S256" {
		return false
	}
	hash := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func matchSecret(expected, actual string) bool {
	if expected == "" {
		return actual == ""
	}
	if strings.HasPrefix(expected, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(expected), []byte(actual)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func bearerToken(header string) string {
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	}
	return ""
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func randomToken(length int) string {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)[:length]
}
