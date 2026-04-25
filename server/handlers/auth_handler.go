/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package handlers

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"minki.cc/mkauth/server/admin"
	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/auth/storage"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
	"minki.cc/mkauth/server/middleware"
	"minki.cc/mkauth/server/oidc"
	"minki.cc/mkauth/server/plugins"
)

// AuthHandler Authentication handler
type AuthHandler struct {
	useAccountAuth  bool
	accountAuth     *auth.AccountAuth
	emailAuth       *auth.EmailAuth
	googleOAuth     *auth.GoogleOAuth
	weixinLogin     *auth.WeixinLogin
	weixinMiniLogin *auth.WeixinMiniLogin
	phoneAuth       *auth.PhoneAuth
	sessionMgr      *auth.SessionManager
	redisStore      *auth.RedisStore
	storage         *storage.StorageClient
	avatarService   *auth.AvatarService
	avatarHandler   *AvatarHandler
	oidcProvider    *oidc.Provider
	enterpriseOIDC  *iam.EnterpriseOIDCManager
	enterpriseSAML  *iam.EnterpriseSAMLManager
	enterpriseLDAP  *iam.EnterpriseLDAPManager
	hookRegistry    *iam.HookRegistry
	pluginRegistry  *plugins.Registry
	adminAccess     *admin.AccessController
	adminEntryURL   string
	config          *config.Config
	logger          *log.Logger
}

func (h *AuthHandler) publicBaseURL() string {
	if h == nil || h.config == nil {
		return ""
	}
	return h.config.OIDC.Issuer
}

func (h *AuthHandler) SetAdminAccess(accessController *admin.AccessController, entryURL string) {
	if h == nil {
		return
	}
	h.adminAccess = accessController
	h.adminEntryURL = entryURL
}

// NewAuthHandler Create new authentication handler
func NewAuthHandler(
	useAccountAuth bool,
	accountAuth *auth.AccountAuth,
	emailAuth *auth.EmailAuth,
	googleOAuth *auth.GoogleOAuth,
	weixinLogin *auth.WeixinLogin,
	weixinMiniLogin *auth.WeixinMiniLogin,
	phoneAuth *auth.PhoneAuth,
	sessionMgr *auth.SessionManager,
	redisStore *auth.RedisStore,
	storage *storage.StorageClient,
	avatarService *auth.AvatarService,
	oidcProvider *oidc.Provider,
	enterpriseOIDC *iam.EnterpriseOIDCManager,
	enterpriseSAML *iam.EnterpriseSAMLManager,
	enterpriseLDAP *iam.EnterpriseLDAPManager,
	hookRegistry *iam.HookRegistry,
	pluginRegistry *plugins.Registry,
	config *config.Config) *AuthHandler {
	return &AuthHandler{
		useAccountAuth:  useAccountAuth,
		accountAuth:     accountAuth,
		emailAuth:       emailAuth,
		googleOAuth:     googleOAuth,
		weixinLogin:     weixinLogin,
		weixinMiniLogin: weixinMiniLogin,
		phoneAuth:       phoneAuth,
		sessionMgr:      sessionMgr,
		redisStore:      redisStore,
		storage:         storage,
		avatarService:   avatarService,
		avatarHandler:   NewAvatarHandler(accountAuth, avatarService),
		oidcProvider:    oidcProvider,
		enterpriseOIDC:  enterpriseOIDC,
		enterpriseSAML:  enterpriseSAML,
		enterpriseLDAP:  enterpriseLDAP,
		hookRegistry:    hookRegistry,
		pluginRegistry:  pluginRegistry,
		config:          config,
		logger:          log.New(os.Stdout, "[AUTH] ", log.LstdFlags|log.Lshortfile),
	}
}

// RegisterRoutes Register routes
func (h *AuthHandler) RegisterRoutes(authGroup *gin.RouterGroup, cfg *config.Config) {
	// Get supported login methods
	authGroup.GET("/providers", h.GetSupportedProviders)
	authGroup.GET("/plugins", h.GetPlugins)

	rejectCrossOriginSessionCreation := h.RejectCrossOriginBrowserSessionCreation()

	// Account login related routes
	if h.useAccountAuth {
		authGroup.POST("/account/register", rejectCrossOriginSessionCreation, h.Register)
		authGroup.POST("/account/login", rejectCrossOriginSessionCreation, h.Login)
		authGroup.POST("/account/password/reset", h.AuthRequired(), h.RequireSameOriginForBrowserSession(), h.ResetPassword)
	}
	authGroup.POST("/logout", h.AuthRequired(), h.RequireSameOriginForBrowserSession(), h.Logout)
	authGroup.GET("/browser-session", h.GetBrowserSession)

	trustedClient := middleware.TrustedClient(cfg)

	// Email login related routes
	if h.emailAuth != nil {
		authGroup.POST("/email/login", rejectCrossOriginSessionCreation, h.EmailLogin)
		authGroup.POST("/email/register", h.EmailRegister)
		authGroup.GET("/email/verify", h.EmailVerify)
		authGroup.POST("/email/resend-verification", h.ResendEmailVerification)
		authGroup.POST("/email/password/reset", h.EmailPasswordReset)
		authGroup.POST("/email/password/reset/complete", h.CompleteEmailPasswordReset)
	}

	// Google OAuth related routes
	if h.googleOAuth != nil {
		// Get Google client ID, for frontend to use
		authGroup.GET("/google/client_id", h.GetGoogleClientID)
		authGroup.POST("/google/callback", rejectCrossOriginSessionCreation, h.GoogleCredential)
	}

	// WeChat login related routes
	if h.weixinLogin != nil {
		authGroup.GET("/weixin/url", h.WeixinLoginURL)
		// authGroup.GET("/weixin/login", h.WeixinLoginHandler)
		authGroup.GET("/weixin/callback", h.WeixinCallback)
	}

	if h.weixinMiniLogin != nil {
		authGroup.GET("/weixin/miniprogram", h.WeixinMiniLogin)
	}

	if h.enterpriseOIDC != nil || h.enterpriseSAML != nil || h.enterpriseLDAP != nil {
		authGroup.GET("/enterprise/discover", h.DiscoverEnterpriseProviders)
		authGroup.GET("/enterprise/providers", h.GetEnterpriseProviders)
		authGroup.GET("/enterprise/oidc/discover", h.DiscoverEnterpriseOIDC)
		authGroup.GET("/enterprise/oidc/providers", h.GetEnterpriseOIDCProviders)
		authGroup.GET("/enterprise/oidc/:slug/login", h.EnterpriseOIDCLogin)
		authGroup.GET("/enterprise/oidc/:slug/callback", h.EnterpriseOIDCCallback)
		authGroup.GET("/enterprise/saml/:slug/login", h.EnterpriseSAMLLogin)
		authGroup.GET("/enterprise/saml/:slug/metadata", h.EnterpriseSAMLMetadata)
		authGroup.POST("/enterprise/saml/:slug/acs", h.EnterpriseSAMLACS)
		authGroup.GET("/enterprise/saml/:slug/acs", h.EnterpriseSAMLACS)
		authGroup.POST("/enterprise/ldap/:slug/login", rejectCrossOriginSessionCreation, h.EnterpriseLDAPLogin)
	}

	// Phone login related routes
	if h.phoneAuth != nil {
		// Phone pre-registration - send verification code
		authGroup.POST("/phone/preregister", h.PhonePreregister)
		// Verify phone number and complete registration
		authGroup.POST("/phone/verify-register", rejectCrossOriginSessionCreation, h.VerifyPhoneAndRegister)
		// Resend verification code
		authGroup.POST("/phone/resend-verification", h.ResendPhoneVerification)
		// Login with phone number + password
		authGroup.POST("/phone/login", rejectCrossOriginSessionCreation, h.PhoneLogin)
		// Send login verification code
		authGroup.POST("/phone/send-login-code", h.SendLoginSMS)
		// Login with phone number + verification code
		authGroup.POST("/phone/code-login", rejectCrossOriginSessionCreation, h.PhoneCodeLogin)
		// Initiate password reset - send verification code
		authGroup.POST("/phone/reset-password/init", h.PhoneInitiatePasswordReset)
		// Complete password reset
		authGroup.POST("/phone/reset-password/complete", h.PhoneCompletePasswordReset)
	}

	// User information related routes
	authGroup.GET("/user", h.AuthRequired(), h.GetUserInfo)
	authGroup.GET("/user/admin-access", h.AuthRequired(), h.GetCurrentUserAdminAccess)
	authGroup.GET("/user/organizations", h.AuthRequired(), h.GetCurrentUserOrganizations)
	authGroup.GET("/user/organization/authorization", h.AuthRequired(), h.GetCurrentOrganizationAuthorization)
	authGroup.GET("/user/:id", h.AuthRequired(), trustedClient, h.GetUserInfoById)
	authGroup.POST("/users", h.AuthRequired(), trustedClient, h.GetUsersInfo)
	authGroup.PUT("/user", h.AuthRequired(), h.RequireSameOriginForBrowserSession(), h.UpdateUserInfo)

	// Avatar related routes
	authGroup.POST("/avatar/upload", h.AuthRequired(), h.RequireSameOriginForBrowserSession(), h.avatarHandler.UploadAvatar)
	authGroup.DELETE("/avatar", h.AuthRequired(), h.RequireSameOriginForBrowserSession(), h.avatarHandler.DeleteAvatar)

	// User session information
	authGroup.GET("/sessions", h.AuthRequired(), h.GetUserSessions)
	authGroup.DELETE("/sessions/:session_id", h.AuthRequired(), h.RequireSameOriginForBrowserSession(), h.TerminateUserSession)
	authGroup.DELETE("/sessions", h.AuthRequired(), h.RequireSameOriginForBrowserSession(), h.TerminateAllUserSessions)
}

// GetSupportedProviders Get supported login methods
func (h *AuthHandler) GetSupportedProviders(c *gin.Context) {
	providers := []string{}

	// Add account login method
	if h.useAccountAuth {
		providers = append(providers, "account")
	}

	// Add email login method
	if h.emailAuth != nil {
		providers = append(providers, "email")
	}

	// Add Google login method
	if h.googleOAuth != nil {
		providers = append(providers, "google")
	}

	// Add WeChat login method
	if h.weixinLogin != nil {
		providers = append(providers, "weixin")
	}

	// Add WeChat Mini Program login method
	if h.weixinMiniLogin != nil {
		providers = append(providers, "weixin_mini")
	}

	if (h.enterpriseOIDC != nil && h.enterpriseOIDC.HasProviders()) ||
		(h.enterpriseSAML != nil && h.enterpriseSAML.HasProviders()) ||
		(h.enterpriseLDAP != nil && h.enterpriseLDAP.HasProviders()) {
		providers = append(providers, "enterprise_oidc")
	}

	// Add phone login method
	if h.phoneAuth != nil {
		providers = append(providers, "phone")
	}

	c.JSON(200, gin.H{
		"providers": providers,
	})
}

func (h *AuthHandler) GetPlugins(c *gin.Context) {
	if h.pluginRegistry == nil {
		c.JSON(200, gin.H{"plugins": []plugins.Summary{}})
		return
	}
	c.JSON(200, gin.H{"plugins": plugins.PublicSummaries(h.pluginRegistry.List())})
}
