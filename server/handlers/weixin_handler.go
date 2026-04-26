/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/common"
	"minki.cc/mkauth/server/iam"
)

// WeixinLoginURL Get WeChat login URL
func (h *AuthHandler) WeixinLoginURL(c *gin.Context) {
	if h.weixinLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "WeChat login is not enabled"})
		return
	}

	// Generate random state
	state := uuid.New().String()

	// Generate an unpredictable state session identifier for callback validation
	clientID := uuid.New().String()
	stateKey := fmt.Sprintf("%s%s", common.RedisKeyWeixinState, clientID)

	// Store state in Redis with a reasonable expiration time (e.g., 15 minutes)
	if err := h.redisStore.Set(stateKey, state, time.Minute*15); err != nil {
		h.logger.Printf("Failed to save OAuth state to Redis: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Set cookie to store client identifier for subsequent callback
	setLaxCookie(c, "weixin_client_id", clientID, int(time.Minute*15/time.Second), "/", "", h.browserSessionCookieSecure(c), true)

	// Get login URL
	authURL := h.weixinLogin.GetAuthURL(state)

	// Return URL
	c.JSON(http.StatusOK, gin.H{
		"url": authURL,
	})
}

// WeixinLoginHandler Handle WeChat login
func (h *AuthHandler) WeixinLoginHandler(c *gin.Context) {
	if h.weixinLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "WeChat login is not enabled"})
		return
	}

	// Generate random state
	state := uuid.New().String()

	// Generate an unpredictable state session identifier for callback validation
	clientID := uuid.New().String()
	stateKey := fmt.Sprintf("%s%s", common.RedisKeyWeixinState, clientID)

	// Store state in Redis with a reasonable expiration time (e.g., 15 minutes)
	if err := h.redisStore.Set(stateKey, state, time.Minute*15); err != nil {
		h.logger.Printf("Failed to save OAuth state to Redis: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Set cookie to store client identifier for subsequent callback
	setLaxCookie(c, "weixin_client_id", clientID, int(time.Minute*15/time.Second), "/", "", h.browserSessionCookieSecure(c), true)

	// Redirect to WeChat login page
	c.Redirect(http.StatusTemporaryRedirect, h.weixinLogin.GetAuthURL(state))
}

// WeixinCallback Handle WeChat callback
func (h *AuthHandler) WeixinCallback(c *gin.Context) {
	if h.weixinLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "WeChat login is not enabled"})
		return
	}

	// Verify state
	actualState := c.Query("state")
	if actualState == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state parameter"})
		return
	}

	// Get client identifier from cookie
	clientID, err := c.Cookie("weixin_client_id")
	if err != nil {
		h.logger.Printf("Failed to get weixin_client_id cookie: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request, please login again"})
		return
	}

	// Get expected state from Redis
	stateKey := fmt.Sprintf("%s%s", common.RedisKeyWeixinState, clientID)
	var expectedState string
	if err := h.redisStore.Get(stateKey, &expectedState); err != nil {
		h.logger.Printf("Failed to get OAuth state from Redis: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session expired, please login again"})
		return
	}

	// Verify state value
	if expectedState != actualState {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state parameter"})
		return
	}

	// Clear state from Redis and cookie
	if err := h.redisStore.Delete(stateKey); err != nil {
		h.logger.Printf("Failed to clear OAuth state from Redis: %v", err)
		// Don't interrupt the flow, continue processing
	}
	setLaxCookie(c, "weixin_client_id", "", -1, "/", "", h.browserSessionCookieSecure(c), true)

	// Handle callback
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization code not provided"})
		return
	}

	if err := h.runHook(c, iam.HookPreAuthenticate, nil, "weixin", nil, map[string]string{
		"login_method": "oauth_code",
	}); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	// Use WeChat login service to directly handle login or registration
	user, created, err := h.weixinLogin.RegisterOrLoginWithWeixin(code)
	if err != nil {
		h.logger.Printf("WeChat login processing failed: %v", err)
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "WeChat login processing failed"})
		return
	}
	if created {
		if err := h.runHook(c, iam.HookPostRegister, user, "weixin", nil, nil); err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
	}

	h.completeBrowserLoginWithProvider(c, user, "", "weixin")
}
