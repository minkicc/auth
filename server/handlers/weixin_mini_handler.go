/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"minki.cc/mkauth/server/auth"
)

// WeixinMiniLogin 处理微信小程序登录
func (h *AuthHandler) WeixinMiniLogin(c *gin.Context) {
	if h.weixinMiniLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "WeChat mini program login is not enabled"})
		return
	}

	// 获取前端传来的 code
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing code parameter"})
		return
	}

	// 调用微信小程序登录服务
	user, _, err := h.weixinMiniLogin.MiniProgramLogin(code)
	if err != nil {
		h.logger.Printf("WeChat mini program login failed: %v", err)
		if appErr, ok := err.(*auth.AppError); ok {
			c.JSON(appErr.GetHTTPStatus(), gin.H{"error": appErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "WeChat mini program login failed"})
		return
	}

	h.completeBrowserLogin(c, user, "")
}
