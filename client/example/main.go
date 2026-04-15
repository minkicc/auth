/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"minki.cc/mkauth/client/auth"
)

func main() {
	// 创建客户端，用来调用 MKAuth 管理型 /api 接口
	client := auth.NewAuthClient("http://auth-service:8080", "", "")

	// 创建Gin引擎
	r := gin.Default()

	// 公开路由
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "MKAuth OIDC-first branch example",
		})
	})

	// 在 OIDC-first 分支，资源服务应自行做 OIDC/JWKS 校验。
	// 这里演示的是如何拿 access token 查询 MKAuth 当前用户接口。
	r.GET("/me", func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}

		user, err := client.GetUserInfo(strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer ")))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, user)
	})

	// 启动服务器
	addr := ":8081"
	fmt.Printf("服务器启动在 %s\n", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}
