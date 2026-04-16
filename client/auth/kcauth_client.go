/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package auth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var errOIDCValidationRequired = errors.New("legacy /api/token/validate validation was removed on the OIDC-first branch; validate tokens with OIDC discovery and JWKS instead")

// KCAuthClient JWT客户端
type KCAuthClient struct {
	APIAddr      string           // 认证服务URL
	HTTPClient   *http.Client     // HTTP客户端
	Timeout      time.Duration    // 请求超时时间
	tokenCache   map[string]int64 // 令牌缓存，用于减少对认证服务的请求
	cacheMutex   sync.RWMutex     // 缓存锁
	cacheExpiry  time.Duration    // 缓存过期时间
	ClientID     string           // 客户端ID
	ClientSecret string           // 客户端密钥
}

// 需要与服务端定义的 Claims 结构一致
// Define JWT Claims structure
type CustomClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// UserInfo 用户信息结构
type UserInfo struct {
	UserID   string `json:"user_id" gorm:"primarykey"` // Login identifier, for normal accounts this is the login account, for email accounts it's automatically generated
	Nickname string `json:"nickname" gorm:"size:50"`   // Nickname
	Avatar   string `json:"avatar" gorm:"size:255"`    // Avatar URL
}

// LoginVerifyResponse 登录验证响应
type LoginVerifyResponse struct {
	UserID     string        `json:"user_id"`
	Token      string        `json:"token"`
	Nickname   string        `json:"nickname"`
	Avatar     string        `json:"avatar"`
	ExpireTime time.Duration `json:"expire_time"`
}

const defaultAPIPath = "/api"

func normalizeAPIAddr(apiAddr string) string {
	trimmed := strings.TrimSpace(apiAddr)
	trimmed = strings.TrimRight(trimmed, "/")
	if trimmed == "" {
		return defaultAPIPath
	}

	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" {
		if strings.HasSuffix(trimmed, defaultAPIPath) {
			return trimmed
		}
		return trimmed + defaultAPIPath
	}

	path := strings.Trim(parsed.Path, "/")
	switch {
	case path == "":
		parsed.Path = defaultAPIPath
	case path == "api" || strings.HasPrefix(path, "api/"):
		parsed.Path = defaultAPIPath
	case path == "auth" || strings.HasPrefix(path, "auth/"):
		parsed.Path = defaultAPIPath
	default:
		parsed.Path = strings.TrimRight(parsed.Path, "/")
		if !strings.HasSuffix(parsed.Path, defaultAPIPath) {
			parsed.Path += defaultAPIPath
		}
	}

	return strings.TrimRight(parsed.String(), "/")
}

// NewAuthClient 创建新的JWT客户端
func NewAuthClient(apiAddr string, clientID string, clientSecret string) *KCAuthClient {
	return &KCAuthClient{
		APIAddr: normalizeAPIAddr(apiAddr),
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		Timeout:      10 * time.Second,
		tokenCache:   make(map[string]int64),
		cacheExpiry:  15 * time.Minute, // 默认缓存15分钟
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
}

// UseInsecureTLS 仅用于本地开发或自签名证书调试场景
func (c *KCAuthClient) UseInsecureTLS() {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: c.Timeout}
	}

	c.HTTPClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}

func getJWTClaims(accessToken string) (*CustomClaims, error) {
	token, _ := jwt.ParseWithClaims(accessToken, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	})

	if claims, ok := token.Claims.(*CustomClaims); ok {
		now := time.Now()
		if claims.ExpiresAt.Time.After(now) {
			return claims, nil
		}
		return nil, errors.New("token expired")
	}

	return nil, errors.New("invalid token claims")
}

// remoteValidateToken 旧 JWT 远程验证接口在 OIDC-first 分支已移除
func (c *KCAuthClient) remoteValidateToken(accessToken string) (bool, error) {
	_ = accessToken
	return false, errOIDCValidationRequired
}

// AuthRequired 验证JWT令牌的中间件
func (c *KCAuthClient) AuthRequired() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// 从请求头获取令牌
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "未提供授权令牌"})
			ctx.Abort()
			return
		}

		// 检查令牌格式
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "授权格式无效"})
			ctx.Abort()
			return
		}

		tokenString := parts[1]

		claims, err := c.ValidateToken(tokenString)
		if err != nil {
			ctx.JSON(http.StatusNotImplemented, gin.H{"error": err.Error()})
			ctx.Abort()
			return
		}
		ctx.Set("user_id", claims.UserID)
		ctx.Set("authenticated", true)
		ctx.Set("access_token", tokenString)
		ctx.Next()
	}
}

// 验证令牌
func (c *KCAuthClient) ValidateToken(tokenString string) (*CustomClaims, error) {
	_ = tokenString
	return nil, errOIDCValidationRequired
}

// OptionalAuth 可选的JWT验证中间件
func (c *KCAuthClient) OptionalAuth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			ctx.Next()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			ctx.Next()
			return
		}

		tokenString := parts[1]

		claims, err := c.ValidateToken(tokenString)
		if err != nil {
			ctx.JSON(http.StatusNotImplemented, gin.H{"error": err.Error()})
			ctx.Abort()
			return
		}
		ctx.Set("user_id", claims.UserID)
		ctx.Set("authenticated", true)
		ctx.Set("access_token", tokenString)
		ctx.Next()
	}
}

// getTokenCached 检查令牌是否在缓存中
func (c *KCAuthClient) _getTokenCached(token string) (string, error) {
	var expiry int64

	c.cacheMutex.RLock()

	var exists bool
	expiry, exists = c.tokenCache[token]
	c.cacheMutex.RUnlock()

	if !exists {
		return "", errors.New("token not cached")
	}

	// 检查缓存是否过期
	now := time.Now().Unix()
	if now <= expiry {
		return token, nil
	}

	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	//重新检查expiry
	expiry, exists = c.tokenCache[token]
	if !exists {
		return "", errors.New("token not cached")
	}

	if now <= expiry {
		return token, nil
	}

	delete(c.tokenCache, token)
	return "", errors.New("token cache expired")

}

// getTokenCached 检查令牌是否在缓存中
func (c *KCAuthClient) getTokenCached(token string) (*CustomClaims, error) {
	token, err := c._getTokenCached(token)
	if err != nil {
		return nil, err
	}

	return getJWTClaims(token)
}

// cacheToken 缓存令牌
func (c *KCAuthClient) cacheToken(token string) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	// 设置缓存过期时间
	expiry := time.Now().Add(c.cacheExpiry).Unix()
	c.tokenCache[token] = expiry
}

// func (c *JWTClient) refreshCacheToken(old string, newtoken string) {
// 	c.cacheMutex.Lock()
// 	defer c.cacheMutex.Unlock()

// 	delete(c.tokenCache, old)
// 	// 设置缓存过期时间
// 	expiry := time.Now().Add(c.cacheExpiry).Unix()
// 	c.tokenCache[newtoken] = expiry
// }

func (c *KCAuthClient) getUserInfo(accessToken string, url string) (*UserInfo, error) {
	// 创建请求
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println("创建请求失败", err)
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("X-Client-ID", c.ClientID)
	req.Header.Set("X-Client-Secret", c.ClientSecret)

	// 发送请求
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("读取响应数据失败: %v", err)
			}
			log.Printf("响应数据: %s", string(bodyBytes))
			return nil, errors.New("未授权")
		}
		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("获取用户信息失败: %d", resp.StatusCode)
		}
		return nil, errors.New(errResp.Error)
	}

	// 解析响应
	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("解析用户信息失败: %v", err)
	}

	return &userInfo, nil
}

// GetUserInfo 获取用户信息
func (c *KCAuthClient) GetUserInfo(accessToken string) (*UserInfo, error) {
	return c.getUserInfo(accessToken, c.APIAddr+"/user")
}

// GetUserInfo 获取用户信息
func (c *KCAuthClient) GetUserInfoById(accessToken string, userId string) (*UserInfo, error) {
	return c.getUserInfo(accessToken, fmt.Sprintf("%s/user/%s", c.APIAddr, userId))
}

// UpdateUserInfo 更新用户信息
func (c *KCAuthClient) UpdateUserInfo(accessToken string, userInfo *UserInfo) error {
	// 将用户信息转换为 JSON
	jsonData, err := json.Marshal(userInfo)
	if err != nil {
		return fmt.Errorf("序列化用户信息失败: %v", err)
	}

	// 创建请求
	req, err := http.NewRequest("PUT", c.APIAddr+"/user", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Println("创建请求失败", err)
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return errors.New("invalid token")
		}
		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return fmt.Errorf("更新用户信息失败: %d", resp.StatusCode)
		}
		return errors.New(errResp.Error)
	}

	return nil
}

// UpdateAvatar 更新用户头像
func (c *KCAuthClient) UpdateAvatar(accessToken string, fileData []byte, fileName string) (string, error) {
	// 创建multipart请求
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// 添加文件
	part, err := writer.CreateFormFile("avatar", fileName)
	if err != nil {
		return "", fmt.Errorf("创建表单文件失败: %v", err)
	}
	if _, err := part.Write(fileData); err != nil {
		return "", fmt.Errorf("写入文件数据失败: %v", err)
	}

	// 关闭writer
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("关闭writer失败: %v", err)
	}

	// 创建请求
	req, err := http.NewRequest("POST", c.APIAddr+"/avatar/upload", body)
	if err != nil {
		log.Println("创建请求失败", err)
		return "", fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置请求头
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// 发送请求
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return "", fmt.Errorf("更新头像失败: %d", resp.StatusCode)
		}
		return "", errors.New(errResp.Error)
	}

	// 解析响应
	var result struct {
		Url string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("解析响应失败: %v", err)
	}
	return result.Url, nil
}

// DeleteAvatar 删除用户头像
func (c *KCAuthClient) DeleteAvatar(accessToken string) error {
	// 创建请求
	req, err := http.NewRequest("DELETE", c.APIAddr+"/avatar", nil)
	if err != nil {
		log.Println("创建请求失败", err)
		return fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置请求头
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// 发送请求
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return fmt.Errorf("删除头像失败: %d", resp.StatusCode)
		}
		return errors.New(errResp.Error)
	}

	return nil
}

// LoginVerify 旧登录 code 交换接口，OIDC-first 分支已移除服务端对应端点
func (c *KCAuthClient) LoginVerify(code string) (*LoginVerifyResponse, error) {
	_ = code
	return nil, errors.New("LoginVerify is not available on the OIDC-first branch; use the standard OIDC authorization code flow against /oauth2/token")
}

// GetUsersInfo 批量获取用户信息
func (c *KCAuthClient) GetUsersInfo(accessToken string, userIDs []string) ([]UserInfo, error, int) {
	// 创建请求体
	reqBody := struct {
		UserIDs []string `json:"user_ids"`
	}{
		UserIDs: userIDs,
	}

	// 将请求体转换为 JSON
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("序列化请求数据失败: %v", err), http.StatusInternalServerError
	}

	// 创建请求
	req, err := http.NewRequest("POST", c.APIAddr+"/users", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Println("创建请求失败", err)
		return nil, fmt.Errorf("创建请求失败: %v", err), http.StatusInternalServerError
	}

	// 设置请求头
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Client-ID", c.ClientID)
	req.Header.Set("X-Client-Secret", c.ClientSecret)

	// 发送请求
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %v", err), http.StatusInternalServerError
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, errors.New("无效的访问令牌或客户端认证失败"), http.StatusUnauthorized
		}
		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("获取用户信息失败: %d", resp.StatusCode), http.StatusInternalServerError
		}
		return nil, errors.New(errResp.Error), http.StatusInternalServerError
	}

	// 解析响应
	var result struct {
		Users []UserInfo `json:"users"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析响应数据失败: %v", err), http.StatusInternalServerError
	}

	return result.Users, nil, http.StatusInternalServerError
}

// logout
func (c *KCAuthClient) Logout(accessToken string) error {
	// 创建请求
	req, err := http.NewRequest("POST", c.APIAddr+"/logout", nil)
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置请求头
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("X-Client-ID", c.ClientID)
	req.Header.Set("X-Client-Secret", c.ClientSecret)

	// 发送请求
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("退出失败: %d", resp.StatusCode)
	}

	return nil
}

// WeixinMiniLogin 微信小程序登录
func (c *KCAuthClient) WeixinMiniLogin(code string) (*LoginVerifyResponse, error) {
	_ = code
	return nil, errors.New("WeixinMiniLogin is not available on the OIDC-first branch; use the browser OIDC session flow or standard OIDC authorization code flow")
}
