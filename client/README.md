# KCAuth 客户端

这个包提供了与KCAuth认证服务交互的Go客户端，用于在业务服务中验证JWT令牌、查询用户信息和处理登录态回调。

## 功能特性

- JWT客户端：与认证服务通信，处理登录、刷新令牌和登出等操作
- JWT中间件：用于验证请求中的JWT令牌
- 令牌刷新：自动刷新过期的令牌
- 令牌缓存：减少对认证服务的请求
- 可选认证：支持公开资源的差异化访问

## 安装

```bash
go get minki.cc/kcauth/client
```

## 使用方法

### 创建客户端

```go
client := auth.NewAuthClient("http://auth-service:8080", "your-client-id", "your-client-secret")
```

`NewAuthClient` 接收认证服务的基地址，内部会自动规范化到 `/api`。例如 `http://auth-service:8080`、`http://auth-service:8080/api` 和旧写法 `http://auth-service:8080/auth/token/validate` 都会被统一处理。

如果你在本地调试自签名证书，可以显式开启：

```go
client.UseInsecureTLS()
```

### 在 Gin 中使用中间件

```go
client := auth.NewAuthClient("http://auth-service:8080", "", "")

r := gin.Default()

r.GET("/", func(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
        "message": "欢迎访问API",
    })
})

protected := r.Group("/api")
protected.Use(client.AuthRequired())
{
    protected.GET("/profile", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "message": "这是受保护的资源",
        })
    })
}

optional := r.Group("/public")
optional.Use(client.OptionalAuth())
{
    optional.GET("/data", func(c *gin.Context) {
        authenticated, exists := c.Get("authenticated")
        if exists && authenticated.(bool) {
            c.JSON(http.StatusOK, gin.H{
                "message": "您已认证，这是完整数据",
                "data": []string{"item1", "item2", "item3", "item4", "item5"},
            })
        } else {
            c.JSON(http.StatusOK, gin.H{
                "message": "您未认证，这是有限数据",
                "data": []string{"item1", "item2"},
            })
        }
    })
}
```

### 在业务代码中使用客户端

```go
client := auth.NewAuthClient("http://auth-service:8080", "your-client-id", "your-client-secret")

user, err := client.GetUserInfo(accessToken)
if err != nil {
    log.Fatalf("获取用户信息失败: %v", err)
}

users, err := client.GetUsersInfo(accessToken, []string{user.UserID})
if err != nil {
    log.Fatalf("批量查询用户失败: %v", err)
}

err = client.Logout(accessToken)
if err != nil {
    log.Fatalf("登出失败: %v", err)
}

_ = users
```

## 配置选项

- `AuthServerURL`：认证服务的URL
- `Timeout`：HTTP请求超时时间
- `cacheExpiry`：令牌缓存过期时间

## 注意事项

- 确保认证服务的 `/api` 路由可用，用于验证令牌和查询用户信息
- 在生产环境中，应使用HTTPS进行通信
- `UseInsecureTLS()` 只建议用于本地开发或测试环境，不要在生产环境启用
- 对 `GetUserInfoById`、`GetUsersInfo`、`LoginVerify` 等接口，需要为客户端配置 `X-Client-ID` 和 `X-Client-Secret`
