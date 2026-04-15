# MKAuth Go SDK

`client/` 提供了一个面向 Go 服务的 SDK，用来完成以下事情：
- 校验业务请求里的 MKAuth JWT
- 获取当前登录用户信息
- 按用户 ID 获取用户信息
- 批量拉取用户资料
- 用登录回调 `code` 换取访问令牌
- 刷新访问令牌

## 安装

```bash
go get minki.cc/mkauth/client
```

代码中导入的包路径为：

```go
import "minki.cc/mkauth/client/auth"
```

## 创建客户端

```go
client := auth.NewAuthClient(
    "http://localhost:8080",
    "myapp",
    "your-client-secret",
)
```

说明：
- 第一个参数是 MKAuth 服务地址。
- SDK 会自动把地址规范到 `/api`。
- 如果只是做 JWT 校验，中间两个参数可以留空。
- 如果要做 `LoginVerify`、`GetUserInfoById`、`GetUsersInfo`，需要配置 `client_id` 和 `client_secret`。

## 1. 给业务接口加登录保护

```go
package main

import (
    "net/http"

    "github.com/gin-gonic/gin"
    mkauth "minki.cc/mkauth/client/auth"
)

func main() {
    client := mkauth.NewAuthClient("http://localhost:8080", "", "")

    r := gin.Default()

    protected := r.Group("/api")
    protected.Use(client.AuthRequired())
    {
        protected.GET("/profile", func(c *gin.Context) {
            userID := c.GetString("user_id")
            c.JSON(http.StatusOK, gin.H{"user_id": userID})
        })
    }

    r.Run(":8082")
}
```

`AuthRequired()` 会：
- 从 `Authorization: Bearer <token>` 中提取令牌
- 远程调用 MKAuth 验证令牌有效性
- 把 `user_id` 写入 Gin Context

如果你希望接口支持“登录用户看完整数据、匿名用户看简化数据”，可以用：

```go
public := r.Group("/public")
public.Use(client.OptionalAuth())
```

## 2. 获取当前登录用户信息

```go
user, err := client.GetUserInfo(accessToken)
if err != nil {
    return
}

fmt.Println(user.UserID, user.Nickname, user.Avatar)
```

这个接口适合：
- 业务系统自己的“当前用户信息”接口
- 登录完成后的资料同步

## 3. 按用户 ID 查询用户

```go
client := auth.NewAuthClient("http://localhost:8080", "myapp", "your-client-secret")
user, err := client.GetUserInfoById(accessToken, "user-001")
```

适合后台管理、订单系统、IM 系统等按 ID 取资料的场景。

## 4. 批量查询用户

```go
users, err, statusCode := client.GetUsersInfo(accessToken, []string{"user-001", "user-002"})
if err != nil {
    fmt.Println(statusCode, err)
    return
}

for _, user := range users {
    fmt.Println(user.UserID, user.Nickname)
}
```

使用前请确认：
- MKAuth 已配置 `auth_trusted_clients`
- 对应客户端拥有 `read:users` scope

## 5. 处理登录回调 code

如果你的业务系统使用 MKAuth 内置登录页，那么回调 URL 会拿到一个 `code`。你可以用 SDK 直接换 token：

```go
r.GET("/auth/callback", func(c *gin.Context) {
    code := c.Query("code")
    loginResp, err := client.LoginVerify(code, c)
    if err != nil {
        c.JSON(401, gin.H{"error": err.Error()})
        return
    }

    c.JSON(200, gin.H{
        "user_id": loginResp.UserID,
        "token":   loginResp.Token,
    })
})
```

`LoginVerify()` 会自动：
- 调用 `/api/login/verify`
- 解析返回的 `token`
- 把新的 `refreshToken` Cookie 写回 Gin Response

## 6. 刷新访问令牌

```go
newToken, statusCode, err := client.RefreshToken(refreshToken, c)
if err != nil {
    fmt.Println(statusCode, err)
    return
}

fmt.Println("new access token:", newToken)
```

`RefreshToken()` 会把 MKAuth 返回的新 `refreshToken` Cookie 回写给当前响应。

## 7. 更新昵称或头像

```go
err := client.UpdateUserInfo(accessToken, &auth.UserInfo{
    UserID:   "user-001",
    Nickname: "new-name",
})
```

上传头像：

```go
url, err := client.UpdateAvatar(accessToken, fileBytes, "avatar.png")
```

删除头像：

```go
err := client.DeleteAvatar(accessToken)
```

## HTTPS 调试

如果你的本地环境使用自签名证书，可以临时开启：

```go
client.UseInsecureTLS()
```

不要在生产环境使用。

## 常见注意事项

- `Authorization` 请求头必须是 `Bearer <token>` 格式。
- 如果只做 JWT 校验，不需要配置 `client_id` 和 `client_secret`。
- 如果要调用 `LoginVerify`、`GetUserInfoById`、`GetUsersInfo`，必须配置可信客户端。
- `client_secret` 应与服务端 `auth_trusted_clients` 配置保持一致。
- 生产环境建议始终使用 HTTPS。

## 相关文档

- 根目录接入说明：[README-zh.md](../README-zh.md)
- 英文说明：[README.md](../README.md)
