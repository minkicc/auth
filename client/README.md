# MKAuth Go SDK

`codex/oidc-break` 分支已经切到 OIDC-first，这个 SDK 主要兼容旧的 `/api` JWT 接口，适合作为过渡或管理型接口调用工具，不再是推荐的登录接入方式。

`client/` 提供了一个面向 Go 服务的 SDK，用来完成以下事情：
- 获取当前登录用户信息
- 按用户 ID 获取用户信息
- 批量拉取用户资料
- 调用资料类管理接口（昵称、头像等）

另外，仓库还提供了一个不依赖旧 `/api/login/*` 流程的标准 OIDC 示例：

- [example/main.go](./example/main.go)：Go 后端回调 / BFF 风格示例
- [example/README.md](./example/README.md)：运行方法
- [example/resource-server/main.go](./example/resource-server/main.go)：Go 资源服务 access token 校验示例
- [example/resource-server/README.md](./example/resource-server/README.md)：资源服务示例运行方法
- [oidcresource/README.md](./oidcresource/README.md)：可复用的 discovery + JWKS + Gin middleware 辅助包

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
- 如果只是调用无需可信客户端的 `/api` 接口，中间两个参数可以留空。
- 如果要做 `GetUserInfoById`、`GetUsersInfo`，需要配置 `client_id` 和 `client_secret`。

## 1. 给业务接口加登录保护

这条分支不再推荐使用 `client.AuthRequired()` 或 `client.OptionalAuth()` 做资源服务鉴权，因为服务端的旧 `/api/token/validate` 已经移除。

推荐做法：
- 读取 `/.well-known/openid-configuration`
- 使用标准 OIDC / OAuth2 JWT 库加载 `jwks_uri`
- 基于 `issuer`、`audience` 和签名校验 access token

可直接参考：
- [example/resource-server/main.go](./example/resource-server/main.go)
- [example/resource-server/README.md](./example/resource-server/README.md)

如果你不想从示例里手抄校验逻辑，也可以直接使用：

```go
import "minki.cc/mkauth/client/oidcresource"
```

也就是说，这个 SDK 现在更适合调用 MKAuth 的管理型 `/api` 接口，而不是承担 OIDC 资源服务器鉴权职责。

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

注意：
- 这里的 `GetUserInfo()` 调用的是 MKAuth 的管理型 `/api/user`
- 它更适合直接使用 `/api/account/login` 这类接口拿到的旧 `/api` token 场景
- 如果你走的是标准 OIDC 登录，用户资料读取应优先使用 `/oauth2/userinfo`

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

## 5. 令牌续期

这条分支没有 `client.RefreshToken()`，也没有 `/api/token/refresh`。

如果你的业务需要无感续期，请直接接标准 OIDC Authorization Code + PKCE，通过 `/oauth2/authorize` 与 `/oauth2/token` 获取新令牌。

如果你的业务是“浏览器 + Go 后端”，更推荐直接参考 [example/main.go](./example/main.go) 的 BFF 风格接法，让 code exchange 留在后端。

## 6. 更新昵称或头像

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
- 如果要调用 `GetUserInfoById`、`GetUsersInfo`，必须配置可信客户端。
- `client_secret` 应与服务端 `auth_trusted_clients` 配置保持一致。
- 生产环境建议始终使用 HTTPS。
- 这条分支的 OIDC 登录请直接使用标准 OIDC 客户端库，不再走 `LoginVerify()` 这种自定义 code 交换方式。
- `AuthRequired()`、`OptionalAuth()`、`ValidateToken()` 在这条分支会直接返回迁移提示，请改用 OIDC discovery + JWKS。
- 如果你要做 Web 登录接入，优先参考 [example/main.go](./example/main.go) 里的后端回调示例，而不是把 SDK 当成 OIDC 登录库使用。

## 相关文档

- 根目录接入说明：[README-zh.md](../README-zh.md)
- 英文说明：[README.md](../README.md)
