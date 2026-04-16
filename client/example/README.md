# MKAuth Go OIDC BFF Example

这个示例演示的是这条 `codex/oidc-break` 分支推荐的 Go 接入方式：

- 后端读取 OIDC discovery
- 浏览器走 `Authorization Code + PKCE`
- 后端回调地址完成 code exchange
- 后端校验 `id_token`
- 后端调用 `/oauth2/userinfo`
- 本地用 server-side session 保存登录态

这比直接在前端持有 token 更接近很多实际生产项目的做法。

## 默认配置

示例默认会读取下面这些环境变量；如果没有设置，就使用内置开发默认值：

```text
MKAUTH_ISSUER=http://127.0.0.1:8080
MKAUTH_CLIENT_ID=demo-backend
MKAUTH_CLIENT_SECRET=demo-backend-secret
MKAUTH_REDIRECT_URL=http://127.0.0.1:8082/auth/callback
LISTEN_ADDR=:8082
```

## 推荐配合 quickstart 运行

先启动 MKAuth：

```bash
cd quickstart
docker compose up -d --build
```

再启动这个示例：

```bash
cd client
go run ./example
```

然后打开：

```text
http://127.0.0.1:8082
```

## 说明

- quickstart 已预置了 `demo-backend` 这个 confidential client。
- 这个示例里的 session 是内存实现，只适合开发和演示。
- 生产环境建议把 session 放到 Redis 等共享存储，并启用 HTTPS。

## 相关示例

- [resource-server/main.go](./resource-server/main.go)：演示资源服务如何通过 discovery + JWKS 校验 MKAuth access token
- [resource-server/README.md](./resource-server/README.md)：资源服务示例的运行方法
