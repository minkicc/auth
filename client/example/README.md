# Auth Go OIDC BFF Example

这个示例演示的是这条 `codex/oidc-break` 分支推荐的 Go 接入方式：

- 后端读取 OIDC discovery
- 浏览器走 `Authorization Code + PKCE`
- 后端回调地址完成 code exchange
- 后端校验 `id_token`
- 后端调用 `/oauth2/userinfo`
- 本地用 server-side session 保存登录态

这比直接在前端持有 token 更接近很多实际生产项目的做法。

## 默认配置

示例会读取下面这些环境变量。`AUTH_CLIENT_SECRET` 没有内置默认值，避免把可复制的客户端密钥带进公开代码：

```text
AUTH_ISSUER=http://127.0.0.1:8080
AUTH_CLIENT_ID=demo-backend
AUTH_CLIENT_SECRET=<the-secret-you-configured-for-your-confidential-client>
AUTH_REDIRECT_URL=http://127.0.0.1:8082/auth/callback
LISTEN_ADDR=:8082
```

## 推荐配合 quickstart 运行

先启动 Auth。quickstart 默认只包含 public PKCE demo；如果要运行本 BFF 示例，需要先在 Auth 的 OIDC 配置中增加一个 confidential client，并把回调地址设为 `http://127.0.0.1:8082/auth/callback`：

```bash
cd quickstart
docker compose up -d --build
```

然后用同一个 client secret 启动这个示例：

```bash
cd client
AUTH_CLIENT_SECRET='<your-client-secret>' go run ./example
```

然后打开：

```text
http://127.0.0.1:8082
```

## 说明

- 这个示例里的 session 是内存实现，只适合开发和演示。
- 生产环境建议把 session 放到 Redis 等共享存储，并启用 HTTPS。

## 相关示例

- [resource-server/main.go](./resource-server/main.go)：演示资源服务如何通过 discovery + JWKS 校验 Auth access token
- [resource-server/README.md](./resource-server/README.md)：资源服务示例的运行方法
