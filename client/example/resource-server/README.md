# MKAuth Go Resource Server Example

这个示例演示的是业务资源服务如何在 OIDC-first 分支里校验 MKAuth 发出的 access token。

它会做这些事：

- 读取 `/.well-known/openid-configuration`
- 使用 `jwks_uri` 建立远程 JWKS verifier
- 校验 Bearer token 的签名、issuer、audience、过期时间
- 额外检查 `token_type=access_token`
- 可选检查某个必需 scope

## 默认配置

```text
MKAUTH_ISSUER=http://127.0.0.1:8080
MKAUTH_EXPECTED_AUDIENCE=demo-backend
MKAUTH_REQUIRED_SCOPE=
LISTEN_ADDR=:8083
```

默认 audience 设成了 `demo-backend`，所以它最适合配合同目录下的 backend callback 示例一起使用。

## 运行方法

先启动 MKAuth：

```bash
cd quickstart
docker compose up -d --build
```

再启动 backend callback 示例拿 token：

```bash
cd client
go run ./example
```

再启动这个资源服务示例：

```bash
cd client
go run ./example/resource-server
```

## 体验方式

1. 打开 `http://127.0.0.1:8082`
2. 通过 backend callback 示例登录
3. 从页面里复制 `access_token`
4. 调用资源服务：

```bash
curl -H 'Authorization: Bearer <access-token>' http://127.0.0.1:8083/protected
```

## 说明

- 如果你把 `MKAUTH_REQUIRED_SCOPE` 设成某个 scope，示例会额外校验该 scope。
- 如果你拿的是 `demo-spa` 那条 public client 的 token，默认 audience 会对不上，需要把 `MKAUTH_EXPECTED_AUDIENCE` 改成对应 client ID。
- 这只是资源服务的最小示例，生产环境里还应补上更完整的日志、错误分类、缓存和可观测性。
