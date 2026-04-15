# MKAuth

MKAuth 是一个可独立部署的统一认证服务，提供账号密码、邮箱、手机号、Google、微信、微信小程序等登录方式，并内置用户中心、管理后台、会话管理和 Go 接入 SDK。

`codex/oidc-break` 分支已经把接入主路径切到标准 OIDC。新接入方优先使用 `Authorization Code + PKCE`，通过 `/.well-known/openid-configuration` 做发现；旧的 `/api/login/redirect` 和 `/api/login/verify` 已经从这条分支移除。

它适合下面几类场景：
- 你的多个业务系统希望共用一套账号体系
- 你需要单点登录能力，而不想从零实现用户、令牌、刷新、会话和后台管理
- 你的业务后端是 Go，希望直接通过 SDK 校验登录态、查询用户信息

## 功能概览

- 多种登录方式：账号、邮箱、手机号、Google、微信、微信小程序
- JWT 访问令牌 + Refresh Token
- Redis 会话管理
- 用户头像上传
- 管理后台
- 用户活跃统计
- Go SDK
- Docker / Docker Compose 部署

## 仓库结构

```text
mkauth/
├── server/        # Go 后端服务
├── web/           # 用户登录页
├── admin-web/     # 管理后台前端
├── client/        # Go SDK
├── quickstart/    # Docker Compose 快速启动配置
└── tools/         # 密码/密钥生成工具
```

## 快速开始

### 1. 使用 Docker Compose 启动

```bash
cd quickstart
docker compose up -d
```

默认会启动：
- MKAuth 用户入口: `http://localhost:8080`
- MKAuth 管理后台: `http://localhost:8081`
- MySQL: `localhost:3306`
- Redis: `localhost:6379`
- MinIO API: `http://localhost:9002`
- MinIO Console: `http://localhost:9003`

说明：
- `quickstart/config.yaml` 默认只启用了 `account` 登录。
- `quickstart/config.yaml` 里默认关闭了管理后台：`auth_admin.enabled: false`。
- `quickstart/docker-compose.yml` 当前使用预构建镜像 `minkicc/auth:latest`，更适合体验和演示。

### 2. 启用管理后台

先生成管理员密码哈希：

```bash
cd tools
go run hashpwd.go -password "YourStrongPassword"
```

把输出的 bcrypt 哈希填入配置：

```yaml
auth_admin:
  enabled: true
  secret_key: "change-this-to-a-random-string"
  accounts:
    - username: "admin"
      password: "$2a$10$..."
      roles:
        - "super_admin"
  allowed_ips:
    - "127.0.0.1"
    - "::1"
```

然后重启服务。

## 本地开发

### 后端

```bash
cd server
cp config/config.yaml.example config/config.yaml
go run . -config ./config/config.yaml -web ../web/dist -admin-web ../admin-web/dist
```

### 用户端前端

```bash
cd web
npm install
npm run dev
```

### 管理后台前端

```bash
cd admin-web
npm ci
npm run dev
```

仓库根目录已提交 `.nvmrc`，建议先执行：

```bash
nvm use
```

## 核心配置

完整配置示例见 [server/config/config.yaml.example](server/config/config.yaml.example)。

最常用的配置块如下。

### 数据库与 Redis

```yaml
db:
  user: "root"
  password: "password"
  host: "localhost"
  port: 3306
  database: "mkauth"
  charset: "utf8mb4"

redis:
  addr: "localhost:6379"
  password: ""
  db: 0
```

### 存储

```yaml
storage:
  provider: "minio" # minio / s3 / oss
  endpoint: "localhost:9000"
  region: "zhuhai-1"
  accessKeyID: "your-access-key"
  secretAccessKey: "your-secret-key"
  attatchBucket: "attatch"

storage_public_url:
  attatch: "http://localhost:9000/attatch"
```

### 登录方式开关

```yaml
auth:
  enabled_providers:
    - "account"
    - "email"
    - "phone"
    - "google"
    - "weixin"
    - "weixin_mini"
  jwt:
    issuer: "mkauth"
```

只配置你真正要开放的登录方式即可。

### OIDC 客户端配置

如果你准备按标准 OIDC 接入，请配置 `oidc.clients`：

```yaml
oidc:
  enabled: true
  issuer: "https://auth.example.com"
  key_id: "mkauth-oidc-v1"
  private_key_file: "/path/to/oidc-private-key.pem"
  code_ttl_seconds: 300
  access_token_ttl_seconds: 900
  id_token_ttl_seconds: 900
  clients:
    - client_id: "demo-spa"
      public: true
      require_pkce: true
      redirect_uris:
        - "https://app.example.com/callback"
      scopes:
        - "openid"
        - "profile"
        - "email"
```

服务启动后会暴露这些标准端点：
- `/.well-known/openid-configuration`
- `/oauth2/authorize`
- `/oauth2/token`
- `/oauth2/userinfo`
- `/oauth2/jwks`

### 可信业务后端配置

`auth_trusted_clients` 在这条分支里只用于旧的管理型 `/api` 接口，例如按用户 ID 查询资料或批量查询用户，不再参与登录回调换 token：

```yaml
auth_trusted_clients:
  - client_id: "myapp"
    client_secret: "$2a$10$..."
    allowed_ips:
      - "*"
    scopes:
      - "read:users"
```

`client_secret` 建议也使用 bcrypt 后的值保存。

## 推荐接入方式

MKAuth 在这条分支上优先推荐标准 OIDC 接入。

### 方式一：OIDC Authorization Code + PKCE

这是现在最推荐的接入方式，适合 Web、SPA、移动端和多语言后端。

#### 流程

1. 客户端读取 `/.well-known/openid-configuration`
2. 浏览器跳转到 `/oauth2/authorize`
3. 用户在 MKAuth 完成登录
4. MKAuth 回调你的 `redirect_uri`，附带 OIDC `code`
5. 客户端或后端调用 `/oauth2/token` 换取 `access_token` 和 `id_token`
6. 通过 `/oauth2/jwks` 校验 `id_token`，或者调用 `/oauth2/userinfo`

补充说明：
- MKAuth 登录页现在通过独立的 `oidc_session` 浏览器会话维持登录状态
- `/oauth2/authorize` 不再依赖旧的 `refreshToken` cookie 来识别当前用户

#### 授权地址示例

```text
GET /oauth2/authorize?client_id=demo-spa&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&response_type=code&scope=openid%20profile%20email&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=abc123&nonce=n-0S6_WzA2Mj
```

#### 换 token 示例

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'client_id=demo-spa' \
  --data-urlencode 'code=YOUR_CODE' \
  --data-urlencode 'redirect_uri=https://app.example.com/callback' \
  --data-urlencode 'code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
```

### 方式二：你的前端直接调用 MKAuth API

适合你已经有自己的登录页，只想复用认证接口。

常用接口：
- `GET /api/providers`：查询当前启用的登录方式
- `POST /api/account/register`
- `POST /api/account/login`
- `POST /api/email/login`
- `POST /api/phone/login`
- `POST /api/token/refresh`
- `POST /api/logout`
- `GET /api/user`

账号登录示例：

```bash
curl -X POST http://localhost:8080/api/account/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"demo123"}'
```

返回示例：

```json
{
  "user_id": "demo",
  "token": "access-token",
  "nickname": "demo",
  "avatar": "",
  "expire_time": 7200000000000
}
```

前端拿到 `token` 后，在后续请求中带上：

```text
Authorization: Bearer <access-token>
```

刷新令牌通过 `refreshToken` Cookie 维护，刷新接口为：

```text
POST /api/token/refresh
```

## Go SDK 使用方式

`client/auth` 目录下的 Go SDK 仍然主要面向旧的 `/api` JWT 接口。它可以继续用于一些管理型 API 或本地过渡，但不是这条分支推荐的 OIDC 接入方式。

### 安装

```bash
go get minki.cc/mkauth/client
```

### 1. 为业务接口加登录保护

这条分支不再推荐使用 `client.AuthRequired()` 做业务资源接口保护。

推荐做法：
- 读取 `/.well-known/openid-configuration`
- 使用标准 OIDC / OAuth2 JWT 库加载 `jwks_uri`
- 基于 `issuer`、`audience` 和签名校验 access token

### 2. 查询当前登录用户

```go
user, err := client.GetUserInfo(accessToken)
```

### 3. 查询指定用户或批量用户

这两个接口需要 `auth_trusted_clients` 配置和对应 scope：

```go
client := auth.NewAuthClient("http://localhost:8080", "myapp", "your-client-secret")

user, err := client.GetUserInfoById(accessToken, "user-001")
users, err, statusCode := client.GetUsersInfo(accessToken, []string{"user-001", "user-002"})
```

### 4. 刷新令牌

```go
newToken, statusCode, err := client.RefreshToken(refreshToken, c)
```

### 5. 本地自签名 HTTPS 调试

```go
client.UseInsecureTLS()
```

只建议在本地或测试环境使用，不要在生产启用。

## 常用接口速查

### 认证接口

- `GET /api/providers`
- `POST /api/account/register`
- `POST /api/account/login`
- `POST /api/email/login`
- `POST /api/phone/login`
- `POST /api/token/refresh`
- `POST /api/logout`

### 用户接口

- `GET /api/user`
- `GET /api/user/:id`
- `POST /api/users`
- `PUT /api/user`
- `POST /api/avatar/upload`
- `DELETE /api/avatar`
- `GET /api/sessions`

### 运维接口

- `GET /health`
- `GET /metrics`

## 接入建议

- 生产环境一定要使用 HTTPS。
- 管理后台建议配置 `allowed_ips`。
- 业务后端不要直接信任前端传来的 `user_id`，应始终以令牌校验结果为准。
- 只开放真正要用的 `enabled_providers`，减少无效暴露面。
- `storage_public_url.attatch` 需要能被前端访问，否则头像 URL 无法正确展示。

## 相关文档

- 根目录接入说明：[README.md](README.md)
- Go SDK 说明：[client/README.md](client/README.md)
- 快速启动说明：[quickstart/README.md](quickstart/README.md)

## 许可证

本项目基于 MIT License 发布，详见 [LICENSE.txt](LICENSE.txt)。
