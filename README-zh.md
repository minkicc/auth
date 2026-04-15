# MKAuth

MKAuth 是一个可独立部署的统一认证服务，提供账号密码、邮箱、手机号、Google、微信、微信小程序等登录方式，并内置用户中心、管理后台、会话管理和 Go 接入 SDK。

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

### 可信业务后端配置

如果你的业务后端要用 code 换 token、按用户 ID 查资料、批量拉用户信息，就需要配置 `auth_trusted_clients`：

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

MKAuth 目前最适合两种接入方式。

### 方式一：直接使用内置登录页

适合你已经有业务系统，希望把登录完全交给 MKAuth。

#### 流程

1. 业务系统把用户跳转到 MKAuth 登录页：

```text
GET /login?client_id=myapp&redirect_uri=https://your-app.example.com/auth/callback
```

2. 用户在 MKAuth 完成登录。
3. MKAuth 会把用户带回你的 `redirect_uri`，并附带一个一次性 `code`。
4. 你的业务后端使用受信任客户端身份调用 `/api/login/verify`，把 `code` 换成访问令牌。
5. 后续业务请求携带 `Authorization: Bearer <token>` 即可。

#### 业务后端回调示例

```go
package main

import (
    "net/http"

    "github.com/gin-gonic/gin"
    mkauth "minki.cc/mkauth/client/auth"
)

func main() {
    authClient := mkauth.NewAuthClient(
        "http://localhost:8080",
        "myapp",
        "your-client-secret",
    )

    r := gin.Default()

    r.GET("/auth/callback", func(c *gin.Context) {
        code := c.Query("code")
        if code == "" {
            c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
            return
        }

        loginResp, err := authClient.LoginVerify(code, c)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
            return
        }

        c.JSON(http.StatusOK, gin.H{
            "user_id": loginResp.UserID,
            "token":   loginResp.Token,
        })
    })

    r.Run(":8082")
}
```

这个模式下，登录页、注册页、第三方登录按钮都由 MKAuth 自己维护，你的业务系统只处理跳转和回调。

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

### 安装

```bash
go get minki.cc/mkauth/client
```

### 1. 为业务接口加登录保护

```go
client := auth.NewAuthClient("http://localhost:8080", "", "")

protected := r.Group("/api")
protected.Use(client.AuthRequired())
{
    protected.GET("/profile", func(c *gin.Context) {
        userID := c.GetString("user_id")
        c.JSON(200, gin.H{"user_id": userID})
    })
}
```

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
- `POST /api/token/validate`
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
