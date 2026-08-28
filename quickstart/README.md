# Auth Quickstart

`quickstart/` 提供了几套可直接体验的 Docker Compose 配置，用来快速启动 Auth 所需的基础依赖，以及一个最小可运行的 OIDC PKCE demo。

## 会启动什么

- MySQL 8
- Redis 7
- Local file storage in SQLite quickstarts; MinIO in MySQL quickstarts
- Auth 服务
- OIDC demo SPA

## 使用方法

### 方式一：本地构建当前仓库代码，使用 MySQL

适合开发、联调、验证当前 checkout：

```bash
cd quickstart
cp .env.example .env
# Replace the CHANGE_ME values in .env before continuing.
docker compose up -d --build
```

对应文件：`quickstart/docker-compose.yml`

### 方式二：本地构建当前仓库代码，使用 SQLite 最小启动

适合本地快速体验，不想额外起 MySQL：

```bash
cd quickstart
docker compose -f docker-compose.sqlite.yml up -d --build
```

对应文件：
- `quickstart/docker-compose.sqlite.yml`
- `quickstart/config.sqlite.yaml`

### 方式三：直接拉取 GitHub 自动发布的镜像，使用 MySQL

适合其他团队或部署环境直接使用预构建版本：

```bash
cd quickstart
cp .env.example .env
# Replace the CHANGE_ME values in .env before continuing.
docker compose -f docker-compose.release.yml up -d
```

如果你想固定版本，可以显式指定镜像标签：

```bash
cd quickstart
AUTH_IMAGE=ghcr.io/example/auth:v1.2.3 docker compose -f docker-compose.release.yml up -d
```

对应文件：`quickstart/docker-compose.release.yml`

### 方式四：直接拉取 GitHub 自动发布的镜像，使用 SQLite 最小启动

适合其他团队直接体验发布版，但不想额外起 MySQL：

```bash
cd quickstart
docker compose -f docker-compose.sqlite.release.yml up -d
```

如果你想固定版本，可以显式指定镜像标签：

```bash
cd quickstart
AUTH_IMAGE=ghcr.io/example/auth:v1.2.3 docker compose -f docker-compose.sqlite.release.yml up -d
```

对应文件：
- `quickstart/docker-compose.sqlite.release.yml`
- `quickstart/config.sqlite.yaml`

如果 GHCR 包还是私有的，先执行：

```bash
docker login ghcr.io
```

如果你希望其他用户匿名拉取镜像，还需要把 GitHub 上的 Container package 可见性改成 `public`。

启动后默认访问地址：
- OIDC demo: `http://127.0.0.1:3000`
- 用户入口: `http://127.0.0.1:8080`
- 管理后台: `http://127.0.0.1:8080/admin`
- MinIO API for MySQL quickstarts: `http://127.0.0.1:9002`
- MinIO Console for MySQL quickstarts: `http://127.0.0.1:9003`

这些端口只绑定到本机回环地址；如果要提供给局域网或公网访问，请在反向代理中配置 TLS、访问控制和实际域名，不要直接把数据库或 MinIO 端口暴露出去。

## 默认行为

`quickstart/config.yaml` 默认配置为：
- 仅启用 `account` 登录
- 默认启用 OIDC，并内置一个公共客户端 `demo-spa`
- 管理后台关闭
- 存储后端使用 MinIO
- OIDC demo 的回调地址已经预先配置为 `http://127.0.0.1:3000/`
- OIDC 签名私钥在首次启动时自动生成，并保存在 `/app/data` 卷中

`quickstart/config.sqlite.yaml` 使用 SQLite 和本地文件存储。数据库、头像文件和自动生成的 OIDC 签名私钥都持久化在容器的 `/app/data` 卷中，不再需要 MinIO。

## 先体验一遍 OIDC 登录

1. 打开 `http://127.0.0.1:3000`
2. 点击页面上的 `Discover configuration`
3. 点击 `Start login`
4. 第一次可以先在 Auth 登录页注册一个账号
5. 登录成功后，demo 会自动完成：
   - PKCE 授权跳转
   - code 换 token
   - 调用 `/oauth2/userinfo`
   - 展示 `access_token`、`id_token` 和用户信息
6. 点击 `Logout` 会调用 `/oauth2/logout` 清理 Auth 浏览器会话，并跳回 demo 页面

## 运行 Go 后端回调示例

仓库还带了一个 Go 版 BFF / backend callback 示例。quickstart 不再预置 confidential client；需要使用该示例时，先生成一个随机 secret，并在 `quickstart/config.yaml` 或 `quickstart/config.sqlite.yaml` 的 `oidc.clients` 下增加：

```yaml
    - name: "Demo Backend"
      client_id: "demo-backend"
      client_secret: "${AUTH_DEMO_BACKEND_SECRET}"
      public: false
      require_pkce: true
      redirect_uris:
        - "http://127.0.0.1:8082/auth/callback"
        - "http://localhost:8082/auth/callback"
      scopes:
        - "openid"
        - "profile"
        - "email"
```

MySQL quickstart 会从 `quickstart/.env` 读取 `AUTH_DEMO_BACKEND_SECRET`；SQLite quickstart 可以在启动前导出同名环境变量。

```bash
export AUTH_DEMO_BACKEND_SECRET="$(openssl rand -hex 32)"
cd client
AUTH_CLIENT_SECRET="$AUTH_DEMO_BACKEND_SECRET" go run ./example
```

启动后访问：

```text
http://127.0.0.1:8082
```

这个示例默认使用：

```text
AUTH_ISSUER=http://127.0.0.1:8080
AUTH_CLIENT_ID=demo-backend
AUTH_CLIENT_SECRET=<the-secret-you-configured-for-your-confidential-client>
AUTH_REDIRECT_URL=http://127.0.0.1:8082/auth/callback
```

## 运行 Go 资源服务校验示例

如果你还想演示“业务 API 如何校验 access token”，可以再起一个资源服务示例：

```bash
cd client
go run ./example/resource-server
```

然后调用：

```bash
curl -H 'Authorization: Bearer <access-token>' http://127.0.0.1:8083/protected
```

默认它会校验：
- 签名
- issuer
- audience=`demo-backend`
- token_type=`access_token`

## 如果要启用管理后台

1. 先在平台里注册第一个管理员账号，拿到它的内部 `user_id`。

2. 修改 `quickstart/config.yaml`：

```yaml
auth_admin:
  enabled: true
  secret_key: "change-this-to-a-random-string"
  user_ids:
    - "usr_admin0000000000000000001"
```

3. 重启服务：

```bash
docker compose restart auth-server
```

后台不再使用单独的管理员用户名密码。管理员用户先在主站登录，然后可以从主站个人资料页右上角直接进入后台。管理页面走同域 `/admin`，后台 API 走 `/admin-api`。后续新增或删除日常管理员，可在后台 `Settings` 页里管理，数据库管理员与配置文件管理员会分开显示。

如果你不想公开注册，可以先在配置里放一个一次性 bootstrap 邀请码：

```yaml
registration:
  mode: "invite_only"
  bootstrap_invitation_code: "CHANGE_ME_FIRST_USER_CODE"
```

用这个邀请码注册出来的是普通用户，不会自动成为管理员。拿到它的 `user_id` 后再写入 `auth_admin.user_ids`，这个启动流程就闭环了。进入后台后，可在 `Settings -> Invitation Codes` 继续生成内测邀请码。

## 如果要启用更多登录方式

编辑 `quickstart/config.yaml` 中的：

```yaml
auth:
  enabled_providers:
    - "account"
    - "email"
    - "phone"
    - "google"
    - "weixin"
    - "weixin_mini"
```

同时补齐对应的 SMTP、短信、OAuth 配置。

## 说明

- `quickstart/docker-compose.yml` 会直接构建你本地 checkout 的代码，并依赖 MySQL，更适合验证完整依赖场景。
- `quickstart/docker-compose.sqlite.yml` 会直接构建你本地 checkout 的代码，但不依赖 MySQL，更适合本地最小启动和快速体验。
- `quickstart/docker-compose.release.yml` 会直接拉取 `ghcr.io/example/auth` 镜像，并依赖 MySQL，更适合发给其他用户或部署环境使用。
- `quickstart/docker-compose.sqlite.release.yml` 会直接拉取 `ghcr.io/example/auth` 镜像，但数据库改成了 SQLite，适合给其他用户做最小体验。
- `quickstart/docker-compose.yml` 和 `quickstart/docker-compose.release.yml` 会等待 MySQL、Redis、MinIO 健康后再启动 `auth-server`。
- `quickstart/docker-compose.sqlite.yml` 和 `quickstart/docker-compose.sqlite.release.yml` 只依赖 Redis；数据库使用 SQLite，头像使用本地文件存储。
- MySQL quickstart 需要先复制 `quickstart/.env.example` 为 `quickstart/.env` 并填写随机凭据；这些凭据不会写入 Git。
