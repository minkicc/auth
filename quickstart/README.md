# MKAuth Quickstart

`quickstart/` 提供了一套可直接体验的 Docker Compose 配置，用来快速启动 MKAuth 所需的基础依赖、当前仓库代码，以及一个最小可运行的 OIDC PKCE demo。

## 会启动什么

- MySQL 8
- Redis 7
- MinIO
- MKAuth 服务
- OIDC demo SPA

## 使用方法

```bash
cd quickstart
docker compose up -d --build
```

启动后默认访问地址：
- OIDC demo: `http://127.0.0.1:3000`
- 用户入口: `http://127.0.0.1:8080`
- 管理后台: `http://127.0.0.1:8081`
- MinIO API: `http://127.0.0.1:9002`
- MinIO Console: `http://127.0.0.1:9003`

## 默认行为

`quickstart/config.yaml` 默认配置为：
- 仅启用 `account` 登录
- 默认启用 OIDC，并内置一个公共客户端 `demo-spa`
- 管理后台关闭
- 存储后端使用 MinIO
- OIDC demo 的回调地址已经预先配置为 `http://127.0.0.1:3000/`
- `quickstart/oidc-private-key.pem` 只是为了本地演示方便而提交的开发私钥，生产环境请务必替换

## 先体验一遍 OIDC 登录

1. 打开 `http://127.0.0.1:3000`
2. 点击页面上的 `Discover configuration`
3. 点击 `Start login`
4. 第一次可以先在 MKAuth 登录页注册一个账号
5. 登录成功后，demo 会自动完成：
   - PKCE 授权跳转
   - code 换 token
   - 调用 `/oauth2/userinfo`
   - 展示 `access_token`、`id_token` 和用户信息
6. 点击 `Logout` 会调用 `/oauth2/logout` 清理 MKAuth 浏览器会话，并跳回 demo 页面

## 如果要启用管理后台

1. 先生成管理员密码哈希：

```bash
cd tools
go run hashpwd.go -password "YourStrongPassword"
```

2. 修改 `quickstart/config.yaml`：

```yaml
auth_admin:
  enabled: true
  secret_key: "change-this-to-a-random-string"
  accounts:
    - username: "admin"
      password: "$2a$10$..."
      roles:
        - "super_admin"
```

3. 重启服务：

```bash
docker compose restart mkauth-server
```

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

当前 `quickstart/docker-compose.yml` 会直接构建你本地 checkout 的代码，因此它更适合这条分支的验证和演示。首次 `--build` 会稍慢一些，但可以确保 OIDC demo 与当前代码一致。
