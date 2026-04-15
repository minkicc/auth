# MKAuth Quickstart

`quickstart/` 提供了一套可直接体验的 Docker Compose 配置，用来快速启动 MKAuth 所需的基础依赖和服务。

## 会启动什么

- MySQL 8
- Redis 7
- MinIO
- MKAuth 服务

## 使用方法

```bash
cd quickstart
docker compose up -d
```

启动后默认访问地址：
- 用户入口: `http://localhost:8080`
- 管理后台: `http://localhost:8081`
- MinIO API: `http://localhost:9002`
- MinIO Console: `http://localhost:9003`

## 默认行为

`quickstart/config.yaml` 默认配置为：
- 仅启用 `account` 登录
- 管理后台关闭
- 存储后端使用 MinIO

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

当前 `quickstart/docker-compose.yml` 使用的是预构建镜像 `minkicc/auth:latest`，适合快速体验。若你正在开发本仓库源码，建议在根目录阅读 [README-zh.md](../README-zh.md) 中的“本地开发”章节。
