# MKAuth

MKAuth 是一个可独立部署的统一认证服务，也是一个面向 B2B 场景的可扩展 CIAM 平台。它提供账号密码、邮箱、手机号、Google、微信、微信小程序等登录方式，并内置下游 OIDC、企业身份接入、组织化访问、会话管理、管理后台和 Go 接入 SDK。

`codex/oidc-break` 分支已经把接入主路径切到标准 OIDC。新接入方优先使用 `Authorization Code + PKCE`，通过 `/.well-known/openid-configuration` 做发现；旧的 `/api/login/redirect` 和 `/api/login/verify` 已经从这条分支移除。

它适合下面几类场景：
- 你的多个业务系统希望共用一套账号体系
- 你需要单点登录能力，而不想从零实现 OIDC、令牌、会话和后台管理
- 你的业务后端是 Go，希望拿到 Go 接入示例，并通过管理型接口查询用户信息

## 功能概览

- 多种登录方式：账号、邮箱、手机号、Google、微信、微信小程序
- OIDC Provider + JWT Access / ID Token
- CIAM/IAM 基础能力：组织管理、Inbound SCIM 用户/组同步、外部身份映射、认证流程 Hook、可安装插件
- Redis 会话管理
- 用户头像上传
- 管理后台
- 用户活跃统计
- Go SDK
- Docker / Docker Compose 部署

## 产品定位

MKAuth 当前最适合定位为一个可扩展的 B2B CIAM 平台：

- 向上连接企业自己的 OIDC、SAML、LDAP/AD 身份源
- 支持组织、域名、成员关系、组织组和组织感知 claims
- 支持企业用户和组的 Inbound SCIM 同步
- 向下为业务系统提供标准 OIDC 接入
- 通过可安装插件和 HTTP Actions 扩展认证流
- 提供敏感配置加密、reseal、安全审计和导出等运维能力

它目前还不适合直接定义为完整 Workforce IAM 套件。要走到那一步，还需要补齐更完整的 RBAC/策略执行、delegated admin、service account 以及 MFA/WebAuthn 能力。

## 当前平台能力

- Enterprise OIDC 企业身份接入
- Enterprise SAML 企业身份接入
- Enterprise LDAP/AD 登录与组同步
- Organizations、组织域名、成员关系、组织组
- 基于邮箱域名的 HRD，以及 `login_hint`、`domain_hint`、`org_hint`
- Inbound SCIM Users / Groups
- 组织感知的 OIDC Claims 与 OIDC Client 级组织访问策略
- 后台可管理并支持热刷新的 OIDC Clients
- 可安装插件运行时与 HTTP Actions
- 敏感配置加密、密钥轮换回读、reseal 与安全审计导出任务

CIAM/IAM 架构和下一阶段路线见 [docs/ciam-iam-plugin-architecture.md](docs/ciam-iam-plugin-architecture.md)、[docs/roadmap.md](docs/roadmap.md)，以及更适合直接落到 GitHub Projects / Issues 的 [docs/project-board.md](docs/project-board.md)。

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
docker compose up -d --build
```

如果你不想本地构建，而是直接使用预构建镜像，也可以：

```bash
cd quickstart
docker compose -f docker-compose.release.yml up -d
```

默认会启动：
- OIDC demo SPA: `http://127.0.0.1:3000`
- MKAuth 用户入口: `http://127.0.0.1:8080`
- MKAuth 管理后台: `http://127.0.0.1:8080/admin`
- MySQL: `127.0.0.1:3306`
- Redis: `127.0.0.1:6379`
- MinIO API: `http://127.0.0.1:9002`
- MinIO Console: `http://127.0.0.1:9003`

说明：
- `quickstart/config.yaml` 默认只启用了 `account` 登录。
- `quickstart/config.yaml` 也默认启用了 OIDC，并预置了给 demo 使用的公共客户端 `demo-spa`。
- `quickstart/config.yaml` 还预置了一个 confidential client `demo-backend`，可直接配合 [client/example](client/example/README.md) 里的 Go 后端回调示例使用。
- `quickstart/config.yaml` 里默认关闭了管理后台：`auth_admin.enabled: false`。
- `quickstart/docker-compose.yml` 会直接构建当前仓库代码，因此 quickstart 与这条分支保持一致。
- `quickstart/docker-compose.sqlite.yml` 也会直接构建当前仓库代码，但数据库改成了 SQLite，适合本地最小启动。
- `quickstart/docker-compose.release.yml` 会直接拉取 `ghcr.io/minkicc/auth`，更适合给其他用户或部署环境使用。
- `quickstart/docker-compose.sqlite.release.yml` 也会直接拉取发布镜像，但数据库改成了 SQLite，适合给其他用户最小体验。
- 如果你希望别人不登录 GHCR 也能直接拉取镜像，需要把 GitHub 上发布出来的 container package 可见性改成 `public`。

### 2. 启用管理后台

先在平台里注册第一个管理员账号，再把它的内部 `user_id` 填入配置：

```yaml
auth_admin:
  enabled: true
  secret_key: "change-this-to-a-random-string"
  user_ids:
    - "usr_admin0000000000000000001"
  allowed_ips:
    - "127.0.0.1"
    - "::1"
```

然后重启服务。

现在后台不再单独维护管理员用户名和密码，而是直接复用当前浏览器里的 MKAuth 主站登录会话。管理页面默认走同域路径 `/admin`，后台 API 走 `/admin-api`；登录后，管理员用户会在主站个人信息页右上角看到进入后台的按钮。配置里的 `auth_admin.user_ids` 属于运维维护的只读管理员；日常需要新增或删除的管理员，可以直接在后台 `Settings` 页里管理，这部分数据会存进数据库。

## CI/CD：GitHub 自动打包 Docker 镜像

仓库已经内置了 `.github/workflows/docker-publish.yml`，可以直接用 GitHub Actions 自动构建并发布 Docker 镜像。

### 它会做什么

- `pull_request`：只做 Docker 构建校验，不推送镜像
- 推送到 `main`：构建多架构镜像并自动推送到 GitHub Container Registry
- 推送形如 `v1.2.3` 的 tag：自动生成并推送 `1.2.3`、`1.2`、`sha-*` 等版本标签
- 手动触发：也可以在 GitHub Actions 页面通过 `workflow_dispatch` 手动执行

### 默认发布到哪里

默认会发布到 GitHub Container Registry：

```text
ghcr.io/<owner>/<repo>
```

GHCR 不需要额外配置账号密码，工作流会直接使用 GitHub 自带的 `GITHUB_TOKEN`。

### 如果还要同步推送到 Docker Hub

在仓库设置里补齐下面三项即可：

- Actions variable：`DOCKERHUB_NAMESPACE`
- Actions secret：`DOCKER_HUB_USERNAME`
- Actions secret：`DOCKER_HUB_TOKEN`

配置完成后，同一个工作流会额外把镜像推送到：

```text
<DOCKERHUB_NAMESPACE>/<repo>
```

### 推荐发布方式

1. 日常代码合入 `main`
2. GitHub 自动发布 `ghcr.io/<owner>/<repo>:latest`
3. 需要正式版本时，打一个 `v1.2.3` 这样的 git tag
4. GitHub 自动生成稳定版本标签，供部署环境引用

这套方式比较适合给其他团队接入使用：PR 先校验 Docker 能不能构建，`main` 和 release tag 再自动产出可部署镜像。

### 首次启用检查清单

1. 先把当前分支 push 到 GitHub，让 Actions 真正跑起来
2. 确认 `Docker` 工作流在 `main` 上执行成功
3. 到 GitHub Packages 打开产出的镜像包，如果希望匿名拉取，就把可见性改成 `public`
4. 用 `docker pull ghcr.io/<owner>/<repo>:latest` 做一次实际拉取验证

### 发布命令示例

```bash
git checkout main
git pull
git tag v1.2.3
git push origin v1.2.3
```

对于“别人怎么用”这个问题，通常比起让外部用户本地 `docker build`，更好的方式是直接给他们预构建镜像。当前仓库已经同时支持两种模式：

- 开发验证：`quickstart/docker-compose.yml`
- 本地最小启动（SQLite）：`quickstart/docker-compose.sqlite.yml`
- 发布使用：`quickstart/docker-compose.release.yml`
- 发布最小启动（SQLite）：`quickstart/docker-compose.sqlite.release.yml`

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
  # 可选：mysql / sqlite。不填时，如果下面这些 MySQL 字段也都没配，
  # MKAuth 会默认使用 SQLite，并把数据写到 data/mkauth.sqlite3。
  # driver: "sqlite"
  # sqlite_path: "data/mkauth.sqlite3"
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

生产环境建议同时配置一个 secrets 加密 key，这样后台托管的敏感配置在写入数据库前会先加密：

```yaml
secrets:
  encryption_key_env: "MKAUTH_SECRETS_KEY"
  # 或者：
  # encryption_key: "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET"
  # 可选：历史 key 回读列表
  decryption_key_envs:
    - "MKAUTH_OLD_SECRETS_KEY"
```

配置后，数据库托管的 OIDC client secret 和企业身份源 secret 会按加密格式落库。已有明文旧数据仍然可以继续读取，方便平滑迁移。
如果要做密钥轮换，把新 key 配到 `encryption_key(_env)`，再把旧 key 保留在 `decryption_key_envs` 中。这样 MKAuth 会继续用旧 key 解密历史记录，但所有新写入都会使用新的主 key。

如果你没有配置 MySQL，MKAuth 现在会默认使用 SQLite 启动，并把数据写到 `data/mkauth.sqlite3`。你也可以显式设置 `db.driver: sqlite`，再通过 `db.sqlite_path` 自定义文件位置。

### 插件运行时

```yaml
plugins:
  enabled: true
  directories:
    - "plugins"
  enabled_plugins: []
  disabled_plugins: []
  allowed_permissions:
    - "hook:post_authenticate"
    - "hook:before_token_issue"
    - "hook:before_userinfo"
    - "network:http_action"
  require_signature: false
  allow_private_networks: false
  allowed_catalog_hosts:
    - "plugins.example.com"
  allowed_download_hosts:
    - "plugins.example.com"
    - "downloads.example.com"
  allowed_action_hosts:
    - "actions.example.com"
  trusted_signers:
    - id: "mkauth-dev"
      algorithm: "ed25519"
      public_key: "BASE64_ED25519_PUBLIC_KEY"
  catalogs:
    - id: "official"
      name: "Official Plugin Catalog"
      url: "https://plugins.example.com/mkauth/catalog.yaml"
      enabled: true
  http_actions:
    - id: "claims-enricher"
      name: "Claims Enricher"
      enabled: false
      events:
        - "before_token_issue"
        - "before_userinfo"
      url: "https://actions.example.com/mkauth"
      secret: "YOUR_ACTION_BEARER_SECRET"
      timeout_ms: 3000
      fail_open: false
```

现在支持两种插件交付方式：

- 通过 `plugins.http_actions` 配置的远程 HTTP Action
- 放在 `plugins.directories` 下、可直接安装的本地插件包

另外还支持两种远程分发方式：

- 通过 `plugins.catalogs` 配置的插件目录
- 在后台直接填入 ZIP 下载地址做 URL 安装

如果准备上线，建议同时配置：

- `plugins.allowed_catalog_hosts`
- `plugins.allowed_download_hosts`
- `plugins.allowed_action_hosts`

这些 host allowlist 支持精确 host、`host:port`、`.example.com` 和 `*.example.com`。catalog 里的插件下载地址默认只能指向“同 catalog host”或者显式允许的下载域。

远程插件下载和插件 HTTP Action 默认都会拒绝回环、私网、链路本地、多播和未指定 IP 地址。生产环境建议保持 `allow_private_networks: false`，除非你的插件目录、ZIP 包或 HTTP Action 端点明确部署在可信私有网络里。

对于本地插件，把包含 `mkauth-plugin.yaml` 的目录打成 ZIP，然后在后台插件页上传即可。`flow_action` 类型的本地插件可以在 manifest 里直接携带自己的 `http_action` 运行配置，因此不需要再额外修改主配置文件。

后台会在上传 ZIP 安装前先做预检，展示解析出的 manifest、包 SHA-256、签名状态、申请权限、是否覆盖现有插件，以及哪些已保存配置会被保留或丢弃。

本地插件 manifest 必须声明运行权限。HTTP Action 需要 `network:http_action`，每个 hook 事件都要声明对应的 `hook:<event>` 权限，例如 `hook:before_token_issue`。如果 `plugins.allowed_permissions` 非空，MKAuth 会拒绝申请了 allowlist 之外权限的插件。

本地插件 manifest 还可以声明 `config_schema`。后台会按 schema 生成配置表单，把配置写入 `mkauth-plugin.state.yaml`，保存后自动重载运行时。对于本地 HTTP Action 插件，保存配置可覆盖 `url`、`secret`、`secret_env`、`timeout_ms` 和 `fail_open`。

如果你希望只允许可信插件，可配置 `trusted_signers`，并开启 `require_signature: true`。MKAuth 会校验 `mkauth-plugin.sig` 对 manifest 原文的签名，并在后台展示签名状态和上传包的 SHA-256 指纹。

插件安装、启停、覆盖和卸载操作会写入插件目录下的 `mkauth-plugin.audit.jsonl`。覆盖/卸载操作还会在 `.mkauth-plugin-backups` 下创建回滚快照；恢复快照前会重新按当前签名、权限和 host 策略校验，避免回滚绕过安全策略。

插件目录响应会叠加本地安装状态，包括已安装版本、已安装包 SHA-256，以及该目录条目是否看起来可更新。后台会据此在 catalog 表格里直接显示安装、更新或重装动作。覆盖插件时会保留启用/禁用状态，并保留新 manifest 里仍然声明的已保存配置项。

仓库里已经附带了签名辅助工具，见 [tools](tools/README.md)：

```bash
cd tools
go run ./pluginsign genkey -key-id mkauth-dev -out-private ./plugin-signing.key.pem -out-public ./plugin-signing.pub
go run ./pluginsign sign -manifest ../examples/plugins/http-claims-action/mkauth-plugin.yaml -private-key ./plugin-signing.key.pem -key-id mkauth-dev
```

常用接口：

- 公共插件发现：`GET /api/plugins`
- 后台插件管理：`GET /admin-api/plugins`
- 后台插件审计：`GET /admin-api/plugins/audit`
- 后台插件备份：`GET /admin-api/plugins/backups`
- 后台插件配置：`GET /admin-api/plugins/:id/config`
- 后台插件预检：`POST /admin-api/plugins/preview`
- 后台安装插件：`POST /admin-api/plugins/install`
- 后台插件目录：`GET /admin-api/plugins/catalog`
- 后台按目录安装：`POST /admin-api/plugins/install-catalog`
- 后台 URL 安装：`POST /admin-api/plugins/install-url`
- 后台恢复备份：`POST /admin-api/plugins/restore`
- 后台更新配置：`PATCH /admin-api/plugins/:id/config`
- 后台安全审计：`GET /admin-api/security/audit`
- 后台安全审计导出：`GET /admin-api/security/audit/export`
- 后台安全审计导出任务：`GET /admin-api/security/audit/export-jobs`、`POST /admin-api/security/audit/export-jobs`、`POST /admin-api/security/audit/export-jobs/cleanup`、`GET /admin-api/security/audit/export-jobs/:job_id`、`DELETE /admin-api/security/audit/export-jobs/:job_id`、`GET /admin-api/security/audit/export-jobs/:job_id/download`
- 后台 Secrets 状态/重写：`GET /admin-api/security/secrets/status`、`POST /admin-api/security/secrets/reseal`

一个完整的本地插件示例见 [examples/plugins/http-claims-action](examples/plugins/http-claims-action/README.md)，远程目录示例见 [examples/plugins/catalog.yaml](examples/plugins/catalog.yaml)。

### CIAM/IAM 组织管理

启用管理后台后，可以在 `组织管理` 菜单里维护 B2B 租户。当前后台已经支持创建和编辑组织、绑定邮箱域名、把已有用户加入组织、给成员配置轻量角色名，并且可以直接给组织配置 Enterprise OIDC 和 Enterprise SAML 上游登录源。

下面接口里的 `:id` 可以传组织 ID，也可以传组织 slug。第一版暂不提供组织硬删除，暂时不用的组织建议把状态改成 `inactive`。

常用后台接口：

- 组织列表/创建：`GET /admin-api/organizations`、`POST /admin-api/organizations`
- 组织详情/更新：`GET /admin-api/organizations/:id`、`PATCH /admin-api/organizations/:id`
- 组织域名：`GET /admin-api/organizations/:id/domains`、`POST /admin-api/organizations/:id/domains`
- 域名更新/删除：`PATCH /admin-api/organizations/:id/domains/:domain`、`DELETE /admin-api/organizations/:id/domains/:domain`
- 组织成员：`GET /admin-api/organizations/:id/memberships`、`POST /admin-api/organizations/:id/memberships`
- 成员更新/删除：`PATCH /admin-api/organizations/:id/memberships/:user_id`、`DELETE /admin-api/organizations/:id/memberships/:user_id`
- 组织组：`GET /admin-api/organizations/:id/groups`、`POST /admin-api/organizations/:id/groups`
- 组织组详情/更新/删除：`GET /admin-api/organizations/:id/groups/:group_id`、`PATCH /admin-api/organizations/:id/groups/:group_id`、`DELETE /admin-api/organizations/:id/groups/:group_id`
- 组织身份源：`GET /admin-api/organizations/:id/identity-providers`、`POST /admin-api/organizations/:id/identity-providers`
- 身份源更新/删除：`PATCH /admin-api/organizations/:id/identity-providers/:provider_id`、`DELETE /admin-api/organizations/:id/identity-providers/:provider_id`

后台现在也支持管理手工组织组。组成员会自动把组的 `role_name` 投影到组织成员的 `org_roles`；SCIM 同步过来的组会在同一个界面只读展示。

当用户存在 active 组织成员关系，并且下游 OIDC 客户端请求了 `profile` scope 时，MKAuth 可以在 ID Token 和 `/oauth2/userinfo` 中返回 `org_id`、`org_slug`、`org_roles`、`org_groups`。

如果同一个用户属于多个组织，下游 OIDC 应用现在还可以在 `/oauth2/authorize` 上带 `org_hint=<组织ID或slug>`。MKAuth 会把这次授权、`id_token`、access token 以及 `/oauth2/userinfo` 都固定到指定组织上下文。

如果下游 OIDC 应用没有传 `org_hint`，而当前浏览器会话对应的用户又属于多个 active 组织，MKAuth 现在会自动跳到 `/select-organization`，让用户交互式选择组织后再继续授权。如果客户端同时传了 `prompt=none`，则不会展示选择页，而是直接返回 `interaction_required`。

用户端前端会通过 `GET /api/user/organizations` 加载当前用户的 active 组织成员关系、轻量角色和组织组，用于渲染这个组织选择页。

企业登录源现在支持两种维护方式：

- 通过 `iam.enterprise_oidc`、`iam.enterprise_saml` 和 `iam.enterprise_ldap` 做 YAML 静态引导
- 通过后台 `组织管理 -> 企业登录` 做运行时维护

每个企业身份源现在都支持一组轻量多 IdP 策略字段：

- `priority`：数值越小越靠前
- `is_default`：标记该组织的默认登录源
- `auto_redirect`：当 HRD 命中多个登录源时，直接跳转到当前优先登录源，而不是展示选择页

后台创建的企业登录配置会落库保存，保存后会直接触发进程内 reload，因此新增、禁用或更新企业登录源都不需要重启 MKAuth。Enterprise OIDC 的 `client_secret` 不会被后台 API 回显；Enterprise SAML 则支持通过 `idp_metadata_url` 或内联 `idp_metadata_xml` 配置元数据，也支持 `email_attribute`、`username_attribute`、`display_name_attribute` 这类属性映射字段。

当组织已经绑定了已验证域名，并且存在可用的企业身份源时，用户登录页现在支持基于企业邮箱做 HRD（Home Realm Discovery）。推荐使用的公开发现接口为：

- `GET /api/enterprise/discover?email=user@example.com`

如果你是域名优先接入，也可以直接调用：

- `GET /api/enterprise/discover?domain=example.com`

接口会返回该邮箱域名命中的组织以及一个或多个企业身份源。每个身份源都会带上 `provider_type`，登录页会根据它自动走 Enterprise OIDC、Enterprise SAML 或 Enterprise LDAP/AD。命中单个 OIDC/SAML provider 时会直接跳转；如果同一组织配置了 `auto_redirect: true` 的优先登录源，也会优先直跳；而 LDAP/AD 类型则会在当前登录页里展开目录账号密码表单。

如果下游 OIDC 应用已经知道用户的企业邮箱，也可以直接在 `/oauth2/authorize` 上带 `login_hint=user@example.com`。MKAuth 现在会把这个 hint 透传到登录页，并自动触发对应的企业身份源发现流程。

如果下游 OIDC 应用拿不到完整邮箱、只知道企业域名，也可以在 `/oauth2/authorize` 上带 `domain_hint=example.com`。MKAuth 也会透传这个 hint，并自动执行基于域名的企业身份源发现。

如果下游 OIDC 应用已经知道多组织用户应该进入哪个组织上下文，也可以直接传：

- `org_hint=acme`
- `org_hint=org_acme000000000000`

### Inbound SCIM 同步

MKAuth 可以暴露 SCIM 2.0 Users 和 Groups 接口，让 Okta、Entra ID、Google Workspace 这类企业目录把用户和组同步到指定组织。

每个企业目录配置一条 inbound SCIM 连接：

```yaml
iam:
  scim_inbound:
    - enabled: true
      slug: "acme-scim"
      name: "Acme SCIM"
      organization_id: "org_acme000000000000"
      bearer_token_hash: "$2a$10$..."
```

可以用 `tools/hashpwd.go` 生成 bcrypt token hash：

```bash
cd tools
go run hashpwd.go -password "YOUR_LONG_RANDOM_SCIM_TOKEN"
```

企业目录里的 SCIM Base URL 填：

```text
https://auth.example.com/api/scim/v2
```

当前支持的 SCIM 接口：

- 发现接口：`GET /api/scim/v2/ServiceProviderConfig`、`GET /api/scim/v2/ResourceTypes`、`GET /api/scim/v2/Schemas`
- 用户列表/创建：`GET /api/scim/v2/Users`、`POST /api/scim/v2/Users`
- 用户读取/替换/局部更新/删除：`GET /api/scim/v2/Users/:id`、`PUT /api/scim/v2/Users/:id`、`PATCH /api/scim/v2/Users/:id`、`DELETE /api/scim/v2/Users/:id`
- 组列表/创建：`GET /api/scim/v2/Groups`、`POST /api/scim/v2/Groups`
- 组读取/替换/局部更新/删除：`GET /api/scim/v2/Groups/:id`、`PUT /api/scim/v2/Groups/:id`、`PATCH /api/scim/v2/Groups/:id`、`DELETE /api/scim/v2/Groups/:id`

SCIM Users 会创建或更新 MKAuth 用户，通过 `external_identities(provider_type=scim)` 建立外部目录映射，并同步组织成员状态和轻量角色名。`DELETE /Users/:id` 和 `active=false` 会禁用 MKAuth 用户，并把对应组织成员关系标记为 disabled。

SCIM Groups 会把企业目录组映射到 `organization_groups` 和组织内的轻量角色。Group `displayName` 会被规范化成 role name，比如 `Engineering Team` 会变成 `engineering-team`。当组成员变化或组被删除时，MKAuth 只会重算由 SCIM Groups 管理的角色，并保留其它手工分配的角色。这些组现在也能在管理后台里看到，并可进入 `org_groups` OIDC claim。

### 存储

```yaml
storage:
  provider: "minio" # minio / s3 / r2 / oss
  endpoint: "localhost:9000"
  region: "zhuhai-1"
  accessKeyID: "your-access-key"
  secretAccessKey: "your-secret-key"
  attatchBucket: "attatch"

storage_public_url:
  attatch: "http://localhost:9000/attatch"
```

如果使用 Cloudflare R2，可以直接配置专门的 `r2` provider：

```yaml
storage:
  provider: "r2"
  endpoint: "https://<account_id>.r2.cloudflarestorage.com"
  region: "auto"
  accessKeyID: "YOUR_R2_ACCESS_KEY_ID"
  secretAccessKey: "YOUR_R2_SECRET_ACCESS_KEY"
  attatchBucket: "mkauth-avatar"

storage_public_url:
  attatch: "https://pub-xxxx.r2.dev"
```

Cloudflare 部署说明和 R2 配置示例见 [docs/cloudflare.md](docs/cloudflare.md)。

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
    - name: "Demo SPA"
      client_id: "demo-spa"
      public: true
      require_pkce: true
      redirect_uris:
        - "https://app.example.com/callback"
      scopes:
        - "openid"
        - "profile"
        - "email"
      # 可选：B2B 组织授权策略
      # require_organization: true
      # allowed_organizations:
      #   - "acme"
      #   - "org_acme000000000000"
      # required_org_roles:
      #   - "admin"
      # required_org_roles_all:
      #   - "security"
      # required_org_groups:
      #   - "Engineering Team"
      # required_org_groups_all:
      #   - "Employees"
      # scope_policies:
      #   email:
      #     required_org_roles_all:
      #       - "security"
      #   admin_api:
      #     required_org_roles:
      #       - "admin"
```

静态 YAML 仍然适合做启动时引导配置，但现在也可以直接在管理后台 `Settings -> OIDC Clients` 里创建、更新、禁用和删除数据库托管的 OIDC client。保存后会立即热刷新，无需重启服务。
同一个 `Settings` 页面现在也提供了 `Secrets Security` 区块，可以查看数据库敏感配置加密是否启用，并在换 key 后一键把已存量的 OIDC client / 企业身份源 secrets 重写到当前主 key。
同一套后台安全审计现在不仅会记录 Secrets 重写，还会记录数据库托管 OIDC client 和企业身份源的创建、更新、删除，方便后续追查是谁改了敏感配置，以及操作是否执行成功。
`GET /admin-api/security/audit` 现在支持 `page`、`size`、`action`、`resource_type`、`client_id`、`provider_id`、`organization_id`、`actor_id`、`query`、`time_from`、`time_to`、`success` 查询参数；其中 `client_id`、`provider_id`、`organization_id` 是精确匹配筛选，适合直接按资源标识排查问题。`time_from` 和 `time_to` 支持 RFC3339，也支持 `YYYY-MM-DD` 这种按整天筛选的写法。`GET /admin-api/security/audit/export` 会把当前筛选结果导出成 CSV，每次导出最多 5000 行。对于更重的导出场景，现在也支持后台异步导出：`POST /admin-api/security/audit/export-jobs` 创建任务，`GET /admin-api/security/audit/export-jobs` 查看最近任务，`GET /admin-api/security/audit/export-jobs/:job_id` 查询状态，`GET /admin-api/security/audit/export-jobs/:job_id/download` 在完成后下载结果。`DELETE /admin-api/security/audit/export-jobs/:job_id` 可以删除单个已完成或已失败任务，`POST /admin-api/security/audit/export-jobs/cleanup` 会按当前保留策略清理已完成或已失败的旧任务。这个保留策略现在可以通过 `auth_admin.security_audit_export_job_retention_days` 配置，自动按小时清理则可以通过 `auth_admin.security_audit_export_job_auto_cleanup` 开关控制。旧的 `GET /admin-api/security/secrets/audit` 仍然保留为兼容别名，`GET /admin-api/security/secrets/audit/export` 也同样兼容导出。管理后台的“设置”页面现在会把安全审计筛选同步到页面 URL，支持一键复制当前筛选链接，同时也支持直接打开审计详情抽屉查看完整操作者和 details 字段，并一键复制审计 ID、资源标识和详情 JSON，也可以一键跳回同 `client_id / provider_id / organization_id` 的审计历史，还能直接打开对应的 OIDC client 或企业身份源配置，同时提供“同步导出 CSV”和“后台导出”两种方式；现在也会额外展示最近后台导出任务，方便页面刷新后继续跟踪和下载结果，并支持单条删除和旧任务清理。“组织管理”页面里也已经把这套审计按组织上下文接了进去，默认只展示该组织企业身份源相关的安全变更，现在同样会把筛选同步到 URL、支持一键复制筛选链接，也可以直接生成某个企业登录源失败记录的深链，并支持同样的后台异步导出、当前组织维度的最近导出任务列表，以及对应的删除/清理操作。

服务启动后会暴露这些标准端点：
- `/.well-known/openid-configuration`
- `/oauth2/authorize`
- `/oauth2/token`
- `/oauth2/logout`
- `/oauth2/userinfo`
- `/oauth2/jwks`

OIDC 的 `sub` 使用 MKAuth 稳定的内部用户 ID，而不是登录用户名。新用户 ID 类似 `usr_8m3kq7p2x9zc4vna`；普通账号的用户名会在可用时单独通过 `preferred_username` / `username` 返回。

如果某个 OIDC client 配置了组织授权策略，MKAuth 会在发授权码之前先做校验：

- `require_organization`：用户必须以某个 active 组织上下文完成授权
- `allowed_organizations`：只允许指定的组织 ID 或 slug
- `required_org_roles`：要求至少命中一个 `org_roles`
- `required_org_roles_all`：要求命中全部列出的 `org_roles`
- `required_org_groups`：要求至少命中一个 `org_groups`
- `required_org_groups_all`：要求命中全部列出的 `org_groups`
- `scope_policies`：仅在请求到对应 OAuth scope 时，再追加更严格的组织策略

如果只有一个组织满足策略，MKAuth 会自动把这次授权固定到该组织；如果有多个组织满足策略，组织选择页也只会展示这些可用组织。

对于已登录浏览器会话和 access token，`GET /api/user/organization/authorization` 现在会从 token、`organization_id` 或 `org_hint` 里解析当前组织上下文，并返回统一组织授权解析器计算出的 `roles`、`groups` 和 `permissions`。如果用户属于多个组织但没有显式指定组织，这个接口会返回 `organization_selection_required`。

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

### 方式二：使用 MKAuth 浏览器会话接口

适合登录页本身就由 MKAuth 承载，或者你的前端能在同一个浏览器上下文里直接调用 MKAuth，并复用 `oidc_session` cookie。

如果你的业务应用在另一个域名下，或者你希望拿到标准第三方登录协议，还是更推荐方式一，直接走 OIDC Authorization Code + PKCE。

企业 LDAP/AD 登录源现在也支持轻量组同步。MKAuth 可以直接读取用户条目上的 `group_member_attribute`（默认适合 `memberOf` 这类属性），或者在 `group_base_dn` 下按 `group_filter` 搜索目录组，再把这些目录组映射为 `organization_groups` 和受管的 `org_roles`。

常用接口：
- `GET /api/providers`：查询当前启用的登录方式
- `GET /api/enterprise/providers`：查询企业登录方式
- `GET /api/enterprise/discover`：按邮箱或域名发现企业登录源
- `GET /api/enterprise/oidc/providers`：查询企业 OIDC 登录方式
- `GET /api/enterprise/oidc/:slug/login`：发起企业 OIDC 登录
- `GET /api/enterprise/oidc/:slug/callback`：企业 OIDC 回调
- `POST /api/enterprise/ldap/:slug/login`：使用企业 LDAP/AD 目录账号密码登录
- `GET /api/enterprise/saml/:slug/login`：发起企业 SAML 登录
- `GET /api/enterprise/saml/:slug/metadata`：获取企业 SAML SP metadata
- `GET /api/enterprise/saml/:slug/acs`：企业 SAML ACS 回调
- `POST /api/enterprise/saml/:slug/acs`：企业 SAML ACS 回调
- `POST /api/account/register`
- `POST /api/account/login`
- `POST /api/email/login`
- `POST /api/phone/login`
- `GET /api/browser-session`
- `POST /api/logout`
- `GET /api/user`

当存在 CIAM/IAM 组织成员数据，并且下游 OIDC 客户端请求了 `profile` scope 时，MKAuth 会在 ID Token 和 `/oauth2/userinfo` 中额外返回 `org_id`、`org_slug`、`org_roles`、`org_groups`。对于多组织用户，也可以通过 `/oauth2/authorize` 的 `org_hint` 把这次授权固定到指定组织。

账号登录示例：

```bash
curl -X POST http://localhost:8080/api/account/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"demo123"}'
```

返回示例：

```json
{
  "authenticated": true,
  "user_id": "usr_8m3kq7p2x9zc4vna",
  "username": "demo",
  "nickname": "demo",
  "avatar": "",
  "expires_at": "2026-04-23T10:00:00Z"
}
```

这些 `/api` 登录接口现在只负责建立 `oidc_session` 浏览器会话，不再返回旧的 `/api` bearer token，这条分支也不再提供 `POST /api/token/refresh`。

后续请求可以用两种方式鉴权：

```text
1. 同一浏览器里的 `oidc_session` cookie
2. Authorization: Bearer <oidc-access-token>
```

如果你需要浏览器里的无感续期，更推荐直接接标准 OIDC Authorization Code + PKCE，让 MKAuth 复用自己的 `oidc_session` 浏览器会话。

#### 标识规范化与浏览器会话写操作限制

MKAuth 现在会在重复校验、登录校验和限流前，对用户标识做统一规范化处理：

- 账号 `username`：先去首尾空格，长度要求 `3-64`，允许字符为字母、数字、`.`、`_`、`@`、`-`，并且首尾必须是字母或数字
- 邮箱：在注册、登录、重发验证、找回密码前都会先去空格并转成小写
- 手机号：会去掉空格、`-`、`.`、`(`、`)` 这些分隔符，允许保留一个前导 `+`，最终规范化后的数字长度必须是 `7-15`

`user_id` 不再是登录标识，而是 `usr_` 加 16 位易读随机字符组成的内部 ID，并作为 OIDC subject 使用。账号密码登录时提交的 `username` 会保存在独立账号映射表里，`/api` 响应会单独返回 `username`。

发送邮件和短信的流程会按“规范化后的标识 + 客户端 IP”做限流。覆盖范围包括邮箱注册、重发验证、发起找回密码，以及手机号预注册、重发验证、发送登录验证码、发起找回密码。

所有会创建 `oidc_session` 浏览器会话的 POST 接口都会拒绝明确的跨站浏览器请求。如果浏览器带来的 `Origin` 不匹配、`Referer` 不匹配，或者 `Sec-Fetch-Site` 是 `cross-site` / `same-site`，MKAuth 会返回 `403`。为了兼容服务端调用，没有浏览器来源元数据的非浏览器请求仍然允许。

如果请求是通过浏览器里的 `oidc_session` cookie 鉴权，那么所有会修改状态的 `/api` 接口还要求 `Origin` 或 `Referer` 必须与 MKAuth 的 issuer/origin 一致。比如登出、改密、更新资料、头像上传/删除、终止会话等接口都受这个限制。使用 `Authorization: Bearer <access_token>` 的调用则不需要这层浏览器 same-origin 校验。

使用浏览器会话 cookie 做 `curl` 登出时，示例可以写成：

```bash
curl -X POST http://localhost:8080/api/logout \
  -H 'Origin: http://localhost:8080' \
  -b 'oidc_session=YOUR_BROWSER_SESSION'
```

## Go SDK 使用方式

`client/auth` 目录下的 Go SDK 现在更适合调用 MKAuth 管理型 `/api` 接口，但它不是这条分支推荐的登录接入方式。

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

可直接参考：
- [client/example/resource-server/main.go](client/example/resource-server/main.go)
- [client/example/resource-server/README.md](client/example/resource-server/README.md)
- [client/oidcresource/README.md](client/oidcresource/README.md)

### 2. 查询当前登录用户

```go
user, err := client.GetUserInfo(accessToken)
```

这个调用走的是 MKAuth 管理型 `/api/user` 接口。

它适合你明确要直接调用 MKAuth `/api` 接口，并使用下面任意一种鉴权方式：
- 浏览器里的 `oidc_session` 会话
- 标准 OIDC `Authorization: Bearer <access_token>`

如果你的应用已经按标准 OIDC 登录，用户资料读取应优先使用 `/oauth2/userinfo`；Go 后端回调接法可以直接参考 [client/example](client/example/README.md)。

### 3. 查询指定用户或批量用户

这两个接口需要 `auth_trusted_clients` 配置和对应 scope：

```go
client := auth.NewAuthClient("http://localhost:8080", "myapp", "your-client-secret")

user, err := client.GetUserInfoById(accessToken, "user-001")
users, err, statusCode := client.GetUsersInfo(accessToken, []string{"user-001", "user-002"})
```

### 4. 令牌续期

这条分支没有 `client.RefreshToken()`，也没有 `POST /api/token/refresh`。

需要续期时，请重新走一次标准 OIDC 授权码流程，通过 `/oauth2/authorize` 和 `/oauth2/token` 获取新的令牌。

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
