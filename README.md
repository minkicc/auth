# MKAuth

MKAuth is a deployable authentication service that provides account/password, email, phone, Google, WeChat, and WeChat Mini Program login, together with JWT, session management, an admin console, and a Go SDK.

The `codex/oidc-break` branch moves the primary integration path to standard OIDC. New integrations should prefer `Authorization Code + PKCE` plus discovery via `/.well-known/openid-configuration`; the older `/api/login/redirect` and `/api/login/verify` flow has been removed from this branch.

It is a good fit when:
- multiple applications need to share one user system
- you want SSO-style login without building OIDC, token, and session management from scratch
- your backend is written in Go and you want Go-based integration examples plus management-style user lookup APIs

## Features

- Multiple login providers
- OIDC provider + JWT access and ID tokens
- CIAM/IAM foundation for organizations, organization admin management, inbound SCIM user/group provisioning, external identities, flow hooks, and installable plugins
- Redis-backed session management
- Avatar upload
- Admin console
- User activity statistics
- Go SDK
- Docker / Docker Compose deployment

For the CIAM/IAM extension roadmap, see [docs/ciam-iam-plugin-architecture.md](docs/ciam-iam-plugin-architecture.md).

## Repository Layout

```text
mkauth/
├── server/        # Go backend service
├── web/           # End-user login UI
├── admin-web/     # Admin console frontend
├── client/        # Go SDK
├── quickstart/    # Docker Compose starter files
└── tools/         # Utility scripts
```

## Quick Start

### 1. Start with Docker Compose

```bash
cd quickstart
docker compose up -d --build
```

If you want to use a prebuilt image instead of building locally:

```bash
cd quickstart
docker compose -f docker-compose.release.yml up -d
```

Default endpoints:
- OIDC demo SPA: `http://127.0.0.1:3000`
- User entry: `http://127.0.0.1:8080`
- Admin console: `http://127.0.0.1:8081`
- MySQL: `127.0.0.1:3306`
- Redis: `127.0.0.1:6379`
- MinIO API: `http://127.0.0.1:9002`
- MinIO Console: `http://127.0.0.1:9003`

Notes:
- `quickstart/config.yaml` enables `account` login only by default.
- `quickstart/config.yaml` also enables OIDC and preconfigures a public client named `demo-spa` for the bundled PKCE demo.
- `quickstart/config.yaml` also preconfigures a confidential client named `demo-backend` for the Go backend callback example under [client/example](client/example/README.md).
- `auth_admin.enabled` is `false` in the quickstart config.
- `quickstart/docker-compose.yml` builds the current checkout so the quickstart always matches this branch.
- `quickstart/docker-compose.sqlite.yml` builds the current checkout too, but uses SQLite instead of MySQL for a smaller local stack.
- `quickstart/docker-compose.release.yml` pulls `ghcr.io/minkicc/auth` directly and is the better option for other users consuming published releases.
- `quickstart/docker-compose.sqlite.release.yml` pulls the published image too, but uses SQLite for the smallest release quickstart stack.
- If you want anonymous pulls from GHCR, set the published container package visibility to `public` in GitHub.

### 2. Enable the admin console

Generate a bcrypt hash for the admin password:

```bash
cd tools
go run hashpwd.go -password "YourStrongPassword"
```

Put the generated hash into your config:

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

Then restart the service.

## CI/CD: Automatic Docker Images

The repository includes a GitHub Actions workflow at `.github/workflows/docker-publish.yml` so GitHub can build and publish Docker images for you.

### What it does

- Pull requests: run a Docker build check only, without pushing an image
- Push to `main`: build multi-arch images and push to GitHub Container Registry
- Push a tag like `v1.2.3`: push versioned tags such as `1.2.3`, `1.2`, plus `sha-*`
- Manual trigger: you can also run the workflow from the GitHub Actions page with `workflow_dispatch`

### Default image registry

By default, the workflow publishes to GitHub Container Registry:

```text
ghcr.io/<owner>/<repo>
```

No extra secret is needed for GHCR. The workflow uses GitHub's built-in `GITHUB_TOKEN`.

### Optional Docker Hub publishing

If you also want to publish to Docker Hub, configure these repository settings:

- Actions variable: `DOCKERHUB_NAMESPACE`
- Actions secret: `DOCKER_HUB_USERNAME`
- Actions secret: `DOCKER_HUB_TOKEN`

After that, the same workflow will push the image to:

```text
<DOCKERHUB_NAMESPACE>/<repo>
```

### Recommended release flow

1. Merge code into `main`
2. GitHub automatically publishes `ghcr.io/<owner>/<repo>:latest`
3. Create a git tag such as `v1.2.3`
4. GitHub automatically publishes stable version tags for deployment

This setup is a good default for other teams because pull requests get build verification first, while `main` and release tags produce ready-to-use Docker images automatically.

### First-time setup checklist

1. Push this branch to GitHub so Actions can run
2. Confirm the `Docker` workflow succeeds on `main`
3. Open the generated package in GitHub Packages and set visibility to `public` if you want anonymous pulls
4. Pull-test the image with `docker pull ghcr.io/<owner>/<repo>:latest`

### Release commands

```bash
git checkout main
git pull
git tag v1.2.3
git push origin v1.2.3
```

For users who only want to deploy MKAuth, a prebuilt-image flow is usually better than asking them to run a local Docker build. This repository now supports both patterns:

- Development / branch verification: `quickstart/docker-compose.yml`
- Minimal local startup with SQLite: `quickstart/docker-compose.sqlite.yml`
- Release / consumer deployment: `quickstart/docker-compose.release.yml`
- Minimal release startup with SQLite: `quickstart/docker-compose.sqlite.release.yml`

## Local Development

### Backend

```bash
cd server
cp config/config.yaml.example config/config.yaml
go run . -config ./config/config.yaml -web ../web/dist -admin-web ../admin-web/dist
```

### User web app

```bash
cd web
npm install
npm run dev
```

### Admin web app

```bash
cd admin-web
npm ci
npm run dev
```

The repository includes `.nvmrc`, so running `nvm use` at the root is recommended.

## Core Configuration

See [server/config/config.yaml.example](server/config/config.yaml.example) for the full example.

### Database and Redis

```yaml
db:
  # Optional. If omitted and the MySQL fields below are empty,
  # MKAuth defaults to SQLite at data/mkauth.sqlite3.
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

If you do not configure MySQL, MKAuth now starts with SQLite by default and stores data in `data/mkauth.sqlite3`. You can also set `db.driver: sqlite` explicitly and override the file location with `db.sqlite_path`.

### Plugin runtime

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

There are now two plugin delivery modes:

- Configured HTTP actions from `plugins.http_actions`
- Local installable plugin packages loaded from `plugins.directories`

There are also two remote distribution paths:

- Catalog-driven installation from `plugins.catalogs`
- Direct admin-side URL installation for a remote ZIP package

For safer production rollout, restrict remote sources with:

- `plugins.allowed_catalog_hosts`
- `plugins.allowed_download_hosts`
- `plugins.allowed_action_hosts`

These host allowlists support exact hosts, `host:port`, `.example.com`, and `*.example.com`. A catalog entry can only point to the same host as the catalog itself, or to an explicitly allowed download host.

Remote plugin downloads and plugin HTTP Actions also reject loopback, private, link-local, multicast, and unspecified IP addresses by default. Keep `allow_private_networks: false` in production unless your plugin catalog, ZIP packages, or HTTP Action endpoints are intentionally served from a trusted private network.

For local packages, zip a directory that contains `mkauth-plugin.yaml` and install it from the admin plugin page. A local `flow_action` plugin can carry its own runtime `http_action` block in the manifest, so it does not require an extra main-config entry.

The admin console previews uploaded ZIP packages before installation. The preview shows the parsed manifest, package SHA-256, signature status, requested permissions, whether the plugin will replace an existing install, and which saved config keys will be preserved or dropped.

Local manifests must declare their runtime permissions. HTTP actions need `network:http_action`, and every hook event needs its matching `hook:<event>` permission, for example `hook:before_token_issue`. If `plugins.allowed_permissions` is not empty, MKAuth rejects plugins that request permissions outside that allowlist.

Local manifests can also declare `config_schema`. The admin console reads that schema, stores values in `mkauth-plugin.state.yaml`, and reloads the runtime after saving. For local HTTP Action plugins, saved config can override `url`, `secret`, `secret_env`, `timeout_ms`, and `fail_open`.

If you want signed packages, add `trusted_signers` and set `require_signature: true`. MKAuth verifies `mkauth-plugin.sig` against the raw manifest content and shows signature status plus the uploaded package SHA-256 fingerprint in the admin UI.

Plugin install, enable, disable, replace, and uninstall operations are written to `mkauth-plugin.audit.jsonl` in the plugin directory. Replace/uninstall operations also create rollback snapshots under `.mkauth-plugin-backups`, and restore validates the backup against the current signature, permission, and host policies before activation.

Catalog responses are annotated with local installation state, including the installed version, installed package SHA-256, and whether the catalog entry appears updateable. The admin console uses this to show install, update, or reinstall actions directly from the catalog table. Replacing a plugin preserves its enabled/disabled state and any saved config keys that still exist in the new manifest.

You can generate keys and sign manifests with the bundled helper under [tools](tools/README.md):

```bash
cd tools
go run ./pluginsign genkey -key-id mkauth-dev -out-private ./plugin-signing.key.pem -out-public ./plugin-signing.pub
go run ./pluginsign sign -manifest ../examples/plugins/http-claims-action/mkauth-plugin.yaml -private-key ./plugin-signing.key.pem -key-id mkauth-dev
```

Useful endpoints:

- Public plugin discovery: `GET /api/plugins`
- Admin plugin management: `GET /admin-api/plugins`
- Admin plugin audit: `GET /admin-api/plugins/audit`
- Admin plugin backups: `GET /admin-api/plugins/backups`
- Admin plugin config: `GET /admin-api/plugins/:id/config`
- Admin plugin preview: `POST /admin-api/plugins/preview`
- Admin plugin install: `POST /admin-api/plugins/install`
- Admin plugin catalog: `GET /admin-api/plugins/catalog`
- Admin plugin install from catalog: `POST /admin-api/plugins/install-catalog`
- Admin plugin install from URL: `POST /admin-api/plugins/install-url`
- Admin plugin restore: `POST /admin-api/plugins/restore`
- Admin plugin config update: `PATCH /admin-api/plugins/:id/config`

See [examples/plugins/http-claims-action](examples/plugins/http-claims-action/README.md) for a self-contained local plugin example, and [examples/plugins/catalog.yaml](examples/plugins/catalog.yaml) for a catalog example.

### CIAM/IAM organization management

After enabling the admin console, open the `Organizations` menu to manage B2B tenants. The admin UI can create and edit organizations, attach verified email domains, assign existing users to organizations with lightweight role names, and configure Enterprise OIDC plus Enterprise SAML providers per organization.

The organization ID or slug can be used in the `:id` path segment. Organizations are not hard-deleted in this first version; set their status to `inactive` when they should no longer be used.

Useful admin endpoints:

- Organization list/create: `GET /admin-api/organizations`, `POST /admin-api/organizations`
- Organization detail/update: `GET /admin-api/organizations/:id`, `PATCH /admin-api/organizations/:id`
- Organization domains: `GET /admin-api/organizations/:id/domains`, `POST /admin-api/organizations/:id/domains`
- Domain update/delete: `PATCH /admin-api/organizations/:id/domains/:domain`, `DELETE /admin-api/organizations/:id/domains/:domain`
- Organization memberships: `GET /admin-api/organizations/:id/memberships`, `POST /admin-api/organizations/:id/memberships`
- Membership update/delete: `PATCH /admin-api/organizations/:id/memberships/:user_id`, `DELETE /admin-api/organizations/:id/memberships/:user_id`
- Organization groups: `GET /admin-api/organizations/:id/groups`, `POST /admin-api/organizations/:id/groups`
- Group detail/update/delete: `GET /admin-api/organizations/:id/groups/:group_id`, `PATCH /admin-api/organizations/:id/groups/:group_id`, `DELETE /admin-api/organizations/:id/groups/:group_id`
- Organization identity providers: `GET /admin-api/organizations/:id/identity-providers`, `POST /admin-api/organizations/:id/identity-providers`
- Identity provider update/delete: `PATCH /admin-api/organizations/:id/identity-providers/:provider_id`, `DELETE /admin-api/organizations/:id/identity-providers/:provider_id`

The admin UI can also manage manual organization groups. Group members automatically project the group's `role_name` into organization membership `org_roles`, while SCIM-managed groups stay read-only in the same view.

When a user has an active organization membership and the downstream OIDC client requests `profile`, MKAuth can include `org_id`, `org_slug`, `org_roles`, and `org_groups` in the ID Token and `/oauth2/userinfo`.

Enterprise login can now be managed in two ways:

- Static bootstrap via `iam.enterprise_oidc` and `iam.enterprise_saml` in YAML
- Runtime management from the admin console under `Organizations -> Enterprise Login`

Each enterprise identity provider also supports lightweight multi-IdP policy fields:

- `priority`: lower numbers sort earlier
- `is_default`: marks the preferred provider for the organization
- `auto_redirect`: when HRD matches multiple providers, jump directly to the preferred provider instead of showing a chooser

Enterprise OIDC providers keep their `client_secret` stored but hidden from admin API responses. Enterprise SAML providers can be configured with either `idp_metadata_url` or inline `idp_metadata_xml`, together with optional attribute mapping fields such as `email_attribute`, `username_attribute`, and `display_name_attribute`.

Providers created from the admin console are stored in the database, and saving changes triggers an in-process reload so enterprise login routes become available immediately without restarting MKAuth.

When an organization has at least one verified domain plus enterprise identity providers, the end-user login page can now perform HRD (Home Realm Discovery) from a work email address. The recommended public discovery endpoint is:

- `GET /api/enterprise/discover?email=user@example.com`

For domain-first flows, you can also use:

- `GET /api/enterprise/discover?domain=example.com`

The response includes the matched organization plus one or more enterprise identity providers for that domain. Each provider carries `provider_type`, so the login page can route to Enterprise OIDC or Enterprise SAML automatically. The login page uses this to auto-redirect when a single provider is matched, or when the preferred provider has `auto_redirect: true`; otherwise it narrows the SSO choices using the organization's default and priority ordering.

If a downstream OIDC client already knows the user's work email, it can pass `login_hint=user@example.com` to `/oauth2/authorize`. MKAuth now forwards that hint to the login page and automatically triggers enterprise provider discovery from it.

If the downstream OIDC client only knows the organization domain, it can instead pass `domain_hint=example.com` to `/oauth2/authorize`. MKAuth forwards that hint too and performs domain-based enterprise provider discovery automatically.

### Inbound SCIM provisioning

MKAuth can expose SCIM 2.0 Users and Groups endpoints so enterprise directories such as Okta, Entra ID, or Google Workspace can provision users and group-derived roles into an organization.

Configure one inbound SCIM connection per enterprise directory:

```yaml
iam:
  scim_inbound:
    - enabled: true
      slug: "acme-scim"
      name: "Acme SCIM"
      organization_id: "org_acme000000000000"
      bearer_token_hash: "$2a$10$..."
```

Use `tools/hashpwd.go` to generate the bcrypt token hash:

```bash
cd tools
go run hashpwd.go -password "YOUR_LONG_RANDOM_SCIM_TOKEN"
```

Point the enterprise directory at:

```text
https://auth.example.com/api/scim/v2
```

Supported SCIM endpoints:

- Discovery: `GET /api/scim/v2/ServiceProviderConfig`, `GET /api/scim/v2/ResourceTypes`, `GET /api/scim/v2/Schemas`
- User list/create: `GET /api/scim/v2/Users`, `POST /api/scim/v2/Users`
- User read/replace/patch/delete: `GET /api/scim/v2/Users/:id`, `PUT /api/scim/v2/Users/:id`, `PATCH /api/scim/v2/Users/:id`, `DELETE /api/scim/v2/Users/:id`
- Group list/create: `GET /api/scim/v2/Groups`, `POST /api/scim/v2/Groups`
- Group read/replace/patch/delete: `GET /api/scim/v2/Groups/:id`, `PUT /api/scim/v2/Groups/:id`, `PATCH /api/scim/v2/Groups/:id`, `DELETE /api/scim/v2/Groups/:id`

SCIM Users creates or updates MKAuth users, links them through `external_identities` with `provider_type=scim`, and syncs organization membership status plus lightweight role names. `DELETE /Users/:id` and `active=false` disable the MKAuth user and mark the organization membership as disabled.

SCIM Groups map enterprise directory groups into `organization_groups` and lightweight organization roles. Group `displayName` is normalized into a role name, for example `Engineering Team` becomes `engineering-team`. When group members change or a group is deleted, MKAuth recalculates only the roles managed by SCIM groups and preserves other manually assigned roles. The same group data is now visible in the admin console and can flow into the `org_groups` OIDC claim.

### Storage

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

Cloudflare R2 can be used with the dedicated `r2` provider:

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

See [docs/cloudflare.md](docs/cloudflare.md) for Cloudflare deployment notes and the R2 configuration example.

### Enabled login providers

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

Only enable the providers you really plan to expose.

### OIDC client configuration

If you want to integrate through standard OIDC, configure `oidc.clients`:

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

When enabled, MKAuth exposes these standard endpoints:
- `/.well-known/openid-configuration`
- `/oauth2/authorize`
- `/oauth2/token`
- `/oauth2/logout`
- `/oauth2/userinfo`
- `/oauth2/jwks`

OIDC `sub` uses MKAuth's stable internal user ID, not the login username. New users receive IDs such as `usr_8m3kq7p2x9zc4vna`; regular account usernames are returned separately as `preferred_username` / `username` when available.

### Trusted backend client

On this branch, `auth_trusted_clients` is only used for legacy management-style `/api` calls such as fetching users by ID or batch-reading users. It is no longer part of the login callback flow:

```yaml
auth_trusted_clients:
  - client_id: "myapp"
    client_secret: "$2a$10$..."
    allowed_ips:
      - "*"
    scopes:
      - "read:users"
```

`client_secret` should also be stored as a bcrypt hash.

## Recommended Integration Patterns

On this branch, MKAuth is OIDC-first.

### Pattern 1: OIDC Authorization Code + PKCE

This is the recommended path for web apps, SPAs, mobile apps, and multi-language backends.

#### Flow

1. Read `/.well-known/openid-configuration`
2. Redirect the browser to `/oauth2/authorize`
3. The user signs in through MKAuth
4. MKAuth redirects back to your `redirect_uri` with an OIDC `code`
5. Exchange that code at `/oauth2/token` for `access_token` and `id_token`
6. Validate the `id_token` with `/oauth2/jwks`, or call `/oauth2/userinfo`

Additional notes:
- the MKAuth login UI now maintains its own `oidc_session` browser session
- `/oauth2/authorize` no longer depends on the older `refreshToken` cookie to identify the signed-in user

#### Authorization example

```text
GET /oauth2/authorize?client_id=demo-spa&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&response_type=code&scope=openid%20profile%20email&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=abc123&nonce=n-0S6_WzA2Mj
```

#### Token exchange example

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'client_id=demo-spa' \
  --data-urlencode 'code=YOUR_CODE' \
  --data-urlencode 'redirect_uri=https://app.example.com/callback' \
  --data-urlencode 'code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
```

### Pattern 2: use MKAuth browser session APIs

This is useful when your login page is hosted by MKAuth itself, or when your frontend can call MKAuth in the same browser context and reuse the `oidc_session` cookie.

If your app is on another domain or you want a standard third-party login contract, prefer Pattern 1 and use OIDC Authorization Code + PKCE.

Common endpoints:
- `GET /api/providers`
- `GET /api/enterprise/providers`
- `GET /api/enterprise/discover`
- `GET /api/enterprise/oidc/providers`
- `GET /api/enterprise/oidc/:slug/login`
- `GET /api/enterprise/oidc/:slug/callback`
- `GET /api/enterprise/saml/:slug/login`
- `GET /api/enterprise/saml/:slug/metadata`
- `GET /api/enterprise/saml/:slug/acs`
- `POST /api/enterprise/saml/:slug/acs`
- `POST /api/account/register`
- `POST /api/account/login`
- `POST /api/email/login`
- `POST /api/phone/login`
- `GET /api/browser-session`
- `POST /api/logout`
- `GET /api/user`

When CIAM/IAM organization data exists and the downstream OIDC client requests `profile`, MKAuth can also include `org_id`, `org_slug`, `org_roles`, and `org_groups` in the ID Token and `/oauth2/userinfo`.

Example account login request:

```bash
curl -X POST http://localhost:8080/api/account/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"demo123"}'
```

Example response:

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

These `/api` login endpoints now establish an `oidc_session` browser session only. They do not return a legacy `/api` bearer token, and this branch does not expose `POST /api/token/refresh`.

Follow-up calls can authenticate in one of two ways:

```text
1. Same-browser requests with the `oidc_session` cookie
2. Authorization: Bearer <oidc-access-token>
```

If you need seamless token renewal in a browser app, prefer the standard OIDC authorization code flow with PKCE so MKAuth can reuse its `oidc_session` browser session.

#### Input normalization and browser-session write rules

MKAuth now normalizes user identifiers consistently before duplicate checks, login checks, and rate limiting:

- Account `username`: trimmed, length `3-64`, allowed characters are letters, digits, `.`, `_`, `@`, `-`, and it must start and end with a letter or digit
- Email: trimmed and lowercased before registration, login, resend-verification, and password-reset flows
- Phone: separators such as spaces, `-`, `.`, `(`, `)` are removed, with an optional leading `+`, and the final normalized value must contain `7-15` digits

`user_id` is no longer a login identifier. It is an opaque internal ID generated as `usr_` plus 16 readable random characters, and it is the value used as the OIDC subject. For username/password accounts, the submitted `username` is stored in a separate account mapping and returned as `username` in `/api` responses.

Email and SMS sending flows are rate-limited by normalized identifier plus client IP. This applies to email registration, resend-verification, and password-reset initiation, and to phone pre-registration, resend-verification, login-code sending, and password-reset initiation.

POST endpoints that create an `oidc_session` browser session reject explicit cross-origin browser requests. If a browser sends a mismatched `Origin`, mismatched `Referer`, or `Sec-Fetch-Site: cross-site` / `same-site`, MKAuth returns `403`. Non-browser server-side calls that do not send browser origin metadata are still accepted for compatibility.

When a request is authenticated by the browser `oidc_session` cookie, state-changing `/api` endpoints also require `Origin` or `Referer` to match the MKAuth issuer/origin. This applies to routes such as logout, password change, profile update, avatar mutation, and session termination. Calls authenticated with `Authorization: Bearer <access_token>` do not need this browser-only same-origin check.

Example `curl` logout using a browser session cookie:

```bash
curl -X POST http://localhost:8080/api/logout \
  -H 'Origin: http://localhost:8080' \
  -b 'oidc_session=YOUR_BROWSER_SESSION'
```

## Go SDK

The Go SDK under `client/auth` is now best treated as a helper for MKAuth management-style `/api` calls. It is not the recommended login integration path on this branch.

### Install

```bash
go get minki.cc/mkauth/client
```

### Protect business APIs

On this branch, `client.AuthRequired()` is no longer the recommended way to protect business resource APIs.

Recommended approach:
- read `/.well-known/openid-configuration`
- load `jwks_uri` with a standard OIDC / OAuth2 JWT library
- validate access tokens against `issuer`, `audience`, and signature

Concrete example:
- [client/example/resource-server/main.go](client/example/resource-server/main.go)
- [client/example/resource-server/README.md](client/example/resource-server/README.md)
- [client/oidcresource/README.md](client/oidcresource/README.md)

### Fetch current user

```go
user, err := client.GetUserInfo(accessToken)
```

This call targets MKAuth's management-style `/api/user` endpoint.

Use it when you intentionally call MKAuth's `/api` endpoints directly and authenticate with either:
- an `oidc_session` browser session, or
- a standard OIDC access token in `Authorization: Bearer <access_token>`

If your app signs users in through standard OIDC, prefer `/oauth2/userinfo` for profile reads and see the Go backend callback example under [client/example](client/example/README.md).

### Fetch one user or many users

These calls require a configured trusted client and matching scopes:

```go
client := auth.NewAuthClient("http://localhost:8080", "myapp", "your-client-secret")

user, err := client.GetUserInfoById(accessToken, "user-001")
users, err, statusCode := client.GetUsersInfo(accessToken, []string{"user-001", "user-002"})
```

### Token renewal

`client.RefreshToken()` and `POST /api/token/refresh` are not available on this branch.

Renew tokens by running a fresh OIDC authorization code flow against `/oauth2/authorize` and `/oauth2/token`.

### Local self-signed TLS debugging

```go
client.UseInsecureTLS()
```

Only use this in local or test environments.

## Useful Endpoints

### Auth endpoints

- `GET /api/providers`
- `POST /api/account/register`
- `POST /api/account/login`
- `POST /api/email/login`
- `POST /api/phone/login`
- `POST /api/logout`

### User endpoints

- `GET /api/user`
- `GET /api/user/:id`
- `POST /api/users`
- `PUT /api/user`
- `POST /api/avatar/upload`
- `DELETE /api/avatar`
- `GET /api/sessions`

### Ops endpoints

- `GET /health`
- `GET /metrics`

## Integration Notes

- Always use HTTPS in production.
- Restrict the admin console with `allowed_ips`.
- Never trust a frontend-provided `user_id`; always derive identity from token validation.
- Only expose the providers you truly need.
- `storage_public_url.attatch` must be reachable by your frontend, otherwise avatar URLs will not render correctly.

## Additional Docs

- Chinese guide: [README-zh.md](README-zh.md)
- Go SDK guide: [client/README.md](client/README.md)
- Quickstart guide: [quickstart/README.md](quickstart/README.md)

## License

Released under the MIT License. See [LICENSE.txt](LICENSE.txt).
