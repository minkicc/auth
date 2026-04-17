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
- Redis-backed session management
- Avatar upload
- Admin console
- User activity statistics
- Go SDK
- Docker / Docker Compose deployment

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

### Storage

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
- `POST /api/account/register`
- `POST /api/account/login`
- `POST /api/email/login`
- `POST /api/phone/login`
- `GET /api/browser-session`
- `POST /api/logout`
- `GET /api/user`

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
  "user_id": "demo",
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
