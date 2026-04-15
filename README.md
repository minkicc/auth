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
  jwt:
    issuer: "mkauth"
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

### Pattern 2: call MKAuth APIs from your own frontend

This is useful when you already have your own login UI and only want the authentication backend.

Common endpoints:
- `GET /api/providers`
- `POST /api/account/register`
- `POST /api/account/login`
- `POST /api/email/login`
- `POST /api/phone/login`
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
  "user_id": "demo",
  "token": "access-token",
  "nickname": "demo",
  "avatar": "",
  "expire_time": 7200000000000
}
```

After login, attach the returned token like this:

```text
Authorization: Bearer <access-token>
```

These `/api` login endpoints now return a short-lived access token only. This branch does not expose `POST /api/token/refresh`.

If you need seamless token renewal in a browser app, prefer the standard OIDC authorization code flow with PKCE so MKAuth can reuse its `oidc_session` browser session.

## Go SDK

The Go SDK under `client/auth` still mainly targets the older `/api` JWT endpoints. It can remain useful for management-style APIs or local transition work, but it is not the recommended OIDC integration path on this branch.

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

### Fetch current user

```go
user, err := client.GetUserInfo(accessToken)
```

This call targets MKAuth's management-style `/api/user` endpoint.

Use it when you are still calling the older `/api` login endpoints directly.

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
