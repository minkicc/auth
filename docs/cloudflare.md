# Cloudflare Deployment Notes

## Current Support Matrix

| Component | Cloudflare target | Current status |
| --- | --- | --- |
| HTTP service | Cloudflare Containers or another container host behind Cloudflare DNS | Compatible with the existing Docker image |
| Object storage | Cloudflare R2 | Supported via `storage.provider: "r2"` |
| Verification email | Cloudflare Email Service | Supported through the REST API |
| SQL database | MySQL or SQLite | Uses the existing project database drivers |
| Session/rate-limit store | Redis-compatible service | Still required |

## R2 Configuration

Create an R2 bucket, for example:

```text
mkauth-avatar
```

Create an R2 S3 API token with object read/write access to that bucket, then configure MKAuth:

```yaml
storage:
  provider: "r2"
  endpoint: "https://<account_id>.r2.cloudflarestorage.com"
  region: "auto"
  accessKeyID: "YOUR_R2_ACCESS_KEY_ID"
  secretAccessKey: "YOUR_R2_SECRET_ACCESS_KEY"
  attatchBucket: "mkauth-avatar"

storage_public_url:
  attatch: "https://assets.example.com"
```

For production, prefer an R2 custom public domain such as `assets.example.com` instead of exposing application assets through temporary or development-only URLs.

## Email Verification Codes

Cloudflare Email Routing only handles inbound routing/forwarding. For MKAuth email login and registration verification codes, use Cloudflare Email Service after onboarding your sending domain in Cloudflare DNS.

```yaml
auth:
  enabled_providers:
    - "email"
  email:
    provider: "cloudflare"
    cloudflare:
      account_id: "YOUR_CLOUDFLARE_ACCOUNT_ID"
      api_token_env: "MKAUTH_CLOUDFLARE_EMAIL_API_TOKEN"
      from: "no-reply@example.com"
```

Create an API token with permission to send emails, expose it to the container through `MKAUTH_CLOUDFLARE_EMAIL_API_TOKEN`, and make sure the `from` address belongs to an onboarded sending domain.

## Recommended Deployment Path Today

Use this path if you want to deploy the current service with minimal code risk:

1. Run the existing Docker image on Cloudflare Containers or another container host proxied by Cloudflare.
2. Point your auth domain to that service.
3. Configure `oidc.issuer` with your public auth origin.
4. Configure storage with R2 as shown above.
5. Use a MySQL-compatible database or the current SQLite mode according to your environment.
6. Use a managed Redis-compatible endpoint for browser sessions, verification codes, and rate limiting.
7. If email login is enabled, configure Cloudflare Email Service or SMTP for outbound verification-code delivery.

Example config starter:

```text
deploy/cloudflare/config.r2.yaml.example
```

## DNS And OIDC Checklist

- Your auth domain must route to the MKAuth HTTPS service.
- `oidc.issuer` must be exactly your public auth origin, including scheme and host.
- OIDC clients must use redirect URIs with exact scheme, host, path, and port matching.
- Google OAuth redirect URL should be `https://<your-auth-domain>/api/google/callback` if Google login is enabled.
- `storage_public_url.attatch` must be reachable by the browser, or avatar URLs will not render.
