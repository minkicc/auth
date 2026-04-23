# CIAM/IAM Plugin Architecture

MKAuth's current core is an OIDC-first authentication service. The CIAM/IAM path should keep that core small and add extension points around it instead of turning every integration into hard-coded login logic.

## Goals

- Keep existing OIDC, browser session, and local login flows stable.
- Support B2B CIAM capabilities such as organizations, enterprise SSO, domain discovery, and directory provisioning.
- Make custom business logic possible through hooks/actions without requiring custom forks.
- Avoid runtime Go shared-object plugins because they are brittle across platforms, build modes, and container targets.

## Plugin Types

### Identity Connectors

Identity connectors authenticate users against upstream identity providers and link the upstream subject to MKAuth's internal `usr_...` user ID.

Initial connectors should be:

- `enterprise_oidc`
- `enterprise_saml`
- `ldap_federation` or `ldap_sync`

The current Google and Weixin integrations can be migrated later onto the same `external_identities` model.

### Flow Actions

Flow actions run at stable points in the authentication lifecycle:

- `pre_register`
- `post_register`
- `pre_authenticate`
- `post_authenticate`
- `before_token_issue`
- `before_userinfo`
- `post_logout`

These hooks are intended for custom claims, risk checks, automatic organization assignment, audit fanout, and profile enrichment.

## Installable Plugin Runtime

The runtime now supports two delivery styles without requiring Go `.so` plugins:

- Configured HTTP actions under `plugins.http_actions`
- Local installable plugin packages loaded from `plugins.directories`
- Catalog-based remote installation from `plugins.catalogs`
- Direct URL installation for remote ZIP packages through the admin API

Example runtime configuration:

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
```

Each local plugin directory must contain one of these manifest files:

- `mkauth-plugin.yaml`
- `plugin.yaml`
- `plugin.yml`

Example local plugin manifest:

```yaml
id: "claims-enricher"
name: "Claims Enricher"
version: "0.1.0"
type: "flow_action"
permissions:
  - "hook:before_token_issue"
  - "hook:before_userinfo"
  - "network:http_action"
config_schema:
  - key: "url"
    label: "HTTP Action URL"
    type: "url"
    required: true
    default: "https://actions.example.com/mkauth"
  - key: "timeout_ms"
    label: "Timeout (ms)"
    type: "integer"
    default: "3000"
  - key: "fail_open"
    label: "Fail Open"
    type: "boolean"
    default: "false"
events:
  - "before_token_issue"
  - "before_userinfo"
http_action:
  url: "https://actions.example.com/mkauth"
  secret_env: "MKAUTH_CLAIMS_SECRET"
  timeout_ms: 3000
  fail_open: false
```

Optional detached signature file beside the manifest:

```yaml
key_id: "mkauth-dev"
algorithm: "ed25519"
signature: "BASE64_SIGNATURE_OF_RAW_MANIFEST_CONTENT"
```

For local `flow_action` plugins, the manifest itself carries the runtime execution details through `http_action`, so installation no longer depends on an extra `plugins.http_actions` block in the main config.

Manifest permissions are mandatory for executable capabilities. HTTP actions must declare `network:http_action`, and each hook event must declare a matching `hook:<event>` permission. If `allowed_permissions` is configured, install and reload reject plugins that request permissions outside that server-side allowlist.

`config_schema` makes installed plugins configurable from the admin console. Values are stored in `mkauth-plugin.state.yaml`, sensitive fields are not echoed back by the admin API, and local HTTP Action plugins can use saved config to override `url`, `secret`, `secret_env`, `timeout_ms`, and `fail_open`.

Runtime behavior:

1. Installing a ZIP package copies it into the first configured plugin directory.
2. MKAuth can preview an uploaded ZIP before installation, returning the parsed manifest, package SHA-256, signature status, replacement impact, and config keys that would be preserved or dropped.
3. MKAuth validates the archive structure, per-file limits, manifest schema, declared permissions, and optional signature.
4. MKAuth can also fetch remote plugin catalogs and install ZIP packages directly from a catalog entry or explicit download URL.
5. MKAuth writes `mkauth-plugin.state.yaml` beside the manifest to persist enabled or disabled state and the uploaded package SHA-256 fingerprint.
6. MKAuth appends plugin management operations to `mkauth-plugin.audit.jsonl` in the plugin directory.
7. Replace and uninstall operations create rollback snapshots under `.mkauth-plugin-backups`; restore revalidates signature, permissions, and host policy before activation.
8. Catalog listing responses are annotated with local install state, installed version, installed package SHA-256, and whether an update appears available.
9. Replace/update operations preserve the plugin's enabled/disabled state and saved config keys that still exist in the new manifest.
10. The registry and hook runtime reload in place, so new plugins can start participating in `post_authenticate`, `before_token_issue`, and `before_userinfo` without a process restart.

Signature behavior:

- If `require_signature` is `false`, unsigned local plugins are allowed.
- If a signature file is present, it must match a configured `trusted_signers` key.
- If `require_signature` is `true`, unsigned or untrusted local plugins are rejected at install and reload time.

Operational tooling:

- `tools/pluginsign` can generate an ed25519 key pair
- `tools/pluginsign sign` signs the raw manifest content into `mkauth-plugin.sig`
- `tools/pluginsign verify` validates a signed plugin before upload or rollout

Discovery endpoints:

- Public: `GET /api/plugins`
- Admin: `GET /admin-api/plugins`
- Admin catalog: `GET /admin-api/plugins/catalog`
- Admin audit: `GET /admin-api/plugins/audit`
- Admin backups: `GET /admin-api/plugins/backups`
- Admin config: `GET /admin-api/plugins/:id/config`
- Admin preview: `POST /admin-api/plugins/preview`
- Admin install: `POST /admin-api/plugins/install`
- Admin install from catalog: `POST /admin-api/plugins/install-catalog`
- Admin install from URL: `POST /admin-api/plugins/install-url`
- Admin restore: `POST /admin-api/plugins/restore`
- Admin config update: `PATCH /admin-api/plugins/:id/config`
- Admin enable or disable: `PATCH /admin-api/plugins/:id`
- Admin uninstall: `DELETE /admin-api/plugins/:id`

Remote source trust behavior:

- Catalog URLs can be restricted with `allowed_catalog_hosts`
- Direct ZIP downloads can be restricted with `allowed_download_hosts`
- Plugin HTTP Action endpoints can be restricted with `allowed_action_hosts`
- A catalog plugin entry may only point to the catalog's own host or an explicitly allowed download host
- Redirects are checked against the same host policy so a trusted source cannot silently bounce to an untrusted host
- Loopback, private, link-local, multicast, and unspecified IP addresses are rejected by default for plugin downloads and plugin HTTP Actions
- `allow_private_networks: true` should only be used for explicitly trusted private plugin distribution environments

### Claim Mappers

Claim mappers transform MKAuth user, organization, membership, and group data into OIDC claims. The first useful claims are:

- `org_id`
- `org_slug`
- `roles`
- `groups`
- `tenant`

### Provisioning Connectors

Provisioning connectors synchronize users and group membership from external directories. The first target should be inbound SCIM, where enterprise directories push users into MKAuth.

### Audit Sinks

Audit sinks receive security and lifecycle events, such as login success/failure, user creation, password reset, organization membership changes, and token issuance.

## Foundation Data Model

The first foundation adds these tables:

- `organizations`: customer/workspace/tenant records.
- `organization_domains`: verified domains for home realm discovery.
- `organization_identity_providers`: upstream enterprise IdP configuration shells.
- `external_identities`: upstream provider subject to MKAuth user mapping.
- `organization_memberships`: user membership and role names within organizations.

This is additive and does not change the current `users.user_id` subject contract.

## Enterprise OIDC MVP

The first upstream identity connector is `enterprise_oidc`. Configure providers under `iam.enterprise_oidc`:

```yaml
iam:
  enterprise_oidc:
    - slug: "acme"
      name: "Acme Workforce"
      organization_id: "org_acme000000000000"
      issuer: "https://idp.example.com"
      client_id: "YOUR_ENTERPRISE_OIDC_CLIENT_ID"
      client_secret: "YOUR_ENTERPRISE_OIDC_CLIENT_SECRET"
      redirect_uri: "https://auth.example.com/api/enterprise/oidc/acme/callback"
      scopes:
        - "openid"
        - "profile"
        - "email"
```

Runtime endpoints:

- `GET /api/enterprise/oidc/providers`
- `GET /api/enterprise/oidc/:slug/login`
- `GET /api/enterprise/oidc/:slug/callback`

The login endpoint accepts an optional `return_uri` query parameter. Use a relative URL such as `/oauth2/authorize?...` when enterprise SSO should resume an existing downstream OIDC authorization request after MKAuth creates the browser session.

The callback flow:

1. Exchanges the upstream authorization code at the enterprise IdP token endpoint.
2. Verifies the upstream `id_token` with OIDC discovery and JWKS.
3. Links `(provider_type=oidc, provider_id=:slug, subject=sub)` into `external_identities`.
4. Creates a new internal `usr_...` user when no linked user exists.
5. Adds an organization membership when the provider has `organization_id`.
6. Reuses the existing MKAuth `oidc_session` browser session mechanism.

## Organization Claims

When a user has an active organization membership and the downstream OIDC client requests the `profile` scope, MKAuth adds these claims to the ID Token and `/oauth2/userinfo` response:

- `org_id`: the selected organization ID.
- `org_slug`: the organization slug when the organization record exists.
- `org_roles`: role names from the active organization membership.

The first version selects the earliest active organization membership. A future version should add explicit organization selection for users who belong to multiple organizations.

## Recommended Delivery Order

1. Add the foundation tables and hook boundary.
2. Implement `enterprise_oidc` as the first upstream enterprise connector.
3. Add claim mapping for organization and membership claims.
4. Add inbound SCIM for user and group provisioning.
5. Add SAML and LDAP connectors after the OIDC path is stable.

## Non-Goals For The First Version

- Dynamic Go `.so` plugins.
- Full ABAC policy engine.
- Downstream SAML IdP support.
- Complete workforce IAM parity with Keycloak, Okta, Auth0, or ZITADEL.

Those can be revisited after the organization and enterprise OIDC path is proven.

## References

- Keycloak Server Development: https://www.keycloak.org/docs/latest/server_development/index.html
- Keycloak Authorization Services: https://www.keycloak.org/docs/latest/authorization_services/index.html
- Auth0 Actions: https://auth0.com/docs/customize/actions
- Okta Inline Hooks: https://developer.okta.com/docs/concepts/inline-hooks/
- Okta SCIM Provisioning: https://developer.okta.com/docs/guides/scim-provisioning-integration-overview/main/
- ZITADEL Actions: https://zitadel.com/docs/apis/actions/introduction
- Go plugin package notes: https://pkg.go.dev/plugin
