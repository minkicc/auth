# CIAM/IAM Plugin Architecture

MKAuth's current core is an OIDC-first authentication service. The CIAM/IAM path should keep that core small and add extension points around it instead of turning every integration into hard-coded login logic.

## Goals

- Keep existing OIDC, browser session, and local login flows stable.
- Support B2B CIAM capabilities such as organizations, enterprise SSO, domain discovery, and directory provisioning.
- Make custom business logic possible through hooks/actions without requiring custom forks.
- Avoid runtime Go shared-object plugins because they are brittle across platforms, build modes, and container targets.

## Current Implementation Status

Implemented:

- Foundation tables for organizations, organization domains, enterprise identity provider shells, external identities, and organization memberships.
- Flow hook boundaries for `post_authenticate`, `before_token_issue`, and `before_userinfo`.
- Installable plugin runtime with local ZIP packages, catalog installation, URL installation, preview, config schema, signatures, audit log, backups, restore, and in-process reload.
- `enterprise_oidc` as the first upstream enterprise identity connector.
- `enterprise_saml` as the second upstream enterprise identity connector.
- `enterprise_ldap` as the third upstream enterprise identity connector.
- HRD (Home Realm Discovery) from verified organization domains to Enterprise OIDC, Enterprise SAML, and Enterprise LDAP providers.
- Organization-level default provider, provider priority, and optional auto-redirect policy for enterprise provider discovery.
- Organization claim injection into ID Token and `/oauth2/userinfo`, including `org_groups`.
- Downstream OIDC organization pinning through `org_hint`.
- Interactive organization chooser for users who belong to multiple organizations.
- Admin API and admin console page for organization, domain, membership, group, and enterprise identity provider management.
- Inbound SCIM Users and Groups MVP for enterprise directory provisioning into an organization.

Not implemented yet:

- Full role/group/RBAC policy enforcement.

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

## Organization Admin MVP

The admin console now includes an `Organizations` page for B2B tenant operations:

- Create and update organizations.
- Attach, verify, update, and delete organization domains.
- Add existing users as organization members.
- Update membership status and lightweight role names.
- Remove organization memberships.
- Create, update, inspect, and delete manual organization groups.
- Surface SCIM-managed groups in the same admin page as read-only group records.
- Create, update, enable, disable, and delete Enterprise OIDC and Enterprise SAML identity providers per organization.
- Configure per-provider `priority`, `is_default`, and `auto_redirect` policy from the admin console.

The admin API accepts either organization ID or slug in the `:id` path segment:

- `GET /admin-api/organizations`
- `POST /admin-api/organizations`
- `GET /admin-api/organizations/:id`
- `PATCH /admin-api/organizations/:id`
- `GET /admin-api/organizations/:id/domains`
- `POST /admin-api/organizations/:id/domains`
- `PATCH /admin-api/organizations/:id/domains/:domain`
- `DELETE /admin-api/organizations/:id/domains/:domain`
- `GET /admin-api/organizations/:id/memberships`
- `POST /admin-api/organizations/:id/memberships`
- `PATCH /admin-api/organizations/:id/memberships/:user_id`
- `DELETE /admin-api/organizations/:id/memberships/:user_id`
- `GET /admin-api/organizations/:id/groups`
- `POST /admin-api/organizations/:id/groups`
- `GET /admin-api/organizations/:id/groups/:group_id`
- `PATCH /admin-api/organizations/:id/groups/:group_id`
- `DELETE /admin-api/organizations/:id/groups/:group_id`
- `GET /admin-api/organizations/:id/identity-providers`
- `POST /admin-api/organizations/:id/identity-providers`
- `PATCH /admin-api/organizations/:id/identity-providers/:provider_id`
- `DELETE /admin-api/organizations/:id/identity-providers/:provider_id`

Organizations are not hard-deleted in this MVP. Use `inactive` status to disable an organization without destroying tenant history.

## Inbound SCIM Users And Groups MVP

The first provisioning connector is inbound SCIM 2.0 Users and Groups. Configure clients under `iam.scim_inbound`:

```yaml
iam:
  scim_inbound:
    - enabled: true
      slug: "acme-scim"
      name: "Acme SCIM"
      organization_id: "org_acme000000000000"
      bearer_token_hash: "$2a$10$..."
```

Runtime endpoints:

- `GET /api/scim/v2/ServiceProviderConfig`
- `GET /api/scim/v2/ResourceTypes`
- `GET /api/scim/v2/Schemas`
- `GET /api/scim/v2/Users`
- `POST /api/scim/v2/Users`
- `GET /api/scim/v2/Users/:id`
- `PUT /api/scim/v2/Users/:id`
- `PATCH /api/scim/v2/Users/:id`
- `DELETE /api/scim/v2/Users/:id`
- `GET /api/scim/v2/Groups`
- `POST /api/scim/v2/Groups`
- `GET /api/scim/v2/Groups/:id`
- `PUT /api/scim/v2/Groups/:id`
- `PATCH /api/scim/v2/Groups/:id`
- `DELETE /api/scim/v2/Groups/:id`

Provisioning behavior:

1. Authenticates SCIM calls with an inbound bearer token. Production configs should prefer `bearer_token_hash`.
2. Creates MKAuth users with random unusable local passwords.
3. Links the external directory record through `external_identities` with `provider_type=scim`.
4. Syncs organization membership status and lightweight role names.
5. Maps `active=false` and `DELETE /Users/:id` to disabled MKAuth users and disabled organization memberships.
6. Maps SCIM Groups into `organization_groups` and `organization_group_members`.
7. Normalizes group `displayName` into an organization role, such as `Engineering Team` -> `engineering-team`.
8. Recalculates only SCIM-managed group roles when group membership changes, preserving manually assigned membership roles.

This is still a lightweight role-mapping layer, not a full group/RBAC policy engine. MKAuth now exposes first-class `org_groups` claims and delegated manual group administration, but it still does not provide full policy enforcement.

## Enterprise OIDC MVP

The first upstream identity connector is `enterprise_oidc`. Providers can be bootstrapped statically from `iam.enterprise_oidc` or managed dynamically from the admin console.

Static bootstrap example:

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

- `GET /api/enterprise/providers`
- `GET /api/enterprise/discover`
- `GET /api/enterprise/oidc/providers`
- `GET /api/enterprise/oidc/:slug/login`
- `GET /api/enterprise/oidc/:slug/callback`

The login endpoint accepts an optional `return_uri` query parameter. Use a relative URL such as `/oauth2/authorize?...` when enterprise SSO should resume an existing downstream OIDC authorization request after MKAuth creates the browser session.

Runtime admin behavior:

1. The admin console stores Enterprise OIDC providers in `organization_identity_providers`.
2. The client secret stays in stored config but is not echoed back by the admin API.
3. Saving or deleting a provider triggers an in-process `EnterpriseOIDCManager.Reload()`.
4. Enterprise OIDC routes are registered whenever the manager exists, so newly added providers become reachable without restarting the service.

HRD behavior:

1. The public endpoint `GET /api/enterprise/discover?email=...` extracts the email domain.
2. MKAuth looks up a verified record in `organization_domains`.
3. The matched active organization is resolved to one or more runtime enterprise identity providers.
4. Providers are ordered by `is_default`, `auto_redirect`, and ascending `priority`.
5. The login page auto-redirects when exactly one provider is matched, or when the preferred provider has `auto_redirect: true`.
6. Otherwise the login page narrows the provider list in the organization's preferred order.
7. When a downstream OIDC client sends `login_hint`, MKAuth forwards it into the login page and reuses it to trigger HRD automatically.
8. When a downstream OIDC client sends `domain_hint`, MKAuth can skip the email requirement and trigger HRD directly from the hinted organization domain.

The callback flow:

1. Exchanges the upstream authorization code at the enterprise IdP token endpoint.
2. Verifies the upstream `id_token` with OIDC discovery and JWKS.
3. Links `(provider_type=oidc, provider_id=:slug, subject=sub)` into `external_identities`.
4. Creates a new internal `usr_...` user when no linked user exists.
5. Adds an organization membership when the provider has `organization_id`.
6. Reuses the existing MKAuth `oidc_session` browser session mechanism.

The OIDC-specific discovery endpoint `GET /api/enterprise/oidc/discover` remains available for compatibility, but new integrations should prefer the generic enterprise discovery endpoint.

## Enterprise SAML MVP

The second upstream identity connector is `enterprise_saml`. Providers can be bootstrapped statically from `iam.enterprise_saml` or managed dynamically from the admin console.

Static bootstrap example:

```yaml
iam:
  enterprise_saml:
    - slug: "acme-saml"
      name: "Acme SAML"
      organization_id: "org_acme000000000000"
      idp_metadata_url: "https://idp.example.com/metadata"
      entity_id: "https://auth.example.com/api/enterprise/saml/acme-saml/metadata"
      acs_url: "https://auth.example.com/api/enterprise/saml/acme-saml/acs"
      name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      email_attribute: "email"
      username_attribute: "preferred_username"
      display_name_attribute: "displayName"
```

Runtime endpoints:

- `GET /api/enterprise/saml/:slug/login`
- `GET /api/enterprise/saml/:slug/metadata`
- `GET /api/enterprise/saml/:slug/acs`
- `POST /api/enterprise/saml/:slug/acs`

The login endpoint accepts an optional `return_uri` query parameter, just like Enterprise OIDC, so enterprise SSO can resume an existing downstream OIDC authorization request after MKAuth creates the browser session.

Enterprise SAML behavior:

1. Loads IdP metadata from `idp_metadata_url` or inline `idp_metadata_xml`.
2. Generates SP defaults for metadata and ACS from the public MKAuth base URL when explicit values are omitted.
3. Tracks the outbound AuthnRequest through `RelayState` and validates the matching request on ACS.
4. Links `(provider_type=saml, provider_id=:slug, subject=NameID)` into `external_identities`.
5. Creates a new internal `usr_...` user when no linked user exists.
6. Adds an organization membership when the provider has `organization_id`.
7. Reuses the existing MKAuth `oidc_session` browser session mechanism after SAML login succeeds.

## Enterprise LDAP/AD MVP

The third upstream identity connector is `enterprise_ldap`. Providers can be bootstrapped statically from `iam.enterprise_ldap` or managed dynamically from the admin console.

Static bootstrap example:

```yaml
iam:
  enterprise_ldap:
    - slug: "acme-ldap"
      name: "Acme Directory"
      organization_id: "org_acme000000000000"
      url: "ldaps://ldap.example.com:636"
      base_dn: "dc=example,dc=com"
      bind_dn: "cn=svc-bind,ou=system,dc=example,dc=com"
      bind_password: "YOUR_LDAP_BIND_PASSWORD"
      user_filter: "(&(objectClass=person)(uid={username}))"
      group_member_attribute: "memberOf"
      # group_base_dn: "ou=groups,dc=example,dc=com"
      # group_filter: "(|(member={user_dn})(uniqueMember={user_dn})(memberUid={username}))"
      group_identifier_attribute: "entryUUID"
      group_name_attribute: "displayName"
      subject_attribute: "entryUUID"
      email_attribute: "mail"
      username_attribute: "uid"
      display_name_attribute: "displayName"
```

Runtime endpoints:

- `POST /api/enterprise/ldap/:slug/login`

Enterprise LDAP behavior:

1. The login page discovers the organization from a verified domain just like Enterprise OIDC and Enterprise SAML.
2. If the selected enterprise identity source has `provider_type=ldap`, the login page opens an in-page directory username/password form instead of redirecting to an external IdP.
3. MKAuth optionally binds with `bind_dn` and `bind_password`, searches under `base_dn` with `user_filter`, and then binds as the matched user DN to verify credentials.
4. The directory entry is mapped into `subject`, `email`, `preferred_username`, and `display_name` through configurable attribute names.
5. MKAuth links `(provider_type=ldap, provider_id=:slug, subject=...)` into `external_identities`.
6. Creates a new internal `usr_...` user when no linked user exists.
7. Adds an organization membership when the provider has `organization_id`.
8. Optionally syncs directory groups into `organization_groups` by reading `group_member_attribute` such as `memberOf`, or by searching `group_base_dn` with `group_filter`.
9. Recalculates only LDAP-managed membership roles when directory group membership changes, preserving manually assigned or SCIM-managed roles.
10. Reuses the existing MKAuth `oidc_session` browser session mechanism after directory login succeeds.

## Organization Claims

When a user has an active organization membership and the downstream OIDC client requests the `profile` scope, MKAuth adds these claims to the ID Token and `/oauth2/userinfo` response:

- `org_id`: the selected organization ID.
- `org_slug`: the organization slug when the organization record exists.
- `org_roles`: role names from the active organization membership.
- `org_groups`: display names of the active organization's assigned groups.

By default, MKAuth selects the earliest active organization membership. Downstream OIDC clients can now override that by sending `org_hint=<organization_id_or_slug>` to `/oauth2/authorize`. A future version should add an interactive organization chooser for end users who belong to multiple organizations.
By default, MKAuth selects the earliest active organization membership. Downstream OIDC clients can now override that by sending `org_hint=<organization_id_or_slug>` to `/oauth2/authorize`. If no `org_hint` is provided and the browser session belongs to multiple active organizations, MKAuth redirects the user to `/select-organization` so the user can choose the organization interactively. When the downstream client also sends `prompt=none`, MKAuth returns `interaction_required` instead of showing the chooser.

The chooser UI loads `GET /api/user/organizations`, which returns the current user's active organization memberships together with lightweight roles and `org_groups`.

## Recommended Delivery Order

1. Add the foundation tables and hook boundary. Done.
2. Implement `enterprise_oidc` as the first upstream enterprise connector. Done.
3. Add claim mapping for organization and membership claims. Done.
4. Add organization admin APIs and UI. Done.
5. Add inbound SCIM Users provisioning. Done.
6. Add SCIM Groups for group-to-role synchronization. Done.
7. Add manual organization group administration and `org_groups` claims. Done.
8. Add `enterprise_saml` after the OIDC path is stable. Done.
9. Add LDAP connector after the OIDC and SAML paths are stable. Done.

## Non-Goals For The First Version

- Dynamic Go `.so` plugins.
- Full ABAC policy engine.
- Downstream SAML IdP support.
- Complete workforce IAM parity with Keycloak, Okta, Auth0, or ZITADEL.

Those can be revisited after the organization and enterprise identity provider path is proven.

## References

- Keycloak Server Development: https://www.keycloak.org/docs/latest/server_development/index.html
- Keycloak Authorization Services: https://www.keycloak.org/docs/latest/authorization_services/index.html
- Auth0 Actions: https://auth0.com/docs/customize/actions
- Okta Inline Hooks: https://developer.okta.com/docs/concepts/inline-hooks/
- Okta SCIM Provisioning: https://developer.okta.com/docs/guides/scim-provisioning-integration-overview/main/
- ZITADEL Actions: https://zitadel.com/docs/apis/actions/introduction
- Go plugin package notes: https://pkg.go.dev/plugin
