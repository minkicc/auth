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
