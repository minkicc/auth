# MKAuth Roadmap

This document turns the current CIAM/IAM direction into an execution-oriented plan. It reflects the project status as of 2026-04-25.

For a GitHub Projects-ready breakdown with suggested issue cards, see [docs/project-board.md](project-board.md).

## Current Stage

MKAuth has already moved beyond a simple authentication service and into an extensible B2B CIAM platform:

- downstream OIDC provider
- enterprise federation through OIDC, SAML, and LDAP/AD
- organizations, domains, memberships, and groups
- inbound SCIM Users and Groups
- organization-aware claims and client-level organization access policy
- installable plugin runtime, HTTP actions, manifest-based claim mappers, admin-managed database claim mappers, and audit webhook sinks
- admin-managed OIDC clients, service-account tokens, delegated organization admins, secret encryption, reseal, and security audit operations

The project is not yet a full workforce IAM suite. The biggest remaining gaps are:

- first-class RBAC and policy enforcement
- richer claim mapper lifecycle features such as ordering, import/export, and reusable templates
- richer service-account lifecycle management beyond token issuance/introspection/revocation
- broader workforce-style delegated administration beyond organization-scoped admin access
- MFA / WebAuthn / passkeys

## Positioning

Recommended external positioning:

- extensible B2B CIAM platform
- enterprise SSO and organization-aware authentication core
- OIDC-first auth platform with upstream enterprise federation

Recommended not to claim yet:

- full IAM suite
- full workforce IAM
- complete RBAC/ABAC/policy engine
- complete MFA/passkey platform

## Four-Week Plan

### Week 1: 2026-04-27 to 2026-05-03

Goal: introduce first-class organization roles and permissions.

- add `organization_roles`
- add `organization_role_permissions`
- add `organization_role_bindings`
- implement unified organization authorization resolver

Exit criteria:

- roles can be created under an organization
- roles can carry permission keys
- effective roles can be resolved from direct membership bindings and group bindings

### Week 2: 2026-05-04 to 2026-05-10

Goal: turn organization roles into enforceable OIDC policy.

- add admin APIs for role management
- add admin UI for role management
- support `all_of` and `any_of` organization policy rules
- support scope-aware organization access policy

Exit criteria:

- a client can require stronger organization authorization per requested scope
- admin can manage organization roles without editing YAML

### Week 3: 2026-05-11 to 2026-05-17

Goal: make actions and claims feel like a platform, not just hook points.

- add `pre_register`, `pre_authenticate`, and `post_logout` lifecycle hooks
- apply lifecycle hooks consistently across account, email, phone, social, and enterprise browser-login flows
- add database-managed claim mapper CRUD in the admin UI
- add per-client and per-organization claim mapper targeting from admin-managed state

Exit criteria:

- claim behavior can be customized per organization or per client from admin-managed state
- more of the auth lifecycle can be extended without modifying core code

### Week 4: 2026-05-18 to 2026-05-24

Goal: fill in the most important IAM-shaped platform gaps.

- add `client_credentials`
- add service account support
- add confidential-client token introspection for resource services
- add access-token revocation
- expand audit sinks beyond admin security audit if needed
- add first delegated organization admin model

Exit criteria:

- machine-to-machine access works for confidential clients
- resource services can introspect their own access tokens without exposing token state to public clients
- access tokens can be revoked before expiry and are rejected by MKAuth online validation paths
- admin security audit events can be sent to external systems
- organization-scoped admin duties do not require full global admin access

## Backlog

### P1: Authorization Core

#### Issue: Add first-class organization roles and permissions

Goals:

- add `organization_roles`
- add `organization_role_permissions`
- support enable/disable lifecycle

Acceptance criteria:

- admin can create a role under an organization
- role supports multiple permission keys
- disabled roles are excluded from effective authorization

#### Issue: Add organization role bindings for members and groups

Goals:

- add direct member-to-role binding
- add group-to-role binding
- support merged effective role resolution

Acceptance criteria:

- a membership can be bound to a role
- a group can be bound to a role
- effective roles are merged and deduplicated

#### Issue: Implement organization authorization resolver

Goals:

- centralize role resolution
- centralize permission resolution
- reuse in OIDC, admin APIs, and future middleware

Acceptance criteria:

- results are deterministic
- disabled memberships, groups, and roles are excluded
- existing OIDC claims can be migrated onto this resolver

#### Issue: Add organization role management APIs and UI

Goals:

- expose admin CRUD endpoints
- add role management to the organization admin page

Acceptance criteria:

- admin can manage roles in UI
- validation covers duplicate names/slugs and invalid permission keys

### P2: Policy Execution and Extensibility

#### Issue: Support `all_of` and `any_of` organization policy rules

Goals:

- extend current client organization policy
- keep backward compatibility

Acceptance criteria:

- a client can require all listed roles
- a client can require any listed groups
- existing clients continue to work unchanged

#### Issue: Support scope-aware organization access policies

Goals:

- evaluate policy per requested scope
- allow stronger requirements for sensitive scopes

Acceptance criteria:

- different scopes can require different organization authorization
- authorization failures are deterministic and tested

#### Issue: Deepen configurable claim mapper model

Goals:

- build on manifest-based `claim_mapper` plugins
- add richer admin UI editing and validation
- support admin-managed mapper records in addition to installed plugin manifests

Acceptance criteria:

- admins can configure mappers without editing YAML or rebuilding plugin ZIPs
- mappers remain scoped by client and organization
- existing manifest-based claim mappers continue to work

#### Issue: Add more lifecycle hooks

Goals:

- add `pre_register`
- add `pre_authenticate`
- add `post_logout`

Acceptance criteria:

- hooks can be registered and executed
- timeout and error behavior are defined
- execution traces are visible for troubleshooting

### P3: Platform Maturity

#### Issue: Add `client_credentials` and service accounts

Status: done.

Goals:

- support machine-to-machine access
- define subject semantics for service accounts

Acceptance criteria:

- confidential client can obtain token through `client_credentials`
- scope checks are enforced
- service-account tokens use `svc:<client_id>` by default and are not accepted by `/oauth2/userinfo`
- confidential clients can call `/oauth2/introspect` for their own tokens; public clients are rejected
- clients can call `/oauth2/revoke` to revoke their own access tokens until the original expiry

#### Issue: Add audit sink / webhook sink extension point

Status: done.

Goals:

- let security and lifecycle events be forwarded externally

Acceptance criteria:

- admin security audit events can be sent to webhook sink
- authentication lifecycle events can be explicitly opted into with `auth_lifecycle`
- failures are visible in audit/log output

#### Issue: Add delegated organization admin model

Status: done.

Goals:

- support organization-scoped administrators
- reduce dependence on global admin access

Acceptance criteria:

- org admins can manage org-local resources
- org admins cannot access unrelated organizations
- global-only admin endpoints remain protected from delegated org admins

#### Issue: Research MFA / WebAuthn / passkeys

Goals:

- define next security milestone
- decide whether TOTP or WebAuthn lands first

Acceptance criteria:

- produce technical design
- produce rollout recommendation

## Suggested Release Messaging

Current message that matches the product:

> MKAuth is an extensible B2B CIAM platform that provides enterprise identity federation, organization-aware authentication, inbound SCIM provisioning, downstream OIDC, and plugin-ready identity extension points.

Message to avoid for now:

> full workforce IAM suite
