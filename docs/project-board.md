# MKAuth Project Board

This document converts the roadmap into a GitHub Projects-friendly view. Use it when you want to create issue cards, milestones, or a board for the next CIAM/IAM phase.

## Recommended Project Columns

- `Inbox`
- `Ready`
- `In Progress`
- `In Review`
- `Blocked`
- `Done`

Optional labels:

- `epic:authorization`
- `epic:policy`
- `epic:extensibility`
- `epic:platform`
- `priority:p1`
- `priority:p2`
- `priority:p3`

## Suggested Milestones

### Milestone: Authorization Foundation

Target outcome:

- first-class organization roles
- role bindings
- unified authorization resolver

### Milestone: OIDC Policy and Claims

Target outcome:

- richer client organization policy
- scope-aware authorization
- configurable claim mapper

### Milestone: IAM Platform Maturity

Target outcome:

- service accounts
- delegated admin
- audit sink

## Epic 1: Authorization Foundation

### Card 1: Add first-class organization roles and permissions

Labels:

- `epic:authorization`
- `priority:p1`

Suggested body:

```md
## Goals

- add `organization_roles`
- add `organization_role_permissions`
- support enable/disable lifecycle

## Acceptance Criteria

- admin can create a role under an organization
- role supports multiple permission keys
- disabled roles are excluded from effective authorization
```

### Card 2: Add organization role bindings for members and groups

Labels:

- `epic:authorization`
- `priority:p1`

Suggested body:

```md
## Goals

- add direct member-to-role binding
- add group-to-role binding
- support merged effective role resolution

## Acceptance Criteria

- a membership can be bound to a role
- a group can be bound to a role
- effective roles are merged and deduplicated
```

### Card 3: Implement organization authorization resolver

Labels:

- `epic:authorization`
- `priority:p1`

Suggested body:

```md
## Goals

- centralize role resolution
- centralize permission resolution
- reuse in OIDC, admin APIs, and future middleware

## Acceptance Criteria

- results are deterministic
- disabled memberships, groups, and roles are excluded
- existing OIDC claims can migrate to this resolver
```

### Card 4: Add organization role management APIs and UI

Labels:

- `epic:authorization`
- `priority:p1`

Suggested body:

```md
## Goals

- expose admin CRUD endpoints for organization roles
- add organization role management UI

## Acceptance Criteria

- admin can manage roles in the organization page
- validation covers duplicate names/slugs and invalid permission keys
```

## Epic 2: OIDC Policy and Claims

### Card 5: Support all-of and any-of organization policy rules

Labels:

- `epic:policy`
- `priority:p1`

Suggested body:

```md
## Goals

- extend current client organization policy
- support `all_of`
- support `any_of`
- keep backward compatibility

## Acceptance Criteria

- a client can require all listed roles
- a client can require any listed groups
- existing clients continue to work unchanged
```

### Card 6: Support scope-aware organization access policies

Labels:

- `epic:policy`
- `priority:p1`

Suggested body:

```md
## Goals

- evaluate policy per requested scope
- allow stronger requirements for sensitive scopes

## Acceptance Criteria

- different scopes can require different organization authorization
- authorization failures are deterministic and tested
```

### Card 7: Introduce configurable claim mapper model

Labels:

- `epic:extensibility`
- `priority:p2`

Suggested body:

```md
## Goals

- add client-specific claim mapping
- add organization-specific claim mapping
- support static values and context field mapping

## Acceptance Criteria

- mappers apply to `id_token`
- mappers apply to `access_token`
- mappers apply to `/userinfo`
```

### Card 8: Add more lifecycle hooks

Labels:

- `epic:extensibility`
- `priority:p2`

Suggested body:

```md
## Goals

- add `pre_register`
- add `pre_authenticate`
- add `post_logout`

## Acceptance Criteria

- hooks can be registered and executed
- timeout and error behavior are defined
- execution traces are visible for troubleshooting
```

## Epic 3: IAM Platform Maturity

### Card 9: Add client_credentials and service accounts

Labels:

- `epic:platform`
- `priority:p3`

Suggested body:

```md
## Goals

- support machine-to-machine access
- define subject semantics for service accounts

## Acceptance Criteria

- confidential client can obtain token through `client_credentials`
- scope checks are enforced
```

### Card 10: Add audit sink / webhook sink extension point

Labels:

- `epic:platform`
- `priority:p3`

Suggested body:

```md
## Goals

- let security and lifecycle events be forwarded externally

## Acceptance Criteria

- events can be sent to a webhook sink
- failures are visible in audit or log output
```

### Card 11: Add delegated organization admin model

Labels:

- `epic:platform`
- `priority:p3`

Suggested body:

```md
## Goals

- support organization-scoped administrators
- reduce dependence on full global admin access

## Acceptance Criteria

- org admins can manage org-local resources
- org admins cannot access unrelated organizations
```

### Card 12: Research MFA / WebAuthn / passkeys

Labels:

- `epic:platform`
- `priority:p3`

Suggested body:

```md
## Goals

- define the next security milestone
- decide whether TOTP or WebAuthn lands first

## Acceptance Criteria

- produce technical design
- produce rollout recommendation
```

## Suggested Ordering

Create and execute cards in this order:

1. Card 1
2. Card 2
3. Card 3
4. Card 4
5. Card 5
6. Card 6
7. Card 7
8. Card 8
9. Card 9
10. Card 10
11. Card 11
12. Card 12

## One-Line Positioning for the Board

> MKAuth is already an extensible B2B CIAM platform. The next phase is about making authorization and extensibility first-class enough to grow into a deeper IAM foundation.
