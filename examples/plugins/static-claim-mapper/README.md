# Static Claim Mapper Plugin

This example shows a local `claim_mapper` plugin. It does not execute remote code; it maps values from the current token/userinfo context into custom claims.

Install it by zipping this directory and uploading it from the admin plugin page, or copy the directory under one of the configured `plugins.directories` paths.

Example mappings:

- `tenant_key` is rendered from plugin config, `org_slug`, and `client_id`
- `app_roles` copies the existing `org_roles` claim into an application-specific claim
- `directory_subject` copies the internal MKAuth user ID

The mapper runs on `before_token_issue` and `before_userinfo`, so it can affect ID Tokens, access tokens, and `/oauth2/userinfo`.

Protected protocol claims such as `sub`, `iss`, `aud`, `exp`, `iat`, `scope`, `client_id`, `org_id`, and `org_roles` cannot be overwritten by claim mapper plugins.
