# HTTP Claims Action Plugin

This directory is a self-contained installable plugin example. You can either:

- upload the zipped directory from the admin plugin page, or
- copy the directory under one of the configured `plugins.directories` paths.

Example runtime config:

```yaml
plugins:
  enabled: true
  directories:
    - "plugins"
```

The `mkauth-plugin.yaml` file already contains the runtime `http_action` block, so no extra `plugins.http_actions` entry is required for this local plugin.

The manifest also declares the permissions it needs. This example requests `network:http_action` plus the hook permissions for `before_token_issue`, `before_userinfo`, and `post_authenticate`; installation fails if those permissions are missing or blocked by `plugins.allowed_permissions`.

The manifest includes a `config_schema`, so after installation the admin plugin page can configure the action URL, secret environment variable, timeout, and fail-open behavior without editing the main server config.

Set the secret through an environment variable if needed:

```bash
export MKAUTH_HTTP_CLAIMS_SECRET="YOUR_ACTION_BEARER_SECRET"
```

If you want to sign the plugin package:

```bash
cd tools
go run ./pluginsign genkey -key-id mkauth-dev -out-private ./plugin-signing.key.pem -out-public ./plugin-signing.pub
go run ./pluginsign sign -manifest ../examples/plugins/http-claims-action/mkauth-plugin.yaml -private-key ./plugin-signing.key.pem -key-id mkauth-dev
```

MKAuth sends a JSON payload to the configured URL. The action may return extra `claims` and `metadata`, or deny the flow with `allow: false`.
