# Audit Webhook Sink

This example plugin forwards MKAuth admin security audit events to an HTTPS webhook. It can also opt into authentication lifecycle events.

## Install

Zip this directory and install it from the admin Settings plugin page:

```bash
cd examples/plugins
zip -r audit-webhook-sink.zip audit-webhook-sink
```

The manifest requests:

- `audit:security` to receive admin security audit events
- `network:audit_sink` to send events to the configured webhook

## Payload

The webhook receives a JSON body shaped like:

```json
{
  "plugin_id": "audit-webhook-sink",
  "event": "security_audit",
  "audit": {
    "id": "aud_xxx",
    "time": "2026-04-26T00:00:00Z",
    "action": "oidc_client_create",
    "actor": { "id": "usr_admin" },
    "success": true,
    "details": { "resource_type": "oidc_client", "client_id": "demo-spa" }
  }
}
```

If `secret` or `secret_env` is configured, MKAuth sends `Authorization: Bearer <token>`.

To receive lifecycle events, add `auth_lifecycle` to `audit_sink.resource_types`, or filter specific lifecycle `actions` such as `pre_authenticate` or `post_register`.

Lifecycle payloads look like:

```json
{
  "plugin_id": "audit-webhook-sink",
  "event": "lifecycle",
  "lifecycle": {
    "time": "2026-04-26T00:00:00Z",
    "event": "pre_authenticate",
    "user_id": "usr_xxx",
    "provider": "enterprise_oidc",
    "ip": "203.0.113.10",
    "metadata": { "provider_slug": "acme" }
  }
}
```
