# Contributing

## Before Opening A Change

- Keep passwords, client secrets, signing keys, local databases, runtime logs, and deployment credentials out of commits.
- Run `cd server && go test ./...` and `cd client && go test ./...`.
- Build both web applications with `npm ci && npm run build` in `web` and `admin-web`.
- Validate every quickstart Compose file with `docker compose ... config --quiet`.

## Pull Requests

Describe the affected login, OIDC, storage, or admin workflow and call out configuration or migration changes. Use generated local secrets for tests and never include real provider keys or customer data in issues, tests, screenshots, or examples.
