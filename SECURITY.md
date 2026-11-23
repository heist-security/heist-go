# Security policy

This project is alpha. Security fixes target the default branch and the next
release; there are no backported fixes to earlier tags.

## Private reporting

Do not disclose exploitable vulnerabilities in public issues or pull requests.

Use GitHub's **Security → Report a vulnerability** when private vulnerability
reporting is enabled. If that option is unavailable, contact
**hello@heisthq.com** (the address published at
[heist.security/contact](https://heist.security/contact)) with the subject
"heist-go: private security reporting channel" to arrange confidential
disclosure. Do not include passwords, access tokens, customer data or
vulnerability details in that initial email.

Once a private channel is established, include the affected commit or release,
impact, prerequisites and a minimal safe reproduction. This repository covers
the Go SDK and CLI. Do not test the hosted Heist service, other customers'
workspaces or production availability without separate authorization. This
policy does not promise a bounty or response-time SLA.

## Trust boundaries

- OAuth app access tokens grant workspace access. The SDK attaches them as a
  bearer token to requests sent through `Config.HTTPClient` to the configured
  server URL. It does not log, persist or include them in errors. Point `Config.ServerURL` only at a Heist API you
  trust, and keep TLS verification enabled in any custom `HTTPClient`.
- The Heist service enforces authentication, workspace membership, roles and
  feature restrictions. The SDK and CLI do not grant or limit access; hiding a
  command or operation is not an access control.
- API responses are untrusted input. They are decoded into typed values without
  executing content, and error bodies are read up to a fixed size limit.
- `api/openapi.json` is pinned by SHA-256 in `api/openapi.lock.json`. Normal
  builds and code generation read only that committed file and never fetch a
  schema.
- Dependencies are public Go modules verified by `go.sum`. The code generator
  is pinned in a separate `tools/go.mod` and is not a dependency of SDK
  consumers.
