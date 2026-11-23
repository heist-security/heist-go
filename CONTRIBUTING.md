# Contributing

Please open an issue for substantial changes before implementation. Use the
private channel in SECURITY.md for security vulnerabilities.

## Development

Use the Go version in `go.mod` and run `make deps` to download modules. After
that, every check works offline and needs no Heist credentials or private
repository access.

Before a pull request:

    make check

`make check` runs the same checks as CI; see the `Makefile` for each target.

Keep changes focused and tests on current behavior. Tests use `httptest`
servers and must not call the live Heist API. Add regression coverage for
changes to authentication, error handling, pagination and response decoding.
Never commit access tokens, `.env` files or real customer data.

## SDK and CLI boundaries

The `heist` package owns the REST client, request and response types,
authentication, error handling and pagination. CLI commands, output formats
and progress handling belong in `cmd/heist`. Terraform state and resource
lifecycle belong in the separate `terraform-provider-heist` repository.

The Heist service owns the API contract. Preserve its field names and
semantics. Responses must keep decoding fields and enum values added by later
API releases, so don't add strict response validation. Prefer additive SDK
changes; a breaking change to exported SDK APIs needs a new minor version while
releases are `v0.x`.

## API contract updates

`api/openapi.json` is a byte-for-byte copy of a published, immutable contract.
Never edit it or `heist/openapi.gen.go` by hand. To target a newer published
version, follow [OpenAPI snapshot](README.md#openapi-snapshot) in the README.

Contract changes themselves, such as new endpoints or fields, are made in the
Heist service and published before this repository can use them.

## Code

Original code contributions are provided under the MIT license. Keep
third-party notices intact. The license grants no rights to Heist names or
logos.
