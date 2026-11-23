# heist-go

The Go SDK and `heist` CLI for the [Heist](https://heist.security) external REST
API.

- `heist/`: the SDK package, `github.com/heist-security/heist-go/heist`. It
  provides the REST client and request/response types, authentication, error
  helpers, and pagination.
- `cmd/heist/`: the CLI, built on the SDK.
- `api/`: the published OpenAPI snapshot the SDK is generated from.

The SDK and CLI share one Go module and one set of version tags.

## Using the SDK

```sh
go get github.com/heist-security/heist-go@latest
```

Create an OAuth app in **Settings → OAuth apps** in Heist and use its access token:

```go
client, err := heist.New(heist.StaticToken(os.Getenv("HEIST_ACCESS_TOKEN")), heist.Config{
	UserAgent: "my-tool/1.0",
})
if err != nil {
	return err
}

res, err := client.GetFindingWithResponse(ctx, findingID)
if heist.IsNotFound(err) {
	return fmt.Errorf("finding %s not found", findingID)
} else if err != nil {
	return err
}
fmt.Println(res.JSON200.Title, res.JSON200.Severity)

for finding, err := range client.AllFindings(ctx, heist.ListFindingsParams{}) {
	if err != nil {
		return err
	}
	fmt.Println(finding.Id, finding.Severity, finding.Title)
}
```

`heist.New` returns the generated `*heist.ClientWithResponses`. Every API
operation is an `<Operation>WithResponse` method, and shared API objects have
named types such as `heist.Finding` and `heist.Credential`. Every non-2xx
response is returned as `*heist.APIError` with the HTTP status and the API's
error code and message, so a nil error means the success field (`JSON200`,
`JSON201` or `JSON202`) is set. `heist.StatusCode(err)` and
`heist.IsNotFound(err)` inspect errors. Implement `heist.TokenSource` to
refresh tokens.

Responses decode leniently: fields and enum values added by later API releases
are accepted, so a pinned SDK keeps working against a newer service.

`heist.APIVersion` is the API contract version the SDK was generated from. The SDK
release version is independent of it.

## Installing the CLI

```sh
go install github.com/heist-security/heist-go/cmd/heist@latest
heist version
```

## Development

Requires Go (version in `go.mod`) and `make`. No Heist credentials, private
repositories, or network access to Heist are needed.

```sh
make deps          # download modules; the only step that needs the network
make check         # everything CI runs
make check-sdk     # SDK: gofmt, vet, tests
make check-cli     # CLI: build to dist/heist, gofmt, vet, tests
make generate      # regenerate heist/openapi.gen.go from api/openapi.json
```

After `make deps`, builds, tests, and generation work offline, for example
with `GOPROXY=off`. CI runs every check this way.

### OpenAPI snapshot

`api/openapi.json` is a byte-for-byte copy of a published, immutable contract
from `https://openapi.heist.security/<version>/openapi.json`.
`api/openapi.lock.json` records its version, source URL, and SHA-256; a test
checks them against the file and the `heist.APIVersion` constant. Generation reads only the
committed file and never fetches a schema.

To target a newer published version:

```sh
go run ./internal/cmd/update-openapi 2.5.0
# set APIVersion in heist/client.go to 2.5.0
make generate
make check
```

Commit the snapshot, lock file, and regenerated code together.

`make generate` runs [oapi-codegen](https://github.com/oapi-codegen/oapi-codegen)
on the snapshot unchanged, configured by `heist/oapi-codegen.yaml`. The
generator is pinned in `tools/go.mod`, a separate module, so SDK consumers don't
inherit its dependencies. Never edit `heist/openapi.gen.go` directly.

## Releases

Releases are Git tags on `main` using semantic versioning (`vMAJOR.MINOR.PATCH`).
The tag versions the SDK and CLI together. While the SDK API is still settling,
releases use `v0.x.y`, and minor versions may break compatibility.

1. Confirm CI is green on the commit to release.
2. Tag and push it: `git tag v0.1.0 && git push origin v0.1.0`.

Consumers pin a release in `go.mod`:

```sh
go get github.com/heist-security/heist-go@v0.1.0
```

The Go module proxy serves tagged versions, so consumers need no access beyond
public module downloads. Never move or delete a published tag; release a new
version instead.

## License

[MIT](LICENSE)
