# heist-go

The Go SDK and `heist` CLI for the [Heist](https://heist.security) external REST
API.

- `heist/`: the SDK package, `github.com/heist-security/heist-go/heist`. It
  provides the REST client and request/response types, authentication, error
  helpers, and pagination.
- `cmd/heist/`: the CLI, built on the SDK.
- `api/`: the published OpenAPI snapshot the SDK is generated from.

The SDK (`github.com/heist-security/heist-go`) and the CLI
(`github.com/heist-security/heist-go/cmd/heist`) are separate Go modules with
their own version tags, so SDK users don't inherit the CLI's dependencies.

## Using the SDK

```sh
go get github.com/heist-security/heist-go@latest
```

Create an OAuth app in **Settings → OAuth apps** in Heist and authenticate with
its client ID and secret:

```go
tokens := &heist.ClientCredentials{
	ClientID:     os.Getenv("HEIST_CLIENT_ID"),
	ClientSecret: os.Getenv("HEIST_CLIENT_SECRET"),
}
client, err := heist.New(tokens, heist.Config{
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

critical, err := client.CountFindings(ctx, heist.ListFindingsParams{
	Severity: &[]heist.ListFindingsParamsSeverity{heist.ListFindingsParamsSeverityCRITICAL},
})
```

`heist.New` returns the generated `*heist.ClientWithResponses`. Every API
operation is an `<Operation>WithResponse` method, and shared API objects have
named types such as `heist.Finding` and `heist.Credential`. Every non-2xx
response is returned as `*heist.APIError` with the HTTP status and the API's
error code and message, so a nil error means the success field (`JSON200`,
`JSON201` or `JSON202`) is set. `heist.StatusCode(err)` and
`heist.IsNotFound(err)` inspect errors.

`heist.ClientCredentials` exchanges the client ID and secret for an access token
at `heist.DefaultTokenURL` with the OAuth 2.0 `client_credentials` grant, using
`golang.org/x/oauth2`. It caches the token and requests a new one shortly before
it expires. Set its `TokenURL` to use a different token endpoint. To use an
access token you already have, pass `heist.StaticToken(token)` instead, or
implement `heist.TokenSource` to supply tokens another way.

Responses decode leniently: fields and enum values added by later API releases
are accepted, so a pinned SDK keeps working against a newer service.

`heist.APIVersion` is the API contract version the SDK was generated from. The SDK
release version is independent of it.

## Installing the CLI

```sh
go install github.com/heist-security/heist-go/cmd/heist@latest
heist version
```

`heist api` sends an authenticated request to any API path and writes the
response body to stdout. It reads the OAuth app credentials from
`HEIST_CLIENT_ID` and `HEIST_CLIENT_SECRET`:

```sh
heist api '/findings?severity=high'
heist api --input domain.json /domains   # POST unless -X is given
```

`heist findings` lists, shows, and counts findings with the same credentials:

```sh
heist findings list --severity high,critical --search login
heist findings list --fail-on high   # exit 3 if an open finding is HIGH or above
heist findings get <id>
heist findings counts
```

`list` follows pagination and prints every matching finding unless `--limit`
is given. `--fail-on <severity>` exits with status 3 when any finding matching
the filters is at or above that severity. It only counts open (`PUBLISHED`)
findings unless `--status` is given. Errors exit with 1 and usage errors with 2.
`counts` shows the API's status counts and open findings by severity. Pass
`--json` to any findings command for JSON output.

`heist domains` lists domains, sets automatic inclusion, and verifies domain
ownership with a DNS TXT record:

```sh
heist domains list
heist domains get <id>
heist domains status                      # exit 3 if an in-scope domain is unverified
heist domains auto-include <id> --on      # or --off
heist domains challenge --create <id>     # issue or show the TXT record
heist domains challenge --value <id>      # only the record value, for DNS tools
heist domains verify <id>                 # exit 3 if the domain isn't verified
```

`challenge` reads the existing TXT record and fails if none has been issued;
`--create` issues one. Publish the record with your DNS provider, then run
`verify`. Changing auto-include, reading or issuing a challenge, and
verifying require the Admin role. Pass `--json` to any domains command for the
API's JSON response.

`heist reports` lists, generates, and downloads PDF reports, and manages report
scopes:

```sh
heist reports list
heist reports get <id>                      # the report and its PDF versions
heist reports generate --application <id>   # prints the export ID
heist reports export-status <export-id>     # exit 3 if the export failed
heist reports download -o report.pdf <id>   # default <id>.pdf; -o - for stdout
heist reports scopes create --name Prod --application <id>,<id>
```

`generate` includes all in-scope applications unless `--application` is
given, and returns as soon as generation starts. Run `export-status` until the
status is `COMPLETED`. It exits with status 3 when the export ended without
completing (`FAILED`, `CANCELLED`, `TERMINATED`, or `TIMED_OUT`). Errors exit
with 1, including an export ID that is unknown or whose history has expired,
and usage errors with 2. Generating reports and changing scopes require
the Admin role and a plan with reports. Pass `--json` to any command that
prints data for the API's JSON response.

Flags can go before or after arguments. Long flags take two dashes
(`--json`); single-letter flags take one (`-o`, `-X`). Run `heist help`, or
`heist <command> --help` at any level, for every command, flag and environment
variable. `heist completion <shell>` prints a shell completion script for bash,
zsh, fish or PowerShell.

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

`cmd/heist/go.work` builds the CLI against the SDK in this checkout, so run Go
commands for the CLI from `cmd/heist/` and CLI changes can use unreleased SDK
changes. `go install` and CLI release builds ignore the workspace and use the
SDK version in `cmd/heist/go.mod`; a CLI release needs that version to provide
everything the CLI uses (see [Releases](#releases)).

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

Releases are Git tags on `main` using semantic versioning. SDK tags are
`vMAJOR.MINOR.PATCH`; CLI tags are `cmd/heist/vMAJOR.MINOR.PATCH`. While the
SDK API is still settling, releases use `v0.x.y`, and minor versions may break
compatibility.

Don't push release tags by hand. To release, run the **Release** workflow
(`.github/workflows/release.yml`) on `main` with the module and version:

```sh
gh workflow run release.yml --ref main -f module=sdk -f version=v0.4.0
gh workflow run release.yml --ref main -f module=cli -f version=v0.4.0
```

It:

1. Runs every check. For the CLI, it also tests and builds binaries for Linux,
   macOS and Windows (amd64 and arm64) without build caches and without the
   workspace, as `go install` would.
2. Waits for a second maintainer to approve the `release` environment.
3. Records signed build provenance for each CLI binary, then creates the tag
   and a GitHub release, with the binaries and `SHA256SUMS` for the CLI.

When the CLI needs SDK changes that aren't released yet, release the SDK first,
then update the CLI's requirement in a pull request before releasing the CLI:

```sh
cd cmd/heist
GOWORK=off go get github.com/heist-security/heist-go@v0.4.0
GOWORK=off go mod tidy
```

Verify a downloaded binary with:

```sh
gh attestation verify heist_v0.4.0_linux_amd64 --repo heist-security/heist-go
```

Consumers pin a release in `go.mod`:

```sh
go get github.com/heist-security/heist-go@v0.1.0
```

The Go module proxy serves tagged versions, so consumers need no access beyond
public module downloads. Published tags and releases are immutable; fix
mistakes with a new version.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md), not in public issues.

## License

[MIT](LICENSE)
