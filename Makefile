.PHONY: check check-sdk check-cli check-generated generate build deps vulncheck

# Run every offline check CI runs. CI also runs vulncheck.
check: check-generated check-sdk check-cli

# Download the SDK, CLI and code generator modules. This is the only step that
# needs the network.
deps:
	go mod download
	cd cmd/heist && go mod download
	cd tools && go mod download

# SDK: format, vet, and test the public package and the snapshot tooling.
check-sdk:
	test -z "$$(gofmt -l heist internal)"
	go vet ./heist/... ./internal/...
	go test ./heist/... ./internal/...

# CLI: build, format, vet, and test. cmd/heist is its own module; its go.work
# builds it against the SDK in this checkout.
check-cli: build
	test -z "$$(gofmt -l cmd)"
	cd cmd/heist && go vet ./...
	cd cmd/heist && go test ./...

# Fail if generated code is stale relative to api/openapi.json.
check-generated: generate
	git diff --exit-code -- heist go.mod go.sum tools
	test -z "$$(git ls-files --others --exclude-standard -- heist)"

# Report known vulnerabilities in reachable code. Queries vuln.go.dev, so it
# needs network access and is not part of the offline check target. The CLI is
# scanned without the workspace, against the dependency versions it ships with.
vulncheck:
	go tool -modfile=tools/go.mod govulncheck ./...
	cd cmd/heist && GOWORK=off go tool -modfile=../../tools/go.mod govulncheck ./...

generate:
	go generate ./...

build:
	cd cmd/heist && go build -o ../../dist/heist .
