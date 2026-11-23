// Command update-openapi downloads a published Heist OpenAPI snapshot and
// records its version, source URL, and SHA-256 checksum.
//
// Usage (from the repository root):
//
//	go run ./internal/cmd/update-openapi 2.4.0
//
// Run go generate ./... afterwards to regenerate the SDK.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	urlTemplate  = "https://openapi.heist.security/%s/openapi.json"
	snapshotPath = "api/openapi.json"
	lockPath     = "api/openapi.lock.json"
)

type lock struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: update-openapi <version>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "update-openapi:", err)
		os.Exit(1)
	}
}

func run(version string) error {
	url := fmt.Sprintf(urlTemplate, version)
	client := http.Client{Timeout: time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var doc struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", url, err)
	}
	if doc.Info.Version != version {
		return fmt.Errorf("%s has info.version %q, want %q", url, doc.Info.Version, version)
	}

	sum := sha256.Sum256(body)
	record, err := json.MarshalIndent(lock{Version: version, URL: url, SHA256: hex.EncodeToString(sum[:])}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(snapshotPath, body, 0o644); err != nil {
		return err
	}
	return os.WriteFile(lockPath, append(record, '\n'), 0o644)
}
