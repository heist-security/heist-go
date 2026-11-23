package heist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// TestSnapshotMatchesLock checks that the committed OpenAPI snapshot matches
// its recorded checksum and version, and that the generated code targets it.
func TestSnapshotMatchesLock(t *testing.T) {
	var lock struct {
		Version string `json:"version"`
		URL     string `json:"url"`
		SHA256  string `json:"sha256"`
	}
	readJSON(t, "../api/openapi.lock.json", &lock)

	snapshot, err := os.ReadFile("../api/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(snapshot)
	if got := hex.EncodeToString(sum[:]); got != lock.SHA256 {
		t.Errorf("api/openapi.json sha256 = %s, lock records %s", got, lock.SHA256)
	}

	var doc struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := json.Unmarshal(snapshot, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Info.Version != lock.Version {
		t.Errorf("snapshot info.version = %q, lock records %q", doc.Info.Version, lock.Version)
	}
	if APIVersion != lock.Version {
		t.Errorf("APIVersion = %q, lock records %q; run go generate ./...", APIVersion, lock.Version)
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}
