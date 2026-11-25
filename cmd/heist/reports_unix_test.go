//go:build unix

package main

import (
	"net/http"
	"os"
	"syscall"
	"testing"
)

func TestReportsDownloadHonoursUmask(t *testing.T) {
	pdfServer(t, http.StatusOK)
	for _, tc := range []struct {
		umask int
		want  os.FileMode
	}{
		{0o022, 0o644},
		{0o077, 0o600},
	} {
		t.Chdir(t.TempDir())
		old := syscall.Umask(tc.umask)
		code, _, stderr := runCLI(t, "reports", "download", reportID)
		syscall.Umask(old)
		if code != 0 {
			t.Fatalf("umask %#o: exit %d, stderr %q", tc.umask, code, stderr)
		}
		info, err := os.Stat(reportID + ".pdf")
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != tc.want {
			t.Errorf("umask %#o: file mode = %v, want %v", tc.umask, got, tc.want)
		}
	}
}
