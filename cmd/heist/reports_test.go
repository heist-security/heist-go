package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	reportID = "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f"
	exportID = "2d3e4f5a-6b7c-4d8e-9f0a-1b2c3d4e5f6a"
	appID    = "3e4f5a6b-7c8d-4e9f-8a1b-2c3d4e5f6a7b"
	app2ID   = "4f5a6b7c-8d9e-4f0a-9b2c-3d4e5f6a7b8c"
	scopeID  = "5a6b7c8d-9e0f-4a1b-8c3d-4e5f6a7b8c9d"
)

// reportsServer serves the given routes, keyed by ServeMux pattern without
// the /external prefix, and fails the test on any other request.
func reportsServer(t *testing.T, routes map[string]http.HandlerFunc) {
	t.Helper()
	mux := http.NewServeMux()
	for pattern, h := range routes {
		method, path, _ := strings.Cut(pattern, " ")
		mux.HandleFunc(method+" /external"+path, h)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusNotFound)
	})
	apiServer(t, mux.ServeHTTP)
}

func respondJSON(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

const reportJSON = `{"id":"` + reportID + `","title":"Pentest  summary","status":"finalized",` +
	`"reportType":"customer_facing","exportFolderId":"f","scopeApplicationId":null,` +
	`"scopeApplicationIds":["` + appID + `"],"scopeName":"Prod","createdAt":"2026-11-01T00:00:00Z",` +
	`"lastVersionAt":null,"newField":"added later"}`

func TestReportsList(t *testing.T) {
	reportsServer(t, map[string]http.HandlerFunc{
		"GET /reports": func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("exportId"); got != exportID {
				t.Errorf("exportId = %q", got)
			}
			respondJSON(http.StatusOK, "["+reportJSON+"]")(w, r)
		},
	})
	code, stdout, stderr := runCLI(t, "reports", "list", "--export-id", exportID)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	want := "ID                                    TYPE             STATUS     SCOPE  CREATED               TITLE\n" +
		reportID + "  customer_facing  finalized  Prod   2026-11-01T00:00:00Z  Pentest summary\n"
	if stdout != want {
		t.Errorf("stdout =\n%s\nwant\n%s", stdout, want)
	}

	code, stdout, stderr = runCLI(t, "reports", "list", "--json", "--export-id", exportID)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, `"newField": "added later"`) {
		t.Errorf("--json dropped fields added later:\n%s", stdout)
	}
}

func TestReportsGet(t *testing.T) {
	reportsServer(t, map[string]http.HandlerFunc{
		"GET /reports/{id}": func(w http.ResponseWriter, r *http.Request) {
			if r.PathValue("id") != reportID {
				t.Errorf("id = %q", r.PathValue("id"))
			}
			body := strings.TrimSuffix(reportJSON, "}") + `,"versions":[` +
				`{"id":"v2","reportId":"` + reportID + `","createdAt":"2026-11-02T00:00:00Z"},` +
				`{"id":"v1","reportId":"` + reportID + `","createdAt":"2026-11-01T00:00:00Z"}]}`
			respondJSON(http.StatusOK, body)(w, r)
		},
	})
	code, stdout, stderr := runCLI(t, "reports", "get", reportID)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	want := "Title:         Pentest summary\n" +
		"ID:            " + reportID + "\n" +
		"Type:          customer_facing\n" +
		"Status:        finalized\n" +
		"Scope:         Prod\n" +
		"Applications:  " + appID + "\n" +
		"Created:       2026-11-01T00:00:00Z\n" +
		"\n" +
		"VERSION  CREATED\n" +
		"v2       2026-11-02T00:00:00Z\n" +
		"v1       2026-11-01T00:00:00Z\n"
	if stdout != want {
		t.Errorf("stdout =\n%s\nwant\n%s", stdout, want)
	}
}

func TestReportsGenerate(t *testing.T) {
	var bodies []string
	reportsServer(t, map[string]http.HandlerFunc{
		"POST /reports": func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			bodies = append(bodies, string(b))
			respondJSON(http.StatusAccepted, `{"workflowId":"wf","exportId":"`+exportID+`"}`)(w, r)
		},
	})
	code, stdout, stderr := runCLI(t, "reports", "generate", "--application", appID+","+app2ID)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if stdout != exportID+"\n" {
		t.Errorf("stdout = %q", stdout)
	}
	if code, _, stderr := runCLI(t, "reports", "generate"); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	want := []string{`{"applicationIds":["` + appID + `","` + app2ID + `"]}`, `{}`}
	for i := range want {
		if strings.TrimSpace(bodies[i]) != want[i] {
			t.Errorf("request %d body = %s, want %s", i, bodies[i], want[i])
		}
	}
}

func TestReportsGenerateShowsAPIError(t *testing.T) {
	reportsServer(t, map[string]http.HandlerFunc{
		"POST /reports": respondJSON(http.StatusForbidden, `{"error":{"code":"FORBIDDEN","message":"Admin role required"}}`),
	})
	code, stdout, stderr := runCLI(t, "reports", "generate")
	if code != 1 || stdout != "" {
		t.Errorf("exit %d, stdout %q", code, stdout)
	}
	if stderr != "heist reports generate: HTTP 403: FORBIDDEN: Admin role required\n" {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestReportsExportStatus(t *testing.T) {
	for _, tt := range []struct {
		status, failure string
		code            int
	}{
		{"RUNNING", "null", 0},
		{"COMPLETED", "null", 0},
		{"FAILED", `"PDF render failed"`, exitExportFailed},
		{"TIMED_OUT", "null", exitExportFailed},
		{"NOT_FOUND", "null", 1},
	} {
		t.Run(tt.status, func(t *testing.T) {
			reportsServer(t, map[string]http.HandlerFunc{
				"GET /report-exports/{id}": respondJSON(http.StatusOK, `{"exportId":"`+exportID+`","workflowId":"wf",`+
					`"runId":null,"status":"`+tt.status+`","startedAt":"2026-11-01T00:00:00Z","closedAt":null,`+
					`"failure":`+tt.failure+`,"reports":[`+reportJSON+`]}`),
			})
			code, stdout, stderr := runCLI(t, "reports", "export-status", exportID)
			if code != tt.code {
				t.Fatalf("exit %d, want %d, stderr %q", code, tt.code, stderr)
			}
			if !strings.Contains(stdout, "Status:   "+tt.status+"\n") || !strings.Contains(stdout, reportID) {
				t.Errorf("stdout =\n%s", stdout)
			}
			if tt.status == "NOT_FOUND" && stderr != "heist reports export-status: export not found, or its history has expired\n" {
				t.Errorf("stderr = %q", stderr)
			}
			if tt.code == exitExportFailed && stderr != "heist reports export-status: export "+tt.status+"\n" {
				t.Errorf("stderr = %q", stderr)
			}
		})
	}
}

// pdfServer serves report downloads. The signed URL points back at the same
// server under /external/signed.
func pdfServer(t *testing.T, pdfStatus int) {
	t.Helper()
	reportsServer(t, map[string]http.HandlerFunc{
		"GET /reports/{id}/download": func(w http.ResponseWriter, r *http.Request) {
			version := r.URL.Query().Get("versionId")
			if version == "" {
				version = "latest"
			}
			url := "http://" + r.Host + "/external/signed/" + version + ".pdf"
			respondJSON(http.StatusOK, `{"reportId":"`+reportID+`","versionId":"v","url":"`+url+`","expiresAt":"x"}`)(w, r)
		},
		"GET /signed/{file}": func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				t.Error("signed URL request sent the API token")
			}
			w.WriteHeader(pdfStatus)
			io.WriteString(w, "%PDF "+r.PathValue("file"))
		},
	})
}

func TestReportsDownload(t *testing.T) {
	pdfServer(t, http.StatusOK)
	t.Chdir(t.TempDir())

	if code, stdout, stderr := runCLI(t, "reports", "download", reportID); code != 0 || stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if got, err := os.ReadFile(reportID + ".pdf"); err != nil || string(got) != "%PDF latest.pdf" {
		t.Errorf("default file = %q, %v", got, err)
	}

	out := filepath.Join("out", "r.pdf")
	os.Mkdir("out", 0o755)
	if code, _, stderr := runCLI(t, "reports", "download", "--version", appID, "-o", out, reportID); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if got, err := os.ReadFile(out); err != nil || string(got) != "%PDF "+appID+".pdf" {
		t.Errorf("-o file = %q, %v", got, err)
	}

	code, stdout, stderr := runCLI(t, "reports", "download", "-o", "-", reportID)
	if code != 0 || stdout != "%PDF latest.pdf" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestReportsDownloadFailureLeavesNoFile(t *testing.T) {
	pdfServer(t, http.StatusForbidden)
	dir := t.TempDir()
	t.Chdir(dir)
	code, _, stderr := runCLI(t, "reports", "download", reportID)
	if code != 1 || stderr != "heist reports download: download PDF: HTTP 403 Forbidden\n" {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("left files behind: %v", entries)
	}
}

const scopeJSON = `{"id":"` + scopeID + `","name":"Prod","applicationIds":["` + appID + `","` + app2ID + `"],"createdAt":"2026-11-01T00:00:00Z"}`

func TestReportScopes(t *testing.T) {
	var requests []string
	record := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			requests = append(requests, r.Method+" "+r.URL.Path+" "+strings.TrimSpace(string(b)))
			respondJSON(status, body)(w, r)
		}
	}
	reportsServer(t, map[string]http.HandlerFunc{
		"GET /report-scopes":         record(http.StatusOK, "["+scopeJSON+"]"),
		"POST /report-scopes":        record(http.StatusCreated, scopeJSON),
		"POST /report-scopes/{id}":   record(http.StatusOK, scopeJSON),
		"DELETE /report-scopes/{id}": record(http.StatusOK, `{"ok":true}`),
	})

	table := "ID                                    NAME  CREATED               APPLICATIONS\n" +
		scopeID + "  Prod  2026-11-01T00:00:00Z  " + appID + "," + app2ID + "\n"
	for _, tt := range []struct {
		args   []string
		stdout string
	}{
		{[]string{"list"}, table},
		{[]string{"create", "--name", "Prod", "--application", appID, "--application", app2ID}, table},
		{[]string{"update", "--name", "Prod", "--application", appID + "," + app2ID, scopeID}, table},
		{[]string{"delete", scopeID}, ""},
	} {
		code, stdout, stderr := runCLI(t, append([]string{"reports", "scopes"}, tt.args...)...)
		if code != 0 || stdout != tt.stdout {
			t.Errorf("%v: exit %d, stderr %q, stdout =\n%s\nwant\n%s", tt.args, code, stderr, stdout, tt.stdout)
		}
	}
	body := `{"applicationIds":["` + appID + `","` + app2ID + `"],"name":"Prod"}`
	want := []string{
		"GET /external/report-scopes ",
		"POST /external/report-scopes " + body,
		"POST /external/report-scopes/" + scopeID + " " + body,
		"DELETE /external/report-scopes/" + scopeID + " ",
	}
	if strings.Join(requests, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests =\n%s\nwant\n%s", strings.Join(requests, "\n"), strings.Join(want, "\n"))
	}

	code, stdout, _ := runCLI(t, "reports", "scopes", "create", "--json", "--name", "Prod", "--application", appID)
	var scope map[string]any
	if code != 0 || json.Unmarshal([]byte(stdout), &scope) != nil || scope["id"] != scopeID {
		t.Errorf("--json: exit %d, stdout %q", code, stdout)
	}
}

func TestReportsUsageErrors(t *testing.T) {
	t.Setenv("HEIST_CLIENT_ID", "")
	for _, tt := range []struct {
		args []string
		msg  string
	}{
		{[]string{"reports"}, ""},
		{[]string{"reports", "nope"}, `heist reports: unknown command "nope"`},
		{[]string{"reports", "list", "--export-id", "x"}, `heist reports list: --export-id: invalid ID "x"`},
		{[]string{"reports", "get"}, "heist reports get: expected one report ID"},
		{[]string{"reports", "get", "x"}, `heist reports get: invalid ID "x"`},
		{[]string{"reports", "generate", "--application", "x"}, `invalid ID "x"`},
		{[]string{"reports", "export-status"}, "heist reports export-status: expected one export ID"},
		{[]string{"reports", "download", "--version", "x", reportID}, `heist reports download: --version: invalid ID "x"`},
		{[]string{"reports", "scopes", "nope"}, `heist reports scopes: unknown command "nope"`},
		{[]string{"reports", "scopes", "create", "--application", appID}, "heist reports scopes create: --name is required"},
		{[]string{"reports", "scopes", "update", "--name", "n", scopeID}, "heist reports scopes update: at least one --application is required"},
		{[]string{"reports", "scopes", "update", "--name", "n", "--application", appID}, "heist reports scopes update: expected one scope ID"},
		{[]string{"reports", "scopes", "delete"}, "heist reports scopes delete: expected one scope ID"},
	} {
		code, stdout, stderr := runCLI(t, tt.args...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, tt.msg) || !strings.Contains(stderr, "Usage: heist reports") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", tt.args, code, stdout, stderr)
		}
	}
}

func TestReportsHelp(t *testing.T) {
	for _, args := range [][]string{
		{"reports", "-h"},
		{"reports", "export-status", "-h"},
		{"reports", "scopes", "--help"},
		{"reports", "scopes", "update", "-h"},
	} {
		code, stdout, stderr := runCLI(t, args...)
		if code != 0 || stderr != "" || !strings.HasPrefix(stdout, "Usage: heist reports") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
	}
}
