package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// findingDetailJSON returns a finding detail response with the given status.
func findingDetailJSON(status string) string {
	return `{"id":"` + findingID + `","title":"Stored XSS","description":"Script runs.","type":"xss",` +
		`"category":"web","severity":"HIGH","validationStatus":"` + status + `","createdAt":"2026-11-01T00:00:00Z",` +
		`"applicationId":null,"routeId":null,"issueMetadata":null,"sourceKind":"pentest","newField":"added later"}`
}

func TestFindingsRetest(t *testing.T) {
	reportsServer(t, map[string]http.HandlerFunc{
		"POST /findings/{id}/retest": func(w http.ResponseWriter, r *http.Request) {
			if r.PathValue("id") != findingID {
				t.Errorf("id = %q", r.PathValue("id"))
			}
			respondJSON(http.StatusAccepted, `{"ok":true}`)(w, r)
		},
	})
	code, stdout, stderr := runCLI(t, "findings", "retest", findingID)
	if code != 0 || stdout != "Retest started. Check it with: heist findings retest-status "+findingID+"\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	code, stdout, _ = runCLI(t, "findings", "retest", "--json", findingID)
	if code != 0 || stdout != "{\n  \"ok\": true\n}\n" {
		t.Errorf("--json: exit %d, stdout %q", code, stdout)
	}
}

func TestFindingsRetestAlreadyRunning(t *testing.T) {
	reportsServer(t, map[string]http.HandlerFunc{
		"POST /findings/{id}/retest": respondJSON(http.StatusConflict, `{"error":{"code":"conflict","message":"Retest already running"}}`),
	})
	code, stdout, stderr := runCLI(t, "findings", "retest", findingID)
	if code != 1 || stdout != "" || stderr != "heist findings retest: HTTP 409: conflict: Retest already running\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestFindingsRetestStatus(t *testing.T) {
	for _, tt := range []struct {
		status, failure string
		code            int
	}{
		{"NOT_STARTED", "null", 0},
		{"RUNNING", "null", 0},
		{"COMPLETED", "null", 0},
		{"FAILED", `"Target unreachable"`, exitRetestFailed},
		{"TIMED_OUT", "null", exitRetestFailed},
	} {
		t.Run(tt.status, func(t *testing.T) {
			reportsServer(t, map[string]http.HandlerFunc{
				"GET /findings/{id}/retest": respondJSON(http.StatusOK, `{"workflowId":"wf","runId":null,`+
					`"status":"`+tt.status+`","startedAt":"2026-11-01T00:00:00Z","closedAt":null,`+
					`"failure":`+tt.failure+`,"finding":`+findingDetailJSON("PUBLISHED")+`,"newField":"added later"}`),
			})
			code, stdout, stderr := runCLI(t, "findings", "retest-status", findingID)
			if code != tt.code {
				t.Fatalf("exit %d, want %d, stderr %q", code, tt.code, stderr)
			}
			for _, want := range []string{"Retest:   " + tt.status + "\n", "\nTitle:     Stored XSS\n"} {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout missing %q:\n%s", want, stdout)
				}
			}
			if tt.code == exitRetestFailed && stderr != "heist findings retest-status: retest "+tt.status+"\n" {
				t.Errorf("stderr = %q", stderr)
			}

			code, stdout, _ = runCLI(t, "findings", "retest-status", "--json", findingID)
			var got map[string]any
			if code != tt.code || json.Unmarshal([]byte(stdout), &got) != nil || got["status"] != tt.status || got["newField"] != "added later" {
				t.Errorf("--json: exit %d, stdout %q", code, stdout)
			}
		})
	}
}

func TestFindingsStatusUpdates(t *testing.T) {
	for _, tt := range []struct {
		command, flag, status string
	}{
		{"accept-risk", "reason", "ACCEPTED"},
		{"compensating-control", "reason", "COMPENSATING_CONTROL"},
		{"false-positive", "comment", "FALSE_POSITIVE_CANDIDATE"},
	} {
		t.Run(tt.command, func(t *testing.T) {
			var body map[string]any
			reportsServer(t, map[string]http.HandlerFunc{
				"POST /findings/{id}/" + tt.command: func(w http.ResponseWriter, r *http.Request) {
					if r.PathValue("id") != findingID {
						t.Errorf("id = %q", r.PathValue("id"))
					}
					b, _ := io.ReadAll(r.Body)
					body = nil
					if err := json.Unmarshal(b, &body); err != nil {
						t.Errorf("request body %q: %v", b, err)
					}
					respondJSON(http.StatusOK, findingDetailJSON(tt.status))(w, r)
				},
			})
			code, stdout, stderr := runCLI(t, "findings", tt.command, findingID, "--"+tt.flag, "WAF blocks it")
			if code != 0 {
				t.Fatalf("exit %d, stderr %q", code, stderr)
			}
			if len(body) != 1 || body[tt.flag] != "WAF blocks it" {
				t.Errorf("request body = %v", body)
			}
			if !strings.Contains(stdout, "Status:    "+tt.status+"\n") {
				t.Errorf("stdout =\n%s", stdout)
			}

			code, stdout, _ = runCLI(t, "findings", tt.command, "--json", "--"+tt.flag, "WAF blocks it", findingID)
			var got map[string]any
			if code != 0 || json.Unmarshal([]byte(stdout), &got) != nil || got["validationStatus"] != tt.status || got["newField"] != "added later" {
				t.Errorf("--json: exit %d, stdout %q", code, stdout)
			}
		})
	}
}

func TestFindingsHistory(t *testing.T) {
	reportsServer(t, map[string]http.HandlerFunc{
		"GET /findings/{id}/status-history": respondJSON(http.StatusOK, `[`+
			`{"id":"h1","fromStatus":"PENDING_REVIEW","toStatus":"PUBLISHED","changedAt":"2026-11-01T00:00:00Z","changedByUserId":null},`+
			`{"id":"h2","fromStatus":"PUBLISHED","toStatus":"ACCEPTED","changedAt":"2026-11-02T00:00:00Z","changedByUserId":"user-1","newField":"added later"}]`),
	})
	code, stdout, stderr := runCLI(t, "findings", "history", findingID)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	want := "CHANGED               FROM            TO         CHANGED BY\n" +
		"2026-11-01T00:00:00Z  PENDING_REVIEW  PUBLISHED  -\n" +
		"2026-11-02T00:00:00Z  PUBLISHED       ACCEPTED   user-1\n"
	if stdout != want {
		t.Errorf("stdout =\n%s\nwant\n%s", stdout, want)
	}

	code, stdout, _ = runCLI(t, "findings", "history", "--json", findingID)
	var got []map[string]any
	if code != 0 || json.Unmarshal([]byte(stdout), &got) != nil || len(got) != 2 || got[1]["newField"] != "added later" {
		t.Errorf("--json: exit %d, stdout %q", code, stdout)
	}
}

func TestFindingActionsUsageErrors(t *testing.T) {
	t.Setenv("HEIST_CLIENT_ID", "")
	for _, tt := range []struct {
		args []string
		msg  string
	}{
		{[]string{"findings", "retest"}, "heist findings retest: expected one finding ID"},
		{[]string{"findings", "retest", "x"}, `heist findings retest: invalid ID "x"`},
		{[]string{"findings", "retest-status", findingID, "extra"}, "heist findings retest-status: expected one finding ID"},
		{[]string{"findings", "history", "x"}, `heist findings history: invalid ID "x"`},
		{[]string{"findings", "accept-risk", findingID}, "heist findings accept-risk: --reason is required"},
		{[]string{"findings", "compensating-control", findingID, "--reason", " "}, "heist findings compensating-control: --reason is required"},
		{[]string{"findings", "false-positive", findingID, "--reason", "r"}, "unknown flag: --reason"},
		{[]string{"findings", "false-positive", "--comment", "c"}, "heist findings false-positive: expected one finding ID"},
	} {
		code, stdout, stderr := runCLI(t, tt.args...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, tt.msg) || !strings.Contains(stderr, "Usage:\n  heist findings") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", tt.args, code, stdout, stderr)
		}
	}
}
