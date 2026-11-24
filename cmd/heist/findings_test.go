package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const findingID = "0b8f5c4e-3c1a-4d2b-9e6f-1a2b3c4d5e6f"

// findingsServer serves /findings from a fixed set of findings, applying the
// severity and status filters and pagination like the API. It records every
// list query.
type findingsServer struct {
	mu       sync.Mutex
	findings []map[string]any
	queries  []url.Values
}

func newFindingsServer(t *testing.T, findings ...map[string]any) *findingsServer {
	t.Helper()
	s := &findingsServer{findings: findings}
	apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/external/findings" {
			t.Errorf("unexpected request %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		q := r.URL.Query()
		s.mu.Lock()
		s.queries = append(s.queries, q)
		s.mu.Unlock()
		var matched []map[string]any
		for _, f := range s.findings {
			if (!q.Has("severity") || contains(q["severity"], f["severity"])) &&
				(!q.Has("status") || contains(q["status"], f["validationStatus"])) {
				matched = append(matched, f)
			}
		}
		page, _ := strconv.Atoi(q.Get("page"))
		page = max(page, 1)
		size, _ := strconv.Atoi(q.Get("size"))
		if size == 0 {
			size = 100
		}
		start := min((page-1)*size, len(matched))
		items := matched[start:min(start+size, len(matched))]
		if items == nil {
			items = []map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"items": items, "total": len(matched), "page": page, "size": size})
	})
	return s
}

func contains(values []string, v any) bool {
	for _, s := range values {
		if s == v {
			return true
		}
	}
	return false
}

func finding(id, severity, status string) map[string]any {
	return map[string]any{
		"id": id, "title": "Finding " + id, "description": "", "type": "xss", "category": "web",
		"severity": severity, "validationStatus": status, "createdAt": "2026-11-01T00:00:00Z",
		"applicationId": nil, "routeId": nil, "issueMetadata": nil, "sourceKind": "pentest",
	}
}

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, nil, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestFindingsListTable(t *testing.T) {
	s := newFindingsServer(t,
		finding("a", "HIGH", "PUBLISHED"),
		finding("b", "LOW", "FIXED"),
		finding("c", "CRITICAL", "PUBLISHED"),
	)
	code, stdout, stderr := runCLI(t, "findings", "list", "--severity", "high,critical", "--status", "published", "--search", "login")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	want := "ID  SEVERITY  STATUS     TITLE\n" +
		"a   HIGH      PUBLISHED  Finding a\n" +
		"c   CRITICAL  PUBLISHED  Finding c\n"
	if stdout != want {
		t.Errorf("stdout =\n%s\nwant\n%s", stdout, want)
	}
	q := s.queries[0]
	if fmt.Sprint(q["severity"]) != "[HIGH CRITICAL]" || q.Get("status") != "PUBLISHED" || q.Get("search") != "login" {
		t.Errorf("query = %v", q)
	}
}

func TestFindingsListFollowsPagesAndLimit(t *testing.T) {
	var findings []map[string]any
	for i := range 150 {
		findings = append(findings, finding(strconv.Itoa(i), "LOW", "PUBLISHED"))
	}
	s := newFindingsServer(t, findings...)

	code, stdout, stderr := runCLI(t, "findings", "list", "--json")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var all []map[string]any
	if err := json.Unmarshal([]byte(stdout), &all); err != nil || len(all) != 150 {
		t.Fatalf("decoded %d findings, err %v", len(all), err)
	}
	if len(s.queries) != 2 {
		t.Errorf("requested %d pages, want 2", len(s.queries))
	}

	s.queries = nil
	code, stdout, _ = runCLI(t, "findings", "list", "--limit", "3", "--json")
	var limited []map[string]any
	if code != 0 || json.Unmarshal([]byte(stdout), &limited) != nil || len(limited) != 3 {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	if len(s.queries) != 1 || s.queries[0].Get("size") != "3" {
		t.Errorf("queries = %v, want one with size=3", s.queries)
	}
}

func TestFindingsListEmptyJSON(t *testing.T) {
	newFindingsServer(t)
	code, stdout, _ := runCLI(t, "findings", "list", "--json")
	if code != 0 || stdout != "[]\n" {
		t.Errorf("exit %d, stdout %q", code, stdout)
	}
}

func TestFindingsListFailOn(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		// wantGate is the gate count query's severity and status, or empty
		// when no count request is expected.
		wantGate string
	}{
		{"open finding at threshold", []string{"--fail-on", "high"}, 3, "[HIGH CRITICAL] [PUBLISHED]"},
		{"fixed findings ignored by default", []string{"--fail-on", "critical"}, 0, "[CRITICAL] [PUBLISHED]"},
		{"explicit status overrides open default", []string{"--fail-on", "critical", "--status", "FIXED"}, 3, "[CRITICAL] [FIXED]"},
		{"limit does not hide findings", []string{"--fail-on", "high", "--limit", "1", "--severity", "low,high"}, 3, "[HIGH] [PUBLISHED]"},
		{"severity filter below threshold", []string{"--fail-on", "high", "--severity", "low"}, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newFindingsServer(t,
				finding("a", "LOW", "PUBLISHED"),
				finding("b", "HIGH", "PUBLISHED"),
				finding("c", "CRITICAL", "FIXED"),
			)
			code, _, stderr := runCLI(t, append([]string{"findings", "list"}, tt.args...)...)
			if code != tt.wantCode {
				t.Errorf("exit %d, want %d; stderr %q", code, tt.wantCode, stderr)
			}
			var gate string
			for _, q := range s.queries {
				if q.Get("size") == "1" && !q.Has("page") {
					gate = fmt.Sprint(q["severity"], " ", q["status"])
				}
			}
			if gate != tt.wantGate {
				t.Errorf("gate query = %q, want %q", gate, tt.wantGate)
			}
			if tt.wantCode == 3 && !strings.Contains(stderr, "at or above") {
				t.Errorf("stderr = %q", stderr)
			}
		})
	}
}

func TestFindingsListUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"findings", "list", "--fail-on", "severe"},
		{"findings", "list", "--limit", "-1"},
		{"findings", "list", "extra"},
		{"findings", "nope"},
		{"findings"},
	} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestFindingsGet(t *testing.T) {
	apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/external/findings/"+findingID {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{
			"id": "`+findingID+`", "title": "Stored XSS", "description": "Script runs.",
			"type": "xss", "category": "web", "severity": "HIGH", "validationStatus": "PUBLISHED",
			"createdAt": "2026-11-01T00:00:00Z", "updatedAt": "2026-11-02T00:00:00Z",
			"applicationId": "app", "routeId": "route", "issueMetadata": null, "sourceKind": "pentest",
			"impact": "Account takeover.", "likelihood": null, "evidence": null, "recommendation": "Encode output.",
			"references": null, "stepsToReproduce": null, "acceptReason": null, "compensatingControlReason": null,
			"retestComment": null, "application": {"id": "app", "url": "https://app.example.com"},
			"route": {"id": "route", "url": "/comments", "routeType": "http", "httpMethods": ["POST"],
				"graphqlOperationName": null, "graphqlOperationType": null},
			"newField": "added later"
		}`)
	})
	code, stdout, stderr := runCLI(t, "findings", "get", findingID)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	for _, want := range []string{
		"Title:        Stored XSS\n",
		"Severity:     HIGH\n",
		"Application:  https://app.example.com\n",
		"Route:        POST /comments\n",
		"\nDescription:\nScript runs.\n",
		"\nImpact:\nAccount takeover.\n",
		"\nRecommendation:\nEncode output.\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "Likelihood") {
		t.Errorf("stdout includes empty section:\n%s", stdout)
	}

	code, stdout, _ = runCLI(t, "findings", "get", "--json", findingID)
	var detail map[string]any
	if code != 0 || json.Unmarshal([]byte(stdout), &detail) != nil || detail["title"] != "Stored XSS" || detail["newField"] != "added later" {
		t.Errorf("exit %d, stdout %q", code, stdout)
	}
}

func TestFindingsGetErrors(t *testing.T) {
	apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"error":{"code":"not_found","message":"Finding not found"}}`)
	})
	code, _, stderr := runCLI(t, "findings", "get", findingID)
	if code != 1 || stderr != "heist findings get: HTTP 404: not_found: Finding not found\n" {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
	if code, _, _ := runCLI(t, "findings", "get", "not-a-uuid"); code != 2 {
		t.Errorf("invalid ID: exit %d, want 2", code)
	}
}

func TestFindingsCounts(t *testing.T) {
	var severityQueries []string
	apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/external/findings/counts":
			io.WriteString(w, `{"all":9,"open":5,"closed":2,"accepted":1,"compensatingControl":1,"newBucket":3}`)
		case "/external/findings":
			q := r.URL.Query()
			severityQueries = append(severityQueries, q.Get("severity")+" "+strings.Join(q["status"], ","))
			total := map[string]int{"CRITICAL": 1, "HIGH": 2, "MEDIUM": 2}[q.Get("severity")]
			fmt.Fprintf(w, `{"items":[],"total":%d,"page":1,"size":1}`, total)
		default:
			t.Errorf("unexpected request %s", r.URL)
		}
	})
	code, stdout, stderr := runCLI(t, "findings", "counts")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	want := `STATUS                COUNT
open                  5
closed                2
accepted              1
compensating control  1
all                   9

SEVERITY (PUBLISHED)  COUNT
CRITICAL              1
HIGH                  2
MEDIUM                2
LOW                   0
INFORMATIONAL         0
`
	if stdout != want {
		t.Errorf("stdout =\n%s\nwant\n%s", stdout, want)
	}
	if fmt.Sprint(severityQueries) != "[INFORMATIONAL PUBLISHED LOW PUBLISHED MEDIUM PUBLISHED HIGH PUBLISHED CRITICAL PUBLISHED]" {
		t.Errorf("severity queries = %v", severityQueries)
	}

	severityQueries = nil
	code, stdout, _ = runCLI(t, "findings", "counts", "--status", "fixed,accepted", "--json")
	var got struct {
		Status           map[string]int `json:"status"`
		Severity         map[string]int `json:"severity"`
		SeverityStatuses []string       `json:"severityStatuses"`
	}
	if code != 0 || json.Unmarshal([]byte(stdout), &got) != nil {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	if got.Status["open"] != 5 || got.Status["newBucket"] != 3 || got.Severity["HIGH"] != 2 || fmt.Sprint(got.SeverityStatuses) != "[FIXED ACCEPTED]" {
		t.Errorf("counts = %+v", got)
	}
	if severityQueries[0] != "INFORMATIONAL FIXED,ACCEPTED" {
		t.Errorf("severity query = %q", severityQueries[0])
	}
}
