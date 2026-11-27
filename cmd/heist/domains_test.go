package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

const (
	domainID   = "6b7c8d9e-0f1a-4b2c-9d4e-5f6a7b8c9d0e"
	domainJSON = `{"id":"` + domainID + `","domain":"example.com","verified":false,"autoInclude":true,` +
		`"inScope":true,"createdAt":"2026-11-01T00:00:00Z","updatedAt":"2026-11-02T00:00:00Z","newField":"added later"}`
	domainTable = "ID                                    DOMAIN       VERIFIED  IN SCOPE  AUTO-INCLUDE\n" +
		domainID + "  example.com  no        yes       yes\n"
)

func challengeJSON(verified string) string {
	return `{"domainId":"` + domainID + `","domain":"example.com","recordType":"TXT",` +
		`"recordName":"_heist-challenge.example.com","recordValue":"heist-verification=abc123",` +
		`"verified":` + verified + `,"provider":{"key":"cloudflare","name":"Cloudflare","dashboardUrl":"https://dash.example"}}`
}

func TestDomainsListAndGet(t *testing.T) {
	reportsServer(t, map[string]http.HandlerFunc{
		"GET /domains": respondJSON(http.StatusOK, "["+domainJSON+"]"),
		"GET /domains/{id}": func(w http.ResponseWriter, r *http.Request) {
			if r.PathValue("id") != domainID {
				t.Errorf("id = %q", r.PathValue("id"))
			}
			respondJSON(http.StatusOK, domainJSON)(w, r)
		},
	})
	code, stdout, stderr := runCLI(t, "domains", "list")
	if code != 0 || stdout != domainTable {
		t.Errorf("list: exit %d, stderr %q, stdout =\n%s\nwant\n%s", code, stderr, stdout, domainTable)
	}

	code, stdout, stderr = runCLI(t, "domains", "get", domainID)
	want := "Domain:        example.com\n" +
		"ID:            " + domainID + "\n" +
		"Verified:      no\n" +
		"In scope:      yes\n" +
		"Auto-include:  yes\n" +
		"Created:       2026-11-01T00:00:00Z\n" +
		"Updated:       2026-11-02T00:00:00Z\n"
	if code != 0 || stdout != want {
		t.Errorf("get: exit %d, stderr %q, stdout =\n%s\nwant\n%s", code, stderr, stdout, want)
	}

	for _, args := range [][]string{{"list", "--json"}, {"get", "--json", domainID}} {
		code, stdout, _ := runCLI(t, append([]string{"domains"}, args...)...)
		if code != 0 || !strings.Contains(stdout, `"newField": "added later"`) {
			t.Errorf("%v: exit %d, --json dropped fields added later:\n%s", args, code, stdout)
		}
	}
}

func TestDomainsStatus(t *testing.T) {
	for _, tt := range []struct {
		name, body, stdout string
		code               int
	}{
		{"verified", `{"verified":true,"unverifiedDomain":null}`, "Verified: yes\n", 0},
		{"unverified", `{"verified":false,"unverifiedDomain":` + domainJSON + `}`,
			"Verified: no\n\nUnverified domain:\n" + domainTable, exitNotVerified},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reportsServer(t, map[string]http.HandlerFunc{
				"GET /domains/verification-status": respondJSON(http.StatusOK, tt.body),
			})
			code, stdout, stderr := runCLI(t, "domains", "status")
			if code != tt.code || stdout != tt.stdout {
				t.Errorf("exit %d, want %d, stderr %q, stdout =\n%s\nwant\n%s", code, tt.code, stderr, stdout, tt.stdout)
			}
			if tt.code == exitNotVerified && stderr != "heist domains status: not all in-scope domains are verified\n" {
				t.Errorf("stderr = %q", stderr)
			}
		})
	}
}

func TestDomainsAutoInclude(t *testing.T) {
	var bodies []string
	reportsServer(t, map[string]http.HandlerFunc{
		"POST /domains/{id}/auto-include": func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			bodies = append(bodies, r.PathValue("id")+" "+strings.TrimSpace(string(b)))
			respondJSON(http.StatusOK, domainJSON)(w, r)
		},
	})
	for _, flag := range []string{"--on", "--off"} {
		code, stdout, stderr := runCLI(t, "domains", "auto-include", domainID, flag)
		if code != 0 || stdout != domainTable {
			t.Errorf("%s: exit %d, stderr %q, stdout =\n%s", flag, code, stderr, stdout)
		}
	}
	want := domainID + ` {"autoInclude":true}` + "\n" + domainID + ` {"autoInclude":false}`
	if got := strings.Join(bodies, "\n"); got != want {
		t.Errorf("requests =\n%s\nwant\n%s", got, want)
	}
}

func TestDomainsAutoIncludeShowsAPIError(t *testing.T) {
	reportsServer(t, map[string]http.HandlerFunc{
		"POST /domains/{id}/auto-include": respondJSON(http.StatusForbidden, `{"error":{"code":"FORBIDDEN","message":"Admin role required"}}`),
	})
	code, stdout, stderr := runCLI(t, "domains", "auto-include", "--on", domainID)
	if code != 1 || stdout != "" || stderr != "heist domains auto-include: HTTP 403: FORBIDDEN: Admin role required\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestDomainsChallenge(t *testing.T) {
	var requests []string
	issued := false
	reportsServer(t, map[string]http.HandlerFunc{
		"GET /domains/{id}/verification-challenge": func(w http.ResponseWriter, r *http.Request) {
			requests = append(requests, "GET")
			if !issued {
				respondJSON(http.StatusOK, "null")(w, r)
				return
			}
			respondJSON(http.StatusOK, challengeJSON("false"))(w, r)
		},
		"POST /domains/{id}/verification-challenge": func(w http.ResponseWriter, r *http.Request) {
			requests = append(requests, "POST")
			issued = true
			respondJSON(http.StatusOK, challengeJSON("false"))(w, r)
		},
	})

	code, stdout, stderr := runCLI(t, "domains", "challenge", domainID)
	if code != 1 || stdout != "" || stderr != "heist domains challenge: no challenge has been issued; issue one with --create\n" {
		t.Errorf("no challenge: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	code, stdout, stderr = runCLI(t, "domains", "challenge", "--create", domainID)
	want := "Domain:         example.com\n" +
		"Domain ID:      " + domainID + "\n" +
		"Verified:       no\n" +
		"Record name:    _heist-challenge.example.com\n" +
		"Record type:    TXT\n" +
		"Record value:   heist-verification=abc123\n" +
		"DNS provider:   Cloudflare\n" +
		"DNS dashboard:  https://dash.example\n"
	if code != 0 || stdout != want {
		t.Errorf("--create: exit %d, stderr %q, stdout =\n%s\nwant\n%s", code, stderr, stdout, want)
	}

	code, stdout, stderr = runCLI(t, "domains", "challenge", "--value", domainID)
	if code != 0 || stdout != "heist-verification=abc123\n" {
		t.Errorf("--value: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	code, stdout, _ = runCLI(t, "domains", "challenge", "--json", domainID)
	if code != 0 || !strings.Contains(stdout, `"recordValue": "heist-verification=abc123"`) {
		t.Errorf("--json: exit %d, stdout %q", code, stdout)
	}

	if got, want := strings.Join(requests, " "), "GET POST GET GET"; got != want {
		t.Errorf("requests = %s, want %s", got, want)
	}
}

func TestDomainsVerify(t *testing.T) {
	for _, tt := range []struct {
		verified string
		code     int
	}{
		{"true", 0},
		{"false", exitNotVerified},
	} {
		t.Run(tt.verified, func(t *testing.T) {
			reportsServer(t, map[string]http.HandlerFunc{
				"POST /domains/{id}/verify": respondJSON(http.StatusOK, challengeJSON(tt.verified)),
			})
			code, stdout, stderr := runCLI(t, "domains", "verify", domainID)
			if code != tt.code {
				t.Fatalf("exit %d, want %d, stderr %q", code, tt.code, stderr)
			}
			if !strings.Contains(stdout, "Verified:       "+yesNo(tt.verified == "true")+"\n") {
				t.Errorf("stdout =\n%s", stdout)
			}
			if tt.code == exitNotVerified && stderr != "heist domains verify: example.com is not verified\n" {
				t.Errorf("stderr = %q", stderr)
			}
		})
	}
}

func TestDomainsUsageErrors(t *testing.T) {
	t.Setenv("HEIST_CLIENT_ID", "")
	for _, tt := range []struct {
		args []string
		msg  string
	}{
		{[]string{"domains"}, ""},
		{[]string{"domains", "nope"}, `heist domains: unknown command "nope"`},
		{[]string{"domains", "list", "x"}, "heist domains list: unexpected arguments"},
		{[]string{"domains", "status", "x"}, "heist domains status: unexpected arguments"},
		{[]string{"domains", "get"}, "heist domains get: expected one domain ID"},
		{[]string{"domains", "get", "x"}, `heist domains get: invalid ID "x"`},
		{[]string{"domains", "auto-include", domainID}, "heist domains auto-include: expected one of --on or --off"},
		{[]string{"domains", "auto-include", "--on", "--off", domainID}, "heist domains auto-include: expected one of --on or --off"},
		{[]string{"domains", "challenge", "--value", "--json", domainID}, "heist domains challenge: --value and --json can't be used together"},
		{[]string{"domains", "verify"}, "heist domains verify: expected one domain ID"},
	} {
		code, stdout, stderr := runCLI(t, tt.args...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, tt.msg) || !strings.Contains(stderr, "Usage:\n  heist domains") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", tt.args, code, stdout, stderr)
		}
	}
}

func TestDomainsHelp(t *testing.T) {
	for _, args := range [][]string{
		{"domains", "-h"},
		{"domains", "challenge", "--help"},
		{"domains", "verify", "-h"},
	} {
		code, stdout, stderr := runCLI(t, args...)
		if code != 0 || stderr != "" || !strings.Contains(stdout, "Usage:\n  heist domains") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
	}
}
