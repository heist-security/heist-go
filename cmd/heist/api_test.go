package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// apiServer serves the OAuth token endpoint at /token and passes other
// requests to handler under /external.
func apiServer(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"test-token","token_type":"Bearer","expires_in":3600}`)
	})
	mux.Handle("/external/", handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Setenv("HEIST_CLIENT_ID", "id")
	t.Setenv("HEIST_CLIENT_SECRET", "secret")
	t.Setenv("HEIST_TOKEN_URL", srv.URL+"/token")
	t.Setenv("HEIST_SERVER_URL", srv.URL+"/external")
}

func TestAPIGet(t *testing.T) {
	apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/external/findings" || r.URL.RawQuery != "severity=high" {
			t.Errorf("request = %s %s", r.Method, r.URL)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q", got)
		}
		io.WriteString(w, `{"data":[]}`)
	})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"api", "/findings?severity=high"}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	if stdout.String() != `{"data":[]}` {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestAPIPostStdin(t *testing.T) {
	apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/external/domains" {
			t.Errorf("request = %s %s", r.Method, r.URL)
		}
		if string(body) != `{"name":"example.com"}` || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("body = %q, Content-Type = %q", body, r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusCreated)
	})
	var stdout, stderr bytes.Buffer
	stdin := strings.NewReader(`{"name":"example.com"}`)
	if code := run([]string{"api", "-X", "post", "--input", "-", "domains"}, stdin, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
}

func TestAPIInputDefaultsToPost(t *testing.T) {
	apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
	})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"api", "--input", "-", "/domains"}, strings.NewReader(`{}`), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
}

func TestAPIError(t *testing.T) {
	apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"error":{"code":"not_found","message":"Finding not found"}}`)
	})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"api", "/findings/x"}, nil, &stdout, &stderr); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if stderr.String() != "heist api: HTTP 404: not_found: Finding not found\n" {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestAPIMissingCredentials(t *testing.T) {
	t.Setenv("HEIST_CLIENT_ID", "")
	t.Setenv("HEIST_CLIENT_SECRET", "")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"api", "/findings"}, nil, &stdout, &stderr); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "HEIST_CLIENT_ID and HEIST_CLIENT_SECRET must be set") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestAPIUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"api"}, nil, &stdout, &stderr); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
}
