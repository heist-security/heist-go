package heist

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// tokenServer is a local stand-in for the OAuth token endpoint. It issues
// "token-1", "token-2", ... each valid for expiresIn seconds.
type tokenServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests int
}

func newTokenServer(t *testing.T, expiresIn int) *tokenServer {
	t.Helper()
	ts := &tokenServer{}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/oauth2/token" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if got := r.PostForm.Get("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q", got)
		}
		if r.PostForm.Has("client_secret") {
			t.Error("client secret sent in the request body")
		}
		if id, secret, ok := r.BasicAuth(); !ok || id != "test-id" || secret != "test-secret" {
			t.Errorf("Basic auth = %q, %q, %v", id, secret, ok)
		}
		ts.mu.Lock()
		ts.requests++
		n := ts.requests
		ts.mu.Unlock()
		writeJSON(w, http.StatusOK, fmt.Sprintf(
			`{"access_token":"token-%d","token_type":"bearer","expires_in":%d}`, n, expiresIn))
	}))
	t.Cleanup(ts.Close)
	return ts
}

func (ts *tokenServer) count() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.requests
}

func (ts *tokenServer) credentials() *ClientCredentials {
	return &ClientCredentials{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		TokenURL:     ts.URL + "/oauth2/token",
		HTTPClient:   ts.Client(),
	}
}

func mustToken(t *testing.T, ts TokenSource) string {
	t.Helper()
	token, err := ts.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestClientCredentialsCachesAndRefreshes(t *testing.T) {
	server := newTokenServer(t, 3600)
	creds := server.credentials()
	for range 2 {
		if got := mustToken(t, creds); got != "token-1" {
			t.Errorf("token = %q, want cached token-1", got)
		}
	}
	if got := server.count(); got != 1 {
		t.Errorf("token requests = %d, want 1", got)
	}

	// A token that expires within x/oauth2's 10-second margin is replaced on
	// every call.
	server = newTokenServer(t, 5)
	creds = server.credentials()
	for _, want := range []string{"token-1", "token-2"} {
		if got := mustToken(t, creds); got != want {
			t.Errorf("token near expiry = %q, want %s", got, want)
		}
	}
}

func TestClientCredentialsSharesConcurrentExchange(t *testing.T) {
	server := newTokenServer(t, 3600)
	creds := server.credentials()

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if got := mustToken(t, creds); got != "token-1" {
				t.Errorf("token = %q", got)
			}
		})
	}
	wg.Wait()
	if got := server.count(); got != 1 {
		t.Errorf("token requests = %d, want 1", got)
	}
}

func TestClientCredentialsAuthenticatesClient(t *testing.T) {
	tokens := newTokenServer(t, 3600)
	client := newTestClientWithTokens(t, tokens.credentials(), func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token-1" {
			t.Errorf("Authorization = %q", got)
		}
		writeJSON(w, http.StatusOK, `{"all":0,"open":0,"closed":0,"accepted":0,"compensatingControl":0}`)
	})
	if _, err := client.FindingCountsWithResponse(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestClientCredentialsErrors(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{
			name:    "oauth error",
			status:  http.StatusUnauthorized,
			body:    `{"error":"invalid_client","error_description":"Client authentication failed"}`,
			wantErr: `heist: token endpoint: oauth2: "invalid_client" "Client authentication failed"`,
		},
		{
			name:    "non-json error",
			status:  http.StatusBadGateway,
			body:    `<html>Bad gateway</html>`,
			wantErr: "heist: token endpoint: oauth2: cannot fetch token: 502 Bad Gateway\nResponse: <html>Bad gateway</html>",
		},
		{
			name:    "missing access token",
			status:  http.StatusOK,
			body:    `{"token_type":"bearer","expires_in":3600}`,
			wantErr: "heist: token endpoint: oauth2: server response missing access_token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, tt.status, tt.body)
			}))
			t.Cleanup(server.Close)
			creds := &ClientCredentials{
				ClientID:     "test-id",
				ClientSecret: "test-secret",
				TokenURL:     server.URL,
				HTTPClient:   server.Client(),
			}
			_, err := creds.Token(context.Background())
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), "test-secret") {
				t.Errorf("error exposes the client secret: %v", err)
			}
		})
	}
}

func TestClientCredentialsRequiresIDAndSecret(t *testing.T) {
	for _, creds := range []*ClientCredentials{
		{ClientSecret: "test-secret"},
		{ClientID: "test-id"},
	} {
		_, err := creds.Token(context.Background())
		if err == nil || !strings.Contains(err.Error(), "client ID and client secret are required") {
			t.Errorf("Token(%q) error = %v", creds.ClientID, err)
		}
	}
}
