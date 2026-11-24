package heist

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	creds.now = func() time.Time { return now }

	if got := mustToken(t, creds); got != "token-1" {
		t.Fatalf("first token = %q", got)
	}
	now = now.Add(58 * time.Minute)
	if got := mustToken(t, creds); got != "token-1" {
		t.Errorf("token before refresh margin = %q, want cached token-1", got)
	}
	// Within a minute of expiry the token is replaced.
	now = now.Add(time.Minute + time.Second)
	if got := mustToken(t, creds); got != "token-2" {
		t.Errorf("token near expiry = %q, want token-2", got)
	}
	if got := server.count(); got != 2 {
		t.Errorf("token requests = %d, want 2", got)
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
			wantErr: "heist: token endpoint: HTTP 401: invalid_client: Client authentication failed",
		},
		{
			name:    "non-json error",
			status:  http.StatusBadGateway,
			body:    `<html>Bad gateway</html>`,
			wantErr: "heist: token endpoint: HTTP 502 Bad Gateway",
		},
		{
			name:    "missing access token",
			status:  http.StatusOK,
			body:    `{"token_type":"bearer","expires_in":3600}`,
			wantErr: "heist: token endpoint: response has no access_token",
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

func TestClientCredentialsWaitingCallerHonorsContext(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		writeJSON(w, http.StatusOK, `{"access_token":"token-1","expires_in":3600}`)
	}))
	t.Cleanup(server.Close)
	creds := &ClientCredentials{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		TokenURL:     server.URL,
		HTTPClient:   server.Client(),
	}

	// The first caller holds the exchange open until release is closed.
	done := make(chan struct{})
	go func() {
		defer close(done)
		mustToken(t, creds)
	}()
	<-started
	timer := time.AfterFunc(2*time.Second, func() { close(release) })
	t.Cleanup(func() {
		if timer.Stop() {
			close(release)
		}
		<-done
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if token, err := creds.Token(ctx); err != context.DeadlineExceeded {
		t.Errorf("waiting Token = %q, %v; want %v", token, err, context.DeadlineExceeded)
	}
}
