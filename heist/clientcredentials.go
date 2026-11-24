package heist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultTokenURL is the production Heist OAuth token endpoint.
const DefaultTokenURL = "https://identity.heist.security/oauth2/token"

// tokenRefreshMargin is how long before expiry a cached token is replaced, so
// a token does not expire while a request is in flight.
const tokenRefreshMargin = time.Minute

// ClientCredentials is a TokenSource that exchanges a Heist OAuth app's client
// ID and secret for access tokens using the OAuth 2.0 client_credentials
// grant. It caches each token and requests a new one shortly before the cached
// token expires.
//
// Use a pointer and don't copy it after first use. It is safe for concurrent
// use; concurrent callers share one exchange.
type ClientCredentials struct {
	ClientID     string
	ClientSecret string
	// TokenURL overrides DefaultTokenURL, for example to target a test server.
	TokenURL string
	// HTTPClient sends token requests. http.DefaultClient is used when nil.
	HTTPClient *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time
	now    func() time.Time // for tests; time.Now when nil
}

// Token returns the cached access token, exchanging the client credentials for
// a new one when there is none or it is about to expire.
func (c *ClientCredentials) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	if c.token != "" && now().Before(c.expiry.Add(-tokenRefreshMargin)) {
		return c.token, nil
	}
	token, expiresIn, err := c.exchange(ctx)
	if err != nil {
		return "", err
	}
	// A token without an expiry is not cached, so every call exchanges again.
	c.token, c.expiry = "", time.Time{}
	if expiresIn > 0 {
		c.token = token
		c.expiry = now().Add(time.Duration(expiresIn) * time.Second)
	}
	return token, nil
}

func (c *ClientCredentials) exchange(ctx context.Context) (token string, expiresIn int64, err error) {
	if c.ClientID == "" || c.ClientSecret == "" {
		return "", 0, errors.New("heist: client ID and client secret are required")
	}
	tokenURL := c.TokenURL
	if tokenURL == "" {
		tokenURL = DefaultTokenURL
	}
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("heist: token request: %w", err)
	}
	// client_secret_basic: RFC 6749 section 2.3.1 form-encodes both values
	// before Basic encoding.
	req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("heist: token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if err != nil {
		return "", 0, fmt.Errorf("heist: token request: %w", err)
	}

	var parsed struct {
		AccessToken      string `json:"access_token"`
		ExpiresIn        int64  `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	decodeErr := json.Unmarshal(body, &parsed)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The body is the RFC 6749 error response, which never contains the
		// request's client secret.
		if decodeErr == nil && parsed.Error != "" {
			return "", 0, fmt.Errorf("heist: token endpoint: HTTP %d: %s: %s",
				resp.StatusCode, parsed.Error, parsed.ErrorDescription)
		}
		return "", 0, fmt.Errorf("heist: token endpoint: HTTP %d %s",
			resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	if decodeErr != nil {
		return "", 0, fmt.Errorf("heist: token endpoint: decoding response: %w", decodeErr)
	}
	if parsed.AccessToken == "" {
		return "", 0, errors.New("heist: token endpoint: response has no access_token")
	}
	return parsed.AccessToken, parsed.ExpiresIn, nil
}
