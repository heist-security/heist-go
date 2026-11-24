package heist

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// DefaultTokenURL is the production Heist OAuth token endpoint.
const DefaultTokenURL = "https://identity.heist.security/oauth2/token"

// defaultTokenClient sends token requests when ClientCredentials.HTTPClient is
// nil. Token requests don't use the caller's context, so the timeout stops a
// stalled token endpoint from blocking every request indefinitely.
var defaultTokenClient = &http.Client{Timeout: 30 * time.Second}

// ClientCredentials is a TokenSource that exchanges a Heist OAuth app's client
// ID and secret for access tokens using the OAuth 2.0 client_credentials
// grant, via golang.org/x/oauth2. It caches each token and requests a new one
// shortly before the cached token expires. A token without an expiry is reused
// indefinitely.
//
// Token requests don't use the context passed to Token, so cancelling it
// doesn't stop a caller from waiting; the HTTP client's timeout bounds each
// token request instead. Concurrent callers wait for a single exchange. When it
// fails, each waiting caller makes its own attempt in turn, so a caller can
// wait for several timeouts while the token endpoint is unavailable.
//
// Use a pointer and don't copy it or change its fields after first use. It is
// safe for concurrent use.
type ClientCredentials struct {
	ClientID     string
	ClientSecret string
	// TokenURL overrides DefaultTokenURL, for example to target a test server.
	TokenURL string
	// HTTPClient sends token requests. When nil, a client with a 30-second
	// timeout is used.
	HTTPClient *http.Client

	init   sync.Once
	source oauth2.TokenSource
}

// Token returns the cached access token, exchanging the client credentials for
// a new one when there is none or it is about to expire.
func (c *ClientCredentials) Token(context.Context) (string, error) {
	if c.ClientID == "" || c.ClientSecret == "" {
		return "", errors.New("heist: client ID and client secret are required")
	}
	c.init.Do(func() {
		tokenURL := c.TokenURL
		if tokenURL == "" {
			tokenURL = DefaultTokenURL
		}
		client := c.HTTPClient
		if client == nil {
			client = defaultTokenClient
		}
		cfg := &clientcredentials.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			TokenURL:     tokenURL,
			AuthStyle:    oauth2.AuthStyleInHeader,
		}
		c.source = cfg.TokenSource(context.WithValue(context.Background(), oauth2.HTTPClient, client))
	})
	token, err := c.source.Token()
	if err != nil {
		return "", fmt.Errorf("heist: token endpoint: %w", err)
	}
	return token.AccessToken, nil
}
