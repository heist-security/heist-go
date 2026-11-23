package heist

import (
	"context"
	"errors"
	"net/http"
)

// APIVersion is the published Heist REST contract version this SDK targets.
// It must match api/openapi.lock.json; a test enforces this.
const APIVersion = "2.4.0"

// DefaultServerURL is the production Heist external REST API.
const DefaultServerURL = "https://api.heisthq.com/external"

const defaultUserAgent = "heist-go"

// TokenSource supplies the OAuth app access token sent with each request.
// Implementations may refresh tokens and must be safe for concurrent use.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken is a TokenSource that always returns the same access token.
type StaticToken string

// Token returns the access token, or an error when it is empty.
func (t StaticToken) Token(context.Context) (string, error) {
	if t == "" {
		return "", errors.New("heist: access token is empty")
	}
	return string(t), nil
}

// Config configures New. The zero value targets DefaultServerURL with
// http.DefaultClient.
type Config struct {
	// ServerURL overrides DefaultServerURL, for example to target a test
	// server. It includes the /external path prefix.
	ServerURL string
	// HTTPClient sends requests. http.DefaultClient is used when nil.
	HTTPClient *http.Client
	// UserAgent identifies the consumer, for example "heist-cli/1.2.3". It is
	// sent before the SDK's own "heist-go" product token.
	UserAgent string
}

// New returns a client for the Heist external REST API authenticated by tokens.
//
// Every non-2xx response is returned as an *APIError, so a nil error means the
// call succeeded and the response's success field (JSON200, JSON201 or
// JSON202) is set.
func New(tokens TokenSource, cfg Config) (*ClientWithResponses, error) {
	if tokens == nil {
		return nil, errors.New("heist: token source is nil")
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = DefaultServerURL
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	userAgent := defaultUserAgent
	if cfg.UserAgent != "" {
		userAgent = cfg.UserAgent + " " + defaultUserAgent
	}
	return NewClientWithResponses(cfg.ServerURL, WithHTTPClient(&doer{
		client:    cfg.HTTPClient,
		tokens:    tokens,
		userAgent: userAgent,
	}))
}

// doer authenticates requests and converts error responses into *APIError.
type doer struct {
	client    *http.Client
	tokens    TokenSource
	userAgent string
}

func (d *doer) Do(req *http.Request) (*http.Response, error) {
	token, err := d.tokens.Token(req.Context())
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", d.userAgent)
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		return nil, newAPIError(resp)
	}
	return resp, nil
}
