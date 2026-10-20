package ovh

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: the signature of the OVHcloud API is SHA-1, which tsigoat cannot choose
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Endpoints of the API, by name, as the OVHcloud tools name them.
const (
	EndpointEU = "https://eu.api.ovh.com/1.0"
	EndpointCA = "https://ca.api.ovh.com/1.0"
	EndpointUS = "https://api.us.ovhcloud.com/1.0"
)

// EndpointURL returns the base URL of an endpoint named ovh-eu, ovh-ca or
// ovh-us, and whether the name is one of them.
func EndpointURL(name string) (string, bool) {
	switch name {
	case "ovh-eu":
		return EndpointEU, true
	case "ovh-ca":
		return EndpointCA, true
	case "ovh-us":
		return EndpointUS, true
	default:
		return "", false
	}
}

// SupportsOAuth2 reports whether the API at an endpoint accepts OAuth2
// service accounts: only the endpoints of OVHcloud do.
func SupportsOAuth2(endpoint string) bool {
	_, ok := tokenURL(endpoint)
	return ok
}

// tokenURL returns the URL of the OAuth2 token endpoint of an API endpoint.
func tokenURL(endpoint string) (string, bool) {
	switch endpoint {
	case EndpointEU:
		return "https://www.ovh.com/auth/oauth2/token", true
	case EndpointCA:
		return "https://ca.ovh.com/auth/oauth2/token", true
	case EndpointUS:
		return "https://us.ovhcloud.com/auth/oauth2/token", true
	default:
		return "", false
	}
}

// signer signs the requests with an application key, its secret and a
// consumer key, as the OVHcloud API requires: a SHA-1 digest of the secrets,
// the method, the URL, the body and the time of the API.
type signer struct {
	applicationKey, applicationSecret, consumerKey string
	// clock returns the time of the API.
	clock *clock
}

func (s *signer) authorize(req *http.Request, body []byte) error {
	now, err := s.clock.now(req.Context())
	if err != nil {
		return err
	}
	timestamp := strconv.FormatInt(now.Unix(), 10)
	digest := sha1.Sum([]byte(strings.Join([]string{ //nolint:gosec // G401: the signature of the OVHcloud API is SHA-1
		s.applicationSecret, s.consumerKey, req.Method, req.URL.String(), string(body), timestamp,
	}, "+")))
	req.Header.Set("X-Ovh-Application", s.applicationKey)
	req.Header.Set("X-Ovh-Consumer", s.consumerKey)
	req.Header.Set("X-Ovh-Timestamp", timestamp)
	req.Header.Set("X-Ovh-Signature", "$1$"+hex.EncodeToString(digest[:]))
	return nil
}

// clock tells the time of the API, which the signatures carry: the API turns
// down the requests signed more than two minutes away from its own time. It
// asks the API, then keeps the difference with the local clock for an hour.
type clock struct {
	// fetch returns the time of the API.
	fetch func(ctx context.Context) (time.Time, error)

	mu      sync.Mutex
	delta   time.Duration
	fetched time.Time
}

// clockLifetime is the time for which the clock keeps the difference
// between the local clock and the one of the API.
const clockLifetime = time.Hour

func (c *clock) now(ctx context.Context) (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fetched.IsZero() || time.Since(c.fetched) > clockLifetime {
		api, err := c.fetch(ctx)
		if err != nil {
			return time.Time{}, fmt.Errorf("reading the time of the OVHcloud API: %w", err)
		}
		c.delta, c.fetched = time.Until(api), time.Now()
	}
	return time.Now().Add(c.delta), nil
}

// reset makes the clock ask the API again.
func (c *clock) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fetched = time.Time{}
}

// tokenSource gets the access tokens of an OAuth2 service account, with the
// client credentials grant, and keeps each one until shortly before it
// expires.
type tokenSource struct {
	url                    string
	clientID, clientSecret string
	client                 *http.Client
	timeout                time.Duration
	userAgent              string

	mu      sync.Mutex
	token   string
	expires time.Time
}

// tokenMargin is the time before its expiry when a token is renewed.
const tokenMargin = time.Minute

func (s *tokenSource) authorize(req *http.Request, _ []byte) error {
	token, err := s.get(req.Context())
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (s *tokenSource) get(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Now().Before(s.expires) {
		return s.token, nil
	}
	token, lifetime, err := s.fetch(ctx)
	if err != nil {
		return "", fmt.Errorf("getting an OAuth2 access token from %s: %w", s.url, err)
	}
	// Renew the token a minute before its expiry, or halfway through a
	// shorter lifetime.
	s.token, s.expires = token, time.Now().Add(lifetime-min(tokenMargin, lifetime/2))
	return token, nil
}

func (s *tokenSource) fetch(ctx context.Context) (token string, lifetime time.Duration, err error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"all"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("building the request: %w", err)
	}
	req.SetBasicAuth(url.QueryEscape(s.clientID), url.QueryEscape(s.clientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if s.userAgent != "" {
		req.Header.Set("User-Agent", s.userAgent)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", 0, err //nolint:wrapcheck // the caller names the endpoint
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", 0, fmt.Errorf("reading the response: %w", err)
	}
	var response struct {
		AccessToken      string `json:"access_token"`
		ExpiresIn        int64  `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(data, &response)
	switch {
	case resp.StatusCode != http.StatusOK:
		message := strings.TrimSpace(response.Error + ": " + response.ErrorDescription)
		if response.Error == "" {
			message = strings.Join(strings.Fields(string(data[:min(len(data), 256)])), " ")
		}
		return "", 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, message)
	case response.AccessToken == "":
		return "", 0, errors.New("no access token in the response")
	}
	return response.AccessToken, time.Duration(max(response.ExpiresIn, 0)) * time.Second, nil
}
