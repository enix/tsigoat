package hosted

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// maxResponseSize bounds the responses read from an API.
	maxResponseSize = 16 << 20
	// maxErrorSize bounds the part of an error response kept in the error.
	maxErrorSize = 4096
	// attempts bounds the attempts of a request.
	attempts = 3
	// defaultBackoff is the default of API.Backoff.
	defaultBackoff = 500 * time.Millisecond
	// maxBackoff bounds the delay that tsigoat chooses before another
	// attempt, when the API asks for none.
	maxBackoff = 5 * time.Second
	// maxRetryAfter bounds the delay that the API may ask for: a request
	// that it asks to send later than that fails at once.
	maxRetryAfter = time.Minute
)

// API calls the HTTP API of a provider, in JSON.
type API struct {
	// Provider names the provider in errors, such as "Cloudflare".
	Provider string
	// Base is the base URL of the API, without a trailing slash.
	Base string
	// Client sends the requests; it must follow no redirect, so that a
	// redirect is an error rather than a write turned into a read.
	Client *http.Client
	// Timeout bounds every attempt of a request.
	Timeout time.Duration
	// UserAgent identifies tsigoat.
	UserAgent string
	// Authorize authenticates a request, whose body it gets.
	Authorize func(req *http.Request, body []byte) error
	// Describe extracts the message and the code of an error response, from
	// its headers and its body; the message is the start of the body when
	// Describe is nil or finds none.
	Describe func(header http.Header, body []byte) (message, code string)
	// Backoff is the delay before the second attempt of a request, which
	// doubles for the next one, when the API sets no Retry-After header;
	// half a second when zero.
	Backoff time.Duration

	// wait replaces the waits between attempts, in tests.
	wait func(ctx context.Context, delay time.Duration) error
}

// HTTPError is an error response of an API.
type HTTPError struct {
	Provider string
	Method   string
	// Path is the path of the request, under the base URL.
	Path   string
	Status int
	// Message is the message of the provider.
	Message string
	// Code is the error code of the provider, "" when it gives none.
	Code string
}

func (e *HTTPError) Error() string {
	message := fmt.Sprintf("%s API: %s %s: HTTP %d", e.Provider, e.Method, e.Path, e.Status)
	if e.Message != "" {
		message += ": " + e.Message
	}
	return message
}

// StatusOf returns the HTTP status of an error response, 0 for other errors.
func StatusOf(err error) int {
	if httpErr, ok := errors.AsType[*HTTPError](err); ok {
		return httpErr.Status
	}
	return 0
}

// Ambiguous reports whether the outcome of a write that failed with err is
// unknown, as after a timeout, a lost connection or a server error: the
// provider may have applied it.
func Ambiguous(err error) bool {
	status := StatusOf(err)
	return status == 0 || status >= http.StatusInternalServerError
}

// CodeOf returns the error code of an error response, "" for other errors.
func CodeOf(err error) string {
	if httpErr, ok := errors.AsType[*HTTPError](err); ok {
		return httpErr.Code
	}
	return ""
}

// Do sends a request, with in as its JSON body unless nil, and decodes the
// JSON response into out unless nil. A request turned down with 429 Too Many
// Requests goes again after the delay of its Retry-After header, or a short
// backoff without one, as does a GET request that failed on the way or got
// 408, 502, 503 or 504. A request that the deadline of ctx would interrupt
// before its next attempt fails at once, rather than going earlier than the
// API asks.
func (a *API) Do(ctx context.Context, method, path string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return fmt.Errorf("encoding the request: %w", err)
		}
	}
	for attempt := 1; ; attempt++ {
		retry, err := a.attempt(ctx, method, path, body, out)
		if err == nil || !retry.again || attempt == attempts {
			return err
		}
		// The delay that the API asks for holds whole: when the deadline
		// leaves no time for it, the request fails at once.
		delay := retry.after
		if !retry.asked {
			delay = min(cmp.Or(a.Backoff, defaultBackoff)<<(attempt-1), maxBackoff)
		}
		if delay > maxRetryAfter {
			return err
		}
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < delay {
			return err
		}
		if a.sleep(ctx, delay) != nil {
			return err
		}
	}
}

// sleep waits for a delay, unless ctx ends first.
func (a *API) sleep(ctx context.Context, delay time.Duration) error {
	if a.wait != nil {
		return a.wait(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("waiting %s before another attempt: %w", delay, ctx.Err())
	case <-timer.C:
		return nil
	}
}

// retry tells whether to send a request again, and when.
type retry struct {
	again bool
	// asked tells that the API asked for a delay, after.
	asked bool
	after time.Duration
}

// attempt sends a request once.
func (a *API) attempt(ctx context.Context, method, path string, body []byte, out any) (retry, error) {
	ctx, cancel := context.WithTimeout(ctx, a.Timeout)
	defer cancel()

	var payload io.Reader
	if body != nil {
		payload = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.Base+path, payload)
	if err != nil {
		return retry{}, fmt.Errorf("building the request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.UserAgent != "" {
		req.Header.Set("User-Agent", a.UserAgent)
	}
	if authErr := a.Authorize(req, body); authErr != nil {
		return retry{}, authErr
	}

	resp, err := a.Client.Do(req)
	if err != nil {
		// A write may have applied before the failure: only reads go again.
		return retry{again: method == http.MethodGet && ctx.Err() == nil}, fmt.Errorf("%s API: %w", a.Provider, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return retry{}, fmt.Errorf("%s API: reading the response: %w", a.Provider, err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return retryOf(method, resp), a.httpError(method, path, resp, data)
	}
	if out == nil {
		return retry{}, nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return retry{}, fmt.Errorf("%s API: decoding the response to %s %s: %w", a.Provider, method, path, err)
	}
	return retry{}, nil
}

func (a *API) httpError(method, path string, resp *http.Response, data []byte) error {
	httpErr := &HTTPError{Provider: a.Provider, Method: method, Path: path, Status: resp.StatusCode}
	if a.Describe != nil {
		httpErr.Message, httpErr.Code = a.Describe(resp.Header, data)
	}
	if httpErr.Message == "" {
		httpErr.Message = strings.Join(strings.Fields(string(data[:min(len(data), maxErrorSize)])), " ")
	}
	if location := resp.Header.Get("Location"); resp.StatusCode/100 == 3 && location != "" {
		httpErr.Message = "redirected to " + location
	}
	return httpErr
}

// retryOf tells whether to send again a request that got resp: after 429 Too
// Many Requests, which applied nothing, and for a GET request after 408, 502,
// 503 or 504.
func retryOf(method string, resp *http.Response) retry {
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
	case http.StatusRequestTimeout, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		if method != http.MethodGet {
			return retry{}
		}
	default:
		return retry{}
	}
	r := retry{again: true}
	r.after, r.asked = retryAfter(resp.Header.Get("Retry-After"), time.Now())
	return r
}

// retryAfter returns the delay of a Retry-After header, and whether it holds
// one: a number of seconds, or an HTTP date (RFC 9110 10.2.3). A date in the
// past asks for no delay; a delay beyond maxRetryAfter reads as one just
// beyond it.
func retryAfter(value string, now time.Time) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseUint(value, 10, 64); err == nil {
		if seconds > uint64(maxRetryAfter/time.Second) {
			return maxRetryAfter + time.Second, true
		}
		return time.Duration(seconds) * time.Second, true
	}
	date, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	delay := date.Sub(now)
	switch {
	case delay < 0:
		return 0, true
	case delay > maxRetryAfter:
		return maxRetryAfter + time.Second, true
	default:
		return delay, true
	}
}
