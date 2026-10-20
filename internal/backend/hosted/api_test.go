package hosted_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enix/tsigoat/internal/backend/hosted"
	"github.com/enix/tsigoat/internal/backend/httpclient"
)

// newAPI returns a client of the API that handler serves, which signs the
// requests with a header holding their body.
func newAPI(t *testing.T, handler http.HandlerFunc) *hosted.API {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := httpclient.New(&httpclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return &hosted.API{
		Provider:  "Provider",
		Base:      server.URL,
		Client:    client,
		Timeout:   time.Second,
		UserAgent: "tsigoat/test",
		Backoff:   time.Millisecond,
		Authorize: func(req *http.Request, body []byte) error {
			req.Header.Set("X-Signature", "signed:"+string(body))
			return nil
		},
		Describe: func(_ http.Header, body []byte) (message, code string) {
			var parsed struct {
				Message string `json:"message"`
				Code    string `json:"code"`
			}
			_ = json.Unmarshal(body, &parsed)
			return parsed.Message, parsed.Code
		},
	}
}

func TestDo(t *testing.T) {
	t.Parallel()
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.Header.Get("X-Signature") != "signed:"+string(body):
			w.WriteHeader(http.StatusUnauthorized)
		case r.Header.Get("User-Agent") != "tsigoat/test" || r.Header.Get("Accept") != "application/json":
			w.WriteHeader(http.StatusBadRequest)
		case r.Method == http.MethodPost && r.Header.Get("Content-Type") != "application/json":
			w.WriteHeader(http.StatusUnsupportedMediaType)
		case len(body) == 0:
			_, _ = w.Write([]byte(`{"echo": "get"}`))
		default:
			_, _ = w.Write([]byte(`{"echo": ` + string(body) + `}`))
		}
	})

	var out struct {
		Echo any `json:"echo"`
	}
	if err := api.Do(t.Context(), http.MethodGet, "/get?x=1", nil, &out); err != nil || out.Echo != "get" {
		t.Errorf("GET: %v, %v", out, err)
	}
	if err := api.Do(t.Context(), http.MethodPost, "/post", map[string]string{"a": "b"}, &out); err != nil {
		t.Errorf("POST: %v", err)
	}
	if echo, ok := out.Echo.(map[string]any); !ok || echo["a"] != "b" {
		t.Errorf("POST echoed %v", out.Echo)
	}
	if err := api.Do(t.Context(), http.MethodDelete, "/delete", nil, nil); err != nil {
		t.Errorf("DELETE: %v", err)
	}
}

func TestDoErrors(t *testing.T) {
	t.Parallel()
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/json":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message": "not allowed", "code": "denied"}`))
		case "/text":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("  internal\n  error  "))
		case "/redirect":
			http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
		case "/garbage":
			_, _ = w.Write([]byte("not json"))
		}
	})
	var out struct{}
	for path, want := range map[string]string{
		"/json":     "Provider API: GET /json: HTTP 403: not allowed",
		"/text":     "Provider API: GET /text: HTTP 500: internal error",
		"/redirect": "Provider API: GET /redirect: HTTP 302: redirected to https://elsewhere.example/",
		"/garbage":  "decoding the response to GET /garbage",
	} {
		err := api.Do(t.Context(), http.MethodGet, path, nil, &out)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("GET %s: %v, want %q", path, err, want)
		}
	}
	err := api.Do(t.Context(), http.MethodGet, "/json", nil, nil)
	if hosted.StatusOf(err) != http.StatusForbidden || hosted.StatusOf(errors.New("other")) != 0 {
		t.Errorf("StatusOf(%v) = %d", err, hosted.StatusOf(err))
	}
	if hosted.CodeOf(err) != "denied" || hosted.CodeOf(errors.New("other")) != "" {
		t.Errorf("CodeOf(%v) = %q", err, hosted.CodeOf(err))
	}
}

func TestDoRetries(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		switch {
		case r.URL.Path == "/limited" && n == 1:
			w.WriteHeader(http.StatusTooManyRequests)
		case r.URL.Path == "/unavailable" && n < 3:
			w.WriteHeader(http.StatusServiceUnavailable)
		case r.URL.Path == "/always":
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			_, _ = w.Write([]byte("{}"))
		}
	})
	for _, c := range []struct {
		method, path string
		calls        int32
		fails        bool
	}{
		{method: http.MethodPost, path: "/limited", calls: 2},
		{method: http.MethodGet, path: "/unavailable", calls: 3},
		{method: http.MethodPost, path: "/unavailable", calls: 1, fails: true},
		{method: http.MethodGet, path: "/always", calls: 3, fails: true},
	} {
		calls.Store(0)
		err := api.Do(t.Context(), c.method, c.path, nil, nil)
		if (err != nil) != c.fails || calls.Load() != c.calls {
			t.Errorf("%s %s: %v after %d calls, want %d calls", c.method, c.path, err, calls.Load(), c.calls)
		}
	}
}

// TestDoDeadline checks that no attempt starts that the deadline would cut:
// the API asks for a delay beyond it.
func TestDoDeadline(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	api := newAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	start := time.Now()
	err := api.Do(ctx, http.MethodGet, "/", nil, nil)
	if hosted.StatusOf(err) != http.StatusTooManyRequests || calls.Load() != 1 || time.Since(start) > time.Second {
		t.Errorf("Do() = %v after %d calls and %s, want the 429 at once", err, calls.Load(), time.Since(start))
	}
}

// TestAmbiguous checks which failures of a write leave its outcome unknown:
// those once the request left whole, and the server errors.
func TestAmbiguous(t *testing.T) {
	t.Parallel()
	status := func(code int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
	}
	dropped := func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
			_ = conn.Close()
		}
	}
	for _, c := range []struct {
		label     string
		handler   http.HandlerFunc
		ambiguous bool
	}{
		{label: "answer lost", handler: dropped, ambiguous: true},
		{label: "server error", handler: status(http.StatusInternalServerError), ambiguous: true},
		{label: "refused", handler: status(http.StatusBadRequest), ambiguous: false},
	} {
		t.Run(c.label, func(t *testing.T) {
			t.Parallel()
			api := newAPI(t, c.handler)
			err := api.Do(t.Context(), http.MethodPost, "/records", map[string]string{"name": "www"}, nil)
			if err == nil || hosted.Ambiguous(err) != c.ambiguous {
				t.Errorf("Do() = %v, want an error, ambiguous: %t", err, c.ambiguous)
			}
		})
	}

	t.Run("unreachable", func(t *testing.T) {
		t.Parallel()
		api := newAPI(t, status(http.StatusNoContent))
		closed := httptest.NewServer(status(http.StatusNoContent))
		closed.Close()
		api.Base = closed.URL
		err := api.Do(t.Context(), http.MethodPost, "/records", map[string]string{"name": "www"}, nil)
		if err == nil || hosted.Ambiguous(err) {
			t.Errorf("Do() to a closed server = %v, want an error that is not ambiguous", err)
		}
	})

	t.Run("not authorized", func(t *testing.T) {
		t.Parallel()
		api := newAPI(t, status(http.StatusNoContent))
		api.Authorize = func(*http.Request, []byte) error { return errors.New("no token") }
		err := api.Do(t.Context(), http.MethodPost, "/records", map[string]string{"name": "www"}, nil)
		if err == nil || hosted.Ambiguous(err) {
			t.Errorf("Do() without authorization = %v, want an error that is not ambiguous", err)
		}
	})
}
