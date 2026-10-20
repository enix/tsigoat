package hosted

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enix/tsigoat/internal/backend/httpclient"
)

func TestRetryAfter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	for value, want := range map[string]struct {
		delay time.Duration
		asked bool
	}{
		"":                              {},
		"30":                            {30 * time.Second, true},
		"0":                             {0, true},
		"-1":                            {},
		"soon":                          {},
		"99999999999999999999":          {},
		"1000000":                       {maxRetryAfter + time.Second, true},
		"Wed, 21 Oct 2026 12:00:20 GMT": {20 * time.Second, true},
		"Wed, 21 Oct 2026 11:59:00 GMT": {0, true},
		"Wed, 21 Oct 2026 14:00:00 GMT": {maxRetryAfter + time.Second, true},
	} {
		delay, asked := retryAfter(value, now)
		if delay != want.delay || asked != want.asked {
			t.Errorf("retryAfter(%q) = %s, %t, want %s, %t", value, delay, asked, want.delay, want.asked)
		}
	}
}

// TestRetryDelays checks that the delay that the API asks for holds whole,
// beyond the cap of the backoff of tsigoat, and that a request fails at once
// when the deadline leaves no time for it.
func TestRetryDelays(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(server.Close)
	client, err := httpclient.New(&httpclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var waited []time.Duration
	api := &API{
		Provider: "Provider", Base: server.URL, Client: client, Timeout: time.Second,
		Authorize: func(*http.Request, []byte) error { return nil },
		wait: func(_ context.Context, delay time.Duration) error {
			waited = append(waited, delay)
			return nil
		},
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	if err := api.Do(ctx, http.MethodGet, "/", nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(waited) != 1 || waited[0] != 30*time.Second {
		t.Errorf("waited %v, want the 30 seconds that the API asked for", waited)
	}

	calls.Store(0)
	waited = nil
	short, cancelShort := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancelShort()
	if err := api.Do(short, http.MethodGet, "/", nil, nil); StatusOf(err) != http.StatusTooManyRequests || len(waited) != 0 {
		t.Errorf("Do() = %v after waiting %v, want the 429 at once", err, waited)
	}
}
