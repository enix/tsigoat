package httpclient_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"

	"github.com/enix/tsigoat/internal/backend/httpclient"
)

// TestDeliveryTrace checks what the trace of a request tells: a request
// whose write started, and did not fail, may have left whole, since the
// transport may give up on it before its write ends.
func TestDeliveryTrace(t *testing.T) {
	t.Parallel()
	broken := httptrace.WroteRequestInfo{Err: errors.New("broken pipe")}
	for _, c := range []struct {
		name  string
		steps func(trace *httptrace.ClientTrace)
		left  bool
	}{
		{"nothing written", func(*httptrace.ClientTrace) {}, false},
		{"headers written", func(trace *httptrace.ClientTrace) {
			trace.WroteHeaders()
		}, true},
		{"written whole", func(trace *httptrace.ClientTrace) {
			trace.WroteHeaders()
			trace.WroteRequest(httptrace.WroteRequestInfo{})
		}, true},
		{"write failed", func(trace *httptrace.ClientTrace) {
			trace.WroteHeaders()
			trace.WroteRequest(broken)
		}, false},
		{"written again after a failure", func(trace *httptrace.ClientTrace) {
			trace.WroteHeaders()
			trace.WroteRequest(broken)
			trace.WroteHeaders()
		}, true},
		{"written whole once", func(trace *httptrace.ClientTrace) {
			trace.WroteHeaders()
			trace.WroteRequest(httptrace.WroteRequestInfo{})
			trace.WroteHeaders()
			trace.WroteRequest(broken)
		}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var d httpclient.Delivery
			c.steps(httptrace.ContextClientTrace(d.Trace(t.Context())))
			if d.Left() != c.left {
				t.Errorf("Left() = %t, want %t", d.Left(), c.left)
			}
		})
	}
}

// TestDelivery checks Delivery with a client: a request to a server that is
// gone never left, and one that the server read whole did, whatever ends
// the wait for its answer.
func TestDelivery(t *testing.T) {
	t.Parallel()
	client, err := httpclient.New(&httpclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	post := func(ctx context.Context, d *httpclient.Delivery, url string) error {
		req, err := http.NewRequestWithContext(d.Trace(ctx), http.MethodPost, url, strings.NewReader("payload"))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}

	t.Run("server gone", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.NotFoundHandler())
		server.Close()
		var d httpclient.Delivery
		if err := post(t.Context(), &d, server.URL); err == nil || d.Left() {
			t.Errorf("post() = %v, Left() = %t, want an error and false", err, d.Left())
		}
	})

	t.Run("read whole, then canceled", func(t *testing.T) {
		t.Parallel()
		received := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if body, err := io.ReadAll(r.Body); err == nil && string(body) == "payload" {
				close(received)
			}
			<-r.Context().Done()
		}))
		t.Cleanup(server.Close)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() {
			<-received
			cancel()
		}()
		var d httpclient.Delivery
		if err := post(ctx, &d, server.URL); err == nil || !d.Left() {
			t.Errorf("post() = %v, Left() = %t, want an error and true", err, d.Left())
		}
	})
}
