package httpclient_test

import (
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enix/tsigoat/internal/backend/httpclient"
)

// TestRedirects checks that a client follows the 307 and 308 redirects to
// the same scheme and host alone, and only on request: the others would turn
// a POST into a GET, or hand the headers of the request to another server.
func TestRedirects(t *testing.T) {
	t.Parallel()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(other.Close)

	mux := http.NewServeMux()
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || string(body) != "payload" {
			http.Error(w, "the request lost its method or its body", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/to/{code}/{where}", func(w http.ResponseWriter, r *http.Request) {
		target := "/final"
		switch r.PathValue("where") {
		case "other":
			target = other.URL + "/final"
		case "http":
			// The same host, in plain HTTP.
			target = "http://" + r.Host + "/final"
		}
		code := map[string]int{"302": http.StatusFound, "307": http.StatusTemporaryRedirect, "308": http.StatusPermanentRedirect}
		http.Redirect(w, r, target, code[r.PathValue("code")])
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		path   string
		follow bool
		status int
	}{
		{"/to/307/same", false, http.StatusTemporaryRedirect},
		{"/to/307/same", true, http.StatusNoContent},
		{"/to/308/same", true, http.StatusNoContent},
		{"/to/302/same", true, http.StatusFound},
		{"/to/307/other", true, http.StatusTemporaryRedirect},
		{"/to/308/http", true, http.StatusPermanentRedirect},
	} {
		client, err := httpclient.New(&httpclient.Options{CAFile: caFile, FollowRedirects: c.follow})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+c.path, strings.NewReader("payload"))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("%s, follow %t: %v", c.path, c.follow, err)
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode != c.status {
			t.Errorf("%s, follow %t: status %d, want %d", c.path, c.follow, resp.StatusCode, c.status)
		}
	}
}

func TestCAFile(t *testing.T) {
	t.Parallel()
	for _, content := range []string{"", "not a certificate"} {
		path := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := httpclient.New(&httpclient.Options{CAFile: path}); err == nil {
			t.Errorf("New() accepted a CA file holding %q", content)
		}
	}
	if _, err := httpclient.New(&httpclient.Options{CAFile: "/missing/ca.pem"}); err == nil {
		t.Error("New() accepted a missing CA file")
	}
}
