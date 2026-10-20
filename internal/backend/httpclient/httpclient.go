// Package httpclient builds the HTTP clients of the backends: TLS 1.2 at
// least, the system roots and a CA bundle, and redirects only on request.
package httpclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

// maxRedirects bounds the redirects that a client follows.
const maxRedirects = 5

// Options configure a client.
type Options struct {
	// CAFile is a PEM bundle trusted for the certificate of the server, on top
	// of the system roots.
	CAFile string
	// InsecureSkipVerify accepts any certificate.
	InsecureSkipVerify bool
	// FollowRedirects follows the 307 and 308 redirects, which keep the method
	// and the body of the request. Otherwise, and for the other redirects,
	// which turn the request into a GET, the redirect is the response.
	FollowRedirects bool
	// Timeout bounds every request, from the connection to the end of the
	// response; no bound when zero.
	Timeout time.Duration
}

// New returns a client.
func New(o *Options) (*http.Client, error) {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("unexpected type of http.DefaultTransport")
	}
	transport = transport.Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: o.InsecureSkipVerify, //nolint:gosec // G402: an explicit setting of the operator, which draws a warning
	}
	if o.CAFile != "" {
		roots, err := loadRoots(o.CAFile)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &http.Client{
		Transport: transport,
		Timeout:   o.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			code := req.Response.StatusCode
			switch {
			case !o.FollowRedirects || (code != http.StatusTemporaryRedirect && code != http.StatusPermanentRedirect):
				return http.ErrUseLastResponse
			case len(via) > maxRedirects:
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			default:
				return nil
			}
		},
	}, nil
}

// loadRoots returns the system roots plus the certificates of a PEM file.
func loadRoots(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the operator chooses the CA file
	if err != nil {
		return nil, fmt.Errorf("reading the CA file: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no certificate found in the CA file %s", path)
	}
	return roots, nil
}
