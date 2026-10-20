// Package app assembles tsigoat from its configuration: the keyring, the
// backends, the zones with their policy, the DNS server, and the
// administration server with the metrics.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/enix/tsigoat/internal/admin"
	"github.com/enix/tsigoat/internal/auth"
	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/powerdns"
	"github.com/enix/tsigoat/internal/backend/rfc2136"
	"github.com/enix/tsigoat/internal/backend/webhook"
	"github.com/enix/tsigoat/internal/config"
	"github.com/enix/tsigoat/internal/dnsserver"
	"github.com/enix/tsigoat/internal/metrics"
	"github.com/enix/tsigoat/internal/product"
)

const (
	// checkTimeout bounds the check of every zone at startup.
	checkTimeout = 10 * time.Second
	// adminShutdownTimeout bounds the shutdown of the administration server.
	adminShutdownTimeout = 5 * time.Second
)

// BackendFactory builds the backend of a configuration entry, for the update
// engine of tsigoat. The rfc2136 backends are relays, which New builds itself.
type BackendFactory func(*config.Backend) (backend.Backend, error)

// App is tsigoat, assembled.
type App struct {
	Server *dnsserver.Server
	// admin is the administration server, nil when disabled.
	admin  *admin.Server
	logger *slog.Logger
	// stopping turns true when the app starts shutting down.
	stopping atomic.Bool
}

// New assembles tsigoat. newBackend builds the backends; NewBackend when
// nil.
func New(c *config.Config, logger *slog.Logger, newBackend BackendFactory) (*App, error) {
	if newBackend == nil {
		newBackend = NewBackend
	}
	keyring, err := auth.NewKeyring(c.Keys)
	if err != nil {
		return nil, fmt.Errorf("loading the keys: %w", err)
	}

	a := &App{logger: logger}
	var m *metrics.Metrics
	if c.AdminListen != "" {
		info := product.BuildInfo()
		m = metrics.New(&info)
		a.admin = admin.New(c.AdminListen, m.Gatherer(), a.ready)
	}

	backends, relays, err := newBackends(c.Backends, newBackend, m)
	if err != nil {
		return nil, err
	}
	zones := make([]dnsserver.Zone, 0, len(c.Zones))
	for i := range c.Zones {
		z := &c.Zones[i]
		b, isBackend := backends[z.Backend]
		relay, isRelay := relays[z.Backend]
		if !isBackend && !isRelay {
			return nil, fmt.Errorf("zone %s: unknown backend %q", z.Name, z.Backend)
		}
		policy, policyErr := auth.NewPolicy(z)
		if policyErr != nil {
			return nil, policyErr
		}
		zones = append(zones, dnsserver.Zone{Name: z.Name, Backend: b, Relay: relay, BackendName: z.Backend, Policy: policy})
	}

	options := &dnsserver.Options{
		Listen:  c.Listen,
		Keyring: keyring,
		Zones:   zones,
		Logger:  logger,
	}
	if m != nil {
		options.Observer = m
	}
	a.Server, err = dnsserver.New(options)
	if err != nil {
		return nil, fmt.Errorf("creating the DNS server: %w", err)
	}
	return a, nil
}

// newBackends builds the backends of the configuration, by name: those of the
// update engine, and the relays. Their calls feed the metrics, when m is set.
func newBackends(entries []config.Backend, newBackend BackendFactory, m *metrics.Metrics) (
	backends map[string]backend.Backend, relays map[string]backend.Relay, err error,
) {
	backends, relays = map[string]backend.Backend{}, map[string]backend.Relay{}
	for i := range entries {
		entry := &entries[i]
		if entry.Type == "rfc2136" || entry.Type == "webhook" {
			relay, relayErr := newRelay(entry)
			if relayErr != nil {
				return nil, nil, fmt.Errorf("backend %s: %w", entry.Name, relayErr)
			}
			if m != nil {
				relay = m.Relay(entry.Name, relay)
			}
			relays[entry.Name] = relay
			continue
		}
		b, backendErr := newBackend(entry)
		if backendErr != nil {
			return nil, nil, fmt.Errorf("backend %s: %w", entry.Name, backendErr)
		}
		if m != nil {
			b = m.Backend(entry.Name, b)
		}
		backends[entry.Name] = b
	}
	return backends, relays, nil
}

// newRelay builds the relay of a configuration entry of type rfc2136 or
// webhook.
func newRelay(entry *config.Backend) (backend.Relay, error) {
	switch {
	case entry.Type == "rfc2136" && entry.RFC2136 != nil:
		r, err := rfc2136.New(&rfc2136.Options{
			Server:  entry.RFC2136.Server,
			Key:     entry.RFC2136.Key,
			Timeout: entry.RFC2136.Timeout,
		})
		if err != nil {
			return nil, fmt.Errorf("configuring the RFC 2136 relay: %w", err)
		}
		return r, nil
	case entry.Type == "webhook" && entry.Webhook != nil:
		w := entry.Webhook
		header := http.Header{}
		for _, h := range w.Headers {
			header.Set(h.Name, h.Value)
		}
		r, err := webhook.New(&webhook.Options{
			URL:                w.URL,
			Timeout:            w.Timeout,
			CAFile:             w.CAFile,
			InsecureSkipVerify: w.InsecureSkipVerify,
			FollowRedirects:    w.FollowRedirects,
			SignatureSecret:    w.SignatureSecret,
			Username:           w.Username,
			Password:           w.Password,
			BearerToken:        w.BearerToken,
			Header:             header,
			UserAgent:          product.Slug + "/" + product.BuildInfo().Version,
		})
		if err != nil {
			return nil, fmt.Errorf("configuring the webhook: %w", err)
		}
		return r, nil
	default:
		return nil, fmt.Errorf("no settings for a relay of type %q", entry.Type)
	}
}

// NewBackend builds the backend of a configuration entry.
func NewBackend(b *config.Backend) (backend.Backend, error) {
	switch {
	case b.Type == "powerdns" && b.PowerDNS != nil:
		pdns, err := powerdns.New(&powerdns.Options{
			URL:      b.PowerDNS.URL,
			ServerID: b.PowerDNS.ServerID,
			APIKey:   b.PowerDNS.APIKey,
			Timeout:  b.PowerDNS.Timeout,
			CAFile:   b.PowerDNS.CAFile,
		})
		if err != nil {
			return nil, fmt.Errorf("configuring PowerDNS: %w", err)
		}
		return pdns, nil
	default:
		return nil, fmt.Errorf("unsupported backend type %q", b.Type)
	}
}

// ready tells whether tsigoat serves DNS, for the readiness probe.
func (a *App) ready() bool {
	return len(a.Server.Addrs()) > 0 && !a.stopping.Load()
}

// AdminAddr returns the address of the administration server, once started;
// "" when it is disabled.
func (a *App) AdminAddr() string {
	if a.admin == nil {
		return ""
	}
	return a.admin.Addr()
}

// Run checks the zones, then serves until ctx is done or a server fails. A
// zone that fails the check only draws a warning: its backend may come back
// later.
func (a *App) Run(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	for _, err := range a.Server.CheckZones(checkCtx) {
		a.logger.WarnContext(ctx, "zone check failed", "error", err)
	}

	ctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		<-ctx.Done()
		a.stopping.Store(true)
	}()

	var adminDone <-chan error
	if a.admin != nil {
		if err := a.admin.Start(ctx); err != nil {
			return err
		}
		a.logger.InfoContext(ctx, "administration server listening", "address", a.admin.Addr())
		adminDone = a.admin.Done()
	}

	served := make(chan error, 1)
	go func() { served <- a.Server.Run(ctx) }()

	var err error
	select {
	case err = <-served:
	case err = <-adminDone:
		if err == nil {
			err = errors.New("the administration server stopped")
		}
		stop()
		err = errors.Join(err, <-served)
	}
	if a.admin != nil {
		shutdownCtx, cancelShutdown := context.WithTimeout(context.WithoutCancel(ctx), adminShutdownTimeout)
		defer cancelShutdown()
		err = errors.Join(err, a.admin.Shutdown(shutdownCtx))
	}
	if err != nil {
		return fmt.Errorf("serving: %w", err)
	}
	return nil
}
