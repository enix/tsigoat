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
	"github.com/enix/tsigoat/internal/backend/cloudflare"
	"github.com/enix/tsigoat/internal/backend/ovh"
	"github.com/enix/tsigoat/internal/backend/powerdns"
	"github.com/enix/tsigoat/internal/backend/rfc2136"
	"github.com/enix/tsigoat/internal/backend/scaleway"
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
	// ShutdownDelay is the time that the servers go on once Run is asked to
	// stop, while /readyz answers 503, so that the load balancers stop
	// sending requests first.
	ShutdownDelay time.Duration
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

	backends, relays, floors, err := newBackends(c.Backends, newBackend, m)
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
		zones = append(zones, dnsserver.Zone{
			Name: z.Name, Backend: b, Relay: relay, BackendName: z.Backend, Policy: policy, MinTTL: floors[z.Backend],
		})
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
// update engine, with the minimum TTL of those that have one, and the relays.
// Their calls feed the metrics, when m is set.
func newBackends(entries []config.Backend, newBackend BackendFactory, m *metrics.Metrics) (
	backends map[string]backend.Backend, relays map[string]backend.Relay, floors map[string]uint32, err error,
) {
	backends, relays, floors = map[string]backend.Backend{}, map[string]backend.Relay{}, map[string]uint32{}
	for i := range entries {
		entry := &entries[i]
		if entry.Type == "rfc2136" || entry.Type == "webhook" {
			relay, relayErr := newRelay(entry)
			if relayErr != nil {
				return nil, nil, nil, fmt.Errorf("backend %s: %w", entry.Name, relayErr)
			}
			if m != nil {
				relay = m.Relay(entry.Name, relay)
			}
			relays[entry.Name] = relay
			continue
		}
		b, backendErr := newBackend(entry)
		if backendErr != nil {
			return nil, nil, nil, fmt.Errorf("backend %s: %w", entry.Name, backendErr)
		}
		if floor, ok := b.(backend.TTLFloor); ok {
			floors[entry.Name] = floor.MinTTL()
		}
		if m != nil {
			b = m.Backend(entry.Name, b)
		}
		backends[entry.Name] = b
	}
	return backends, relays, floors, nil
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
			UserAgent:          userAgent(),
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
	case b.Type == "cloudflare" && b.Cloudflare != nil:
		cf, err := cloudflare.New(&cloudflare.Options{
			APIToken:  b.Cloudflare.APIToken,
			ZoneIDs:   b.Cloudflare.ZoneIDs,
			Timeout:   b.Cloudflare.Timeout,
			UserAgent: userAgent(),
		})
		if err != nil {
			return nil, fmt.Errorf("configuring Cloudflare: %w", err)
		}
		return cf, nil
	case b.Type == "ovh" && b.OVH != nil:
		o, err := ovh.New(&ovh.Options{
			Endpoint:          b.OVH.Endpoint,
			ApplicationKey:    b.OVH.ApplicationKey,
			ApplicationSecret: b.OVH.ApplicationSecret,
			ConsumerKey:       b.OVH.ConsumerKey,
			ClientID:          b.OVH.ClientID,
			ClientSecret:      b.OVH.ClientSecret,
			Timeout:           b.OVH.Timeout,
			UserAgent:         userAgent(),
		})
		if err != nil {
			return nil, fmt.Errorf("configuring OVHcloud: %w", err)
		}
		return o, nil
	case b.Type == "scaleway" && b.Scaleway != nil:
		s, err := scaleway.New(&scaleway.Options{
			SecretKey: b.Scaleway.SecretKey,
			Timeout:   b.Scaleway.Timeout,
			UserAgent: userAgent(),
		})
		if err != nil {
			return nil, fmt.Errorf("configuring Scaleway: %w", err)
		}
		return s, nil
	default:
		return nil, fmt.Errorf("unsupported backend type %q", b.Type)
	}
}

// userAgent identifies tsigoat to the HTTP APIs.
func userAgent() string {
	return product.Slug + "/" + product.BuildInfo().Version
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
// later. Once ctx is done, the servers go on for ShutdownDelay.
func (a *App) Run(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	for _, err := range a.Server.CheckZones(checkCtx) {
		a.logger.WarnContext(ctx, "zone check failed", "error", err)
	}

	serveCtx, stop := context.WithCancel(context.WithoutCancel(ctx))
	defer stop()
	go a.stopAfterDelay(ctx, serveCtx, stop)

	var adminDone <-chan error
	if a.admin != nil {
		if err := a.admin.Start(serveCtx); err != nil {
			return err
		}
		a.logger.InfoContext(ctx, "administration server listening", "address", a.admin.Addr())
		adminDone = a.admin.Done()
	}

	served := make(chan error, 1)
	go func() { served <- a.Server.Run(serveCtx) }()

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

// stopAfterDelay marks the app as stopping once ctx is done, which /readyz
// tells, then stops the servers after the shutdown delay. When the servers
// stop first, on a failure, it only marks the app as stopping.
func (a *App) stopAfterDelay(ctx, serveCtx context.Context, stop context.CancelFunc) {
	select {
	case <-serveCtx.Done():
		a.stopping.Store(true)
		return
	case <-ctx.Done():
	}
	a.stopping.Store(true)
	if a.ShutdownDelay > 0 {
		a.logger.InfoContext(serveCtx, "stopping after the shutdown delay", slog.Duration("delay", a.ShutdownDelay))
		timer := time.NewTimer(a.ShutdownDelay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-serveCtx.Done():
		}
	}
	stop()
}
