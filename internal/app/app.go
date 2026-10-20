// Package app assembles tsigoat from its configuration: the keyring, the
// backends, the zones with their policy, and the DNS server.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/enix/tsigoat/internal/auth"
	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/powerdns"
	"github.com/enix/tsigoat/internal/config"
	"github.com/enix/tsigoat/internal/dnsserver"
)

// checkTimeout bounds the check of every zone at startup.
const checkTimeout = 10 * time.Second

// BackendFactory builds the backend of a configuration entry.
type BackendFactory func(*config.Backend) (backend.Backend, error)

// App is tsigoat, assembled.
type App struct {
	Server *dnsserver.Server
	logger *slog.Logger
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

	backends := make(map[string]backend.Backend, len(c.Backends))
	for i := range c.Backends {
		b, backendErr := newBackend(&c.Backends[i])
		if backendErr != nil {
			return nil, fmt.Errorf("backend %s: %w", c.Backends[i].Name, backendErr)
		}
		backends[c.Backends[i].Name] = b
	}

	a := &App{logger: logger}
	zones := make([]dnsserver.Zone, 0, len(c.Zones))
	for i := range c.Zones {
		z := &c.Zones[i]
		b, ok := backends[z.Backend]
		if !ok {
			return nil, fmt.Errorf("zone %s: unknown backend %q", z.Name, z.Backend)
		}
		policy, policyErr := auth.NewPolicy(z)
		if policyErr != nil {
			return nil, policyErr
		}
		zones = append(zones, dnsserver.Zone{Name: z.Name, Backend: b, BackendName: z.Backend, Policy: policy})
	}

	a.Server, err = dnsserver.New(&dnsserver.Options{
		Listen:  c.Listen,
		Keyring: keyring,
		Zones:   zones,
		Logger:  logger,
	})
	if err != nil {
		return nil, fmt.Errorf("creating the DNS server: %w", err)
	}
	return a, nil
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

// Run checks the zones, then serves until ctx is done. A zone that fails the
// check only draws a warning: its backend may come back later.
func (a *App) Run(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	for _, err := range a.Server.CheckZones(checkCtx) {
		a.logger.WarnContext(ctx, "zone check failed", "error", err)
	}

	if err := a.Server.Run(ctx); err != nil {
		return fmt.Errorf("serving: %w", err)
	}
	return nil
}
