package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	"github.com/enix/tsigoat/internal/app"
	"github.com/enix/tsigoat/internal/config"
)

// backendCheckTimeout bounds the check of the zones through their backends.
const backendCheckTimeout = 30 * time.Second

func newCheckConfigCommand(stdout io.Writer) *cobra.Command {
	var configPath string
	var checkBackends bool
	command := &cobra.Command{
		Use:   "check-config",
		Short: "Validate the configuration file",
		Long: `Validate the configuration file and print the warnings about risky
settings. With --backends, also read the SOA of every zone through its
backend. The exit code is 1 when a check fails.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, warnings, err := config.Load(configPath)
			if err != nil {
				return err
			}
			for _, warning := range warnings {
				if _, writeErr := fmt.Fprintln(stdout, "warning:", warning); writeErr != nil {
					return fmt.Errorf("writing the warnings: %w", writeErr)
				}
			}
			_, err = fmt.Fprintf(stdout, "%s is valid: %d keys, %d backends, %d zones\n",
				configPath, len(c.Keys), len(c.Backends), len(c.Zones))
			if err != nil {
				return fmt.Errorf("writing the result: %w", err)
			}
			if checkBackends {
				return checkZones(cmd.Context(), stdout, c)
			}
			return nil
		},
	}
	command.Flags().StringVarP(&configPath, "config", "c", defaultConfigPath, "configuration file")
	command.Flags().BoolVar(&checkBackends, "backends", false, "also read the SOA of every zone through its backend")
	return command
}

// checkZones reads the SOA of every zone through its backend.
func checkZones(ctx context.Context, stdout io.Writer, c *config.Config) error {
	a, err := app.New(c, slog.New(slog.DiscardHandler), nil)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, backendCheckTimeout)
	defer cancel()
	errs := a.Server.CheckZones(ctx)
	if len(errs) > 0 {
		for _, zoneErr := range errs {
			if _, writeErr := fmt.Fprintln(stdout, "failure:", zoneErr); writeErr != nil {
				return fmt.Errorf("writing the failures: %w", writeErr)
			}
		}
		return fmt.Errorf("%d of %d zones failed the backend check", len(errs), len(c.Zones))
	}
	if _, err := fmt.Fprintln(stdout, "every zone answers through its backend"); err != nil {
		return fmt.Errorf("writing the result: %w", err)
	}
	return nil
}
