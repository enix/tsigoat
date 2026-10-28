package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/KimMachineGun/automemlimit/memlimit"
	"github.com/spf13/cobra"

	"github.com/enix/tsigoat/internal/app"
	"github.com/enix/tsigoat/internal/config"
	"github.com/enix/tsigoat/internal/logging"
	"github.com/enix/tsigoat/internal/product"
)

type serveOptions struct {
	configPath    string
	listen        []string
	adminListen   string
	logFormat     string
	logLevel      string
	autoMemLimit  bool
	shutdownDelay time.Duration
}

func newServeCommand(stderr io.Writer) *cobra.Command {
	o := &serveOptions{}
	command := &cobra.Command{
		Use:   "serve",
		Short: "Serve DNS updates",
		Long: `Serve DNS updates over UDP and TCP until SIGINT or SIGTERM, then for the
shutdown delay, while /readyz answers 503, then finish the updates in
progress and exit. Logs go to the standard error.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd.Context(), stderr)
		},
	}

	flags := command.Flags()
	flags.StringVarP(&o.configPath, "config", "c", defaultConfigPath, "configuration file")
	flags.StringSliceVar(&o.listen, "listen", nil,
		"address to listen on for both UDP and TCP, repeatable; replaces the addresses of the configuration")
	flags.StringVar(&o.adminListen, "admin-listen", "",
		"address of the administration HTTP server (/healthz, /readyz, /metrics); replaces the one of the configuration")
	flags.StringVar(&o.logFormat, "log-format", string(logging.FormatText),
		"log format: "+strings.Join(logging.Formats(), ", "))
	flags.StringVar(&o.logLevel, "log-level", "info", "log level: "+strings.Join(logging.Levels(), ", "))
	flags.BoolVar(&o.autoMemLimit, "auto-gomemlimit", true, "set GOMEMLIMIT from the memory limit of the cgroup")
	flags.DurationVar(&o.shutdownDelay, "shutdown-delay", 0,
		"time to go on serving after SIGINT or SIGTERM, while /readyz answers 503, so that load balancers stop sending requests first")
	return command
}

func (o *serveOptions) run(ctx context.Context, stderr io.Writer) error {
	if o.shutdownDelay < 0 {
		return fmt.Errorf("--shutdown-delay is %s: a delay cannot be negative", o.shutdownDelay)
	}
	level, err := logging.ParseLevel(o.logLevel)
	if err != nil {
		return err
	}
	logger, err := logging.New(stderr, logging.Format(o.logFormat), level)
	if err != nil {
		return err
	}
	logger.InfoContext(ctx, "starting", product.VariadicBuildInfo()...)

	if o.autoMemLimit {
		if _, limitErr := memlimit.Set(memlimit.WithLogger(logger)); limitErr != nil {
			logger.WarnContext(ctx, "setting GOMEMLIMIT failed", "error", limitErr)
		}
	}

	c, warnings, err := config.Load(o.configPath)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		logger.WarnContext(ctx, "risky configuration", "warning", warning)
	}
	if len(o.listen) > 0 {
		c.Listen = o.listen
	}
	if o.adminListen != "" {
		c.AdminListen = o.adminListen
	}
	logger.InfoContext(ctx, "configuration loaded", slog.String("path", o.configPath),
		slog.Int("keys", len(c.Keys)), slog.Int("backends", len(c.Backends)), slog.Int("zones", len(c.Zones)))

	a, err := app.New(c, logger, nil)
	if err != nil {
		return err
	}
	a.ShutdownDelay = o.shutdownDelay
	if err := a.Run(ctx); err != nil {
		return fmt.Errorf("%s stopped: %w", product.Slug, err)
	}
	logger.InfoContext(ctx, "stopped")
	return nil
}
