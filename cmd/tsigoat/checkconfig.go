package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/enix/tsigoat/internal/config"
)

func newCheckConfigCommand(stdout io.Writer) *cobra.Command {
	var configPath string
	command := &cobra.Command{
		Use:   "check-config",
		Short: "Validate the configuration file",
		Long: `Validate the configuration file and print the warnings about risky
settings. The exit code is 1 when the configuration is invalid.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
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
			return nil
		},
	}
	command.Flags().StringVarP(&configPath, "config", "c", defaultConfigPath, "configuration file")
	return command
}
