package main

import (
	"github.com/enix/tsigoat/pkg/cmd"

	"github.com/spf13/cobra"
)

const globalDesc = `
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.
Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.
Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
`

func newCmdRoot(name string, settings *cmd.Settings) *cobra.Command {
	command := &cobra.Command{
		Use:   name,
		Short: "Lorem ipsum dolor sit amet",
		Long:  globalDesc,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return settings.Init()
		},
	}

	rootFlags := command.PersistentFlags()
	settings.AddFlags(rootFlags)

	command.AddCommand(
		newCmdVersion(settings),
		newCmdServe(settings),
	)

	return command
}
