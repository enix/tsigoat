package main

import (
	"fmt"

	"github.com/enix/tsigan/internal/product"
	"github.com/enix/tsigan/pkg/cmd"
	"github.com/enix/tsigan/pkg/server"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const serveDesc = `
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.
Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.
Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
`

type serveOptions struct {
	viper *viper.Viper
}

func newCmdServe(settings *cmd.Settings) *cobra.Command {
	serverSettings := settings.ToServer()

	options := &serveOptions{}
	command := &cobra.Command{
		Use:     "serve",
		Aliases: []string{"server"},
		Short:   "lorem ipsum dolor sit amet",
		Long:    serveDesc,
		Args:    cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return serverSettings.Init()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return options.run(serverSettings)
		},
	}

	flags := command.Flags()
	serverSettings.AddFlags(flags)

	options.viper = viper.NewWithOptions(viper.KeyDelimiter("\\"))
	options.viper.SetEnvPrefix(product.Name)

	return command
}

func (o *serveOptions) run(settings *cmd.ServerSettings) error {
	logger := settings.Logger.Sugar()

	logger.Infow(fmt.Sprintf("initializing %s server", product.Name), product.VariadicBuildInfo()...)

	settings.InitRuntime()

	o.viper.SetConfigType(settings.ConfigurationFile.Type.String())

	configFileName := fmt.Sprintf("%s.%s", settings.ConfigurationFile.Name, settings.ConfigurationFile.Type.String())
	logger.Debugw("configuration file search parameters",
		"directories", settings.ConfigurationFile.SearchPaths,
		"filename", configFileName)
	o.viper.SetConfigName(configFileName)
	for _, path := range settings.ConfigurationFile.SearchPaths {
		o.viper.AddConfigPath(path)
	}

	if settings.ConfigurationFile.FullPath != "" {
		logger.Debugw("using a configuration full path",
			"path", settings.ConfigurationFile.FullPath)
		o.viper.SetConfigFile(settings.ConfigurationFile.FullPath)
	}

	err := o.viper.ReadInConfig()
	if err != nil {
		logger.Fatalf("failed to load configuration file: %s", err)
	}

	logger.Debugw("parsing configuration file", "path", o.viper.ConfigFileUsed())
	config := server.Configuration{}
	if err := config.Unmarshal(o.viper); err != nil {
		logger.Fatalf("failed to decode configuration: %s", err)
	}

	logger.Infow("successfully decoded configuration file", "path", o.viper.ConfigFileUsed())

	server.Logger = logger // FIXME
	server.NewServer(&config).Run()

	return nil
}
