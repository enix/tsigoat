package cmd

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/enix/tsigan/pkg/logging"
	"github.com/enix/tsigan/pkg/server"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type settingsFlags struct {
	verbosity int
}

type Settings struct {
	flags  settingsFlags
	Stdout io.Writer
	Stderr io.Writer
	Logger *zap.Logger
}

type serverSettingsFlags struct {
	logFormat *logging.FormatFlag
	logLevel  *logging.LevelFlag
}

type ServerSettings struct {
	serverFlags       serverSettingsFlags
	Settings          *Settings
	Logger            *zap.Logger
	SlogLogger        *slog.Logger
	UseAutoMaxProcs   bool
	UseAutoMemLimit   bool
	ConfigurationFile *server.ConfigurationFile
}

func New() *Settings {
	return &Settings{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
}

func (s *Settings) ToServer() *ServerSettings {
	return &ServerSettings{
		serverFlags: serverSettingsFlags{
			logFormat: logging.NewServerFormatFlag(logging.StructuredFormat),
			logLevel:  logging.NewLevelFlag(zapcore.InfoLevel),
		},
		Settings:          s,
		ConfigurationFile: server.NewConfigurationFile(server.YamlConfiguration),
	}
}

func (s Settings) AddFlags(fs *pflag.FlagSet) {
	flags := &s.flags
	fs.CountVarP(&flags.verbosity, "verbose", "v",
		"Verbose mode for CLI commands. Multiple -v options increase the verbosity. The maximum is 2.")
}

func (s *ServerSettings) AddFlags(fs *pflag.FlagSet) {
	flags := &s.serverFlags

	fs.VarP(flags.logFormat, "log-format", "f",
		fmt.Sprintf("Format for log output. Valid values are: %s.", strings.Join(flags.logFormat.AllowedValues(), ", ")))
	fs.VarP(flags.logLevel, "log-level", "l",
		fmt.Sprintf("Level at which to log. Valid values are: %s.", strings.Join(flags.logLevel.AllowedValues(), ", ")))

	fs.BoolVar(&s.UseAutoMaxProcs, "auto-gomaxprocs", true,
		"Automatically set GOMAXPROCS to match Linux cgroups CPU quota")
	fs.BoolVar(&s.UseAutoMemLimit, "auto-gomemlimit", true,
		"Automatically set GOMEMLIMIT to match Linux cgroups memory limit")

	fs.VarP(&s.ConfigurationFile.Type, "config-format", "e",
		fmt.Sprintf("Decoder for the configuration file. Also sets the file extension for -p. Valid values are: %s.",
			strings.Join(s.ConfigurationFile.Type.AllowedValues(), ", ")))
	fs.StringArrayVarP(&s.ConfigurationFile.SearchPaths, "config-paths", "p", []string{"/etc"},
		"Configuration file search paths when -c is not set. Comma separated list of directories.")
	fs.StringVarP(&s.ConfigurationFile.FullPath, "config", "c", "", "Full path to the configuration file")
}

func (s *Settings) Init() error {
	var level zapcore.Level

	switch s.flags.verbosity {
	case 0:
		level = zapcore.WarnLevel
	case 1:
		level = zapcore.InfoLevel
	default:
		level = zapcore.DebugLevel
	}

	s.Logger = logging.NewLogger(logging.SimpleFormat, level, s.Stdout, s.Stderr)

	return nil // FIXME zap error?
}

func (s *ServerSettings) initLogging() error {
	flags := s.serverFlags
	format := logging.Format(flags.logFormat.Enum.String())

	level, err := logging.ParseLevel(flags.logLevel.Enum.String())
	if err != nil {
		return err
	}

	s.Logger = logging.NewLogger(format, level, s.Settings.Stdout, s.Settings.Stderr)
	s.SlogLogger = logging.NewSlogHandler(s.Logger)

	return nil // FIXME zap error?
}

func (s *ServerSettings) Init() error {
	if err := s.initLogging(); err != nil {
		return err
	}

	return nil
}
