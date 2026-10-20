package main

import (
	"bytes"
	"fmt"
	"io"
	"text/template"

	"github.com/spf13/cobra"

	"github.com/enix/tsigoat/internal/product"
	"github.com/enix/tsigoat/pkg/cmd"
)

const (
	versionDesc = `
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.
Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.
Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
`
	versionTemplate = `Version:    {{.Version}}
Build time: {{.BuildTime}}
Git commit: {{.GitCommit}}
Git state:  {{.GitTreeState}}
Runtime:    {{.Runtime}}
Platform:   {{.Os}}/{{.Arch}}`
	shortCommitLength = 7
)

type versionOptions struct {
	short bool
}

func newCmdVersion(settings *cmd.Settings) *cobra.Command {
	options := &versionOptions{}
	command := &cobra.Command{
		Use:   "version",
		Short: "lorem ipsum dolor sit amet",
		Long:  versionDesc,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return options.run(settings.Stdout)
		},
	}

	flags := command.Flags()
	flags.BoolVarP(&options.short, "short", "s", false, "Print the version number only")

	return command
}

func (o *versionOptions) run(out io.Writer) error {
	text, err := formatVersion(o.short)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, text)
	if err != nil {
		return fmt.Errorf("writing version: %w", err)
	}
	return nil
}

func formatVersion(short bool) (string, error) {
	info := product.BuildInfo()

	if short {
		if info.GitCommit != product.Unknown && len(info.GitCommit) >= shortCommitLength {
			return fmt.Sprintf("%s+g%s", info.Version, info.GitCommit[:shortCommitLength]), nil
		}
		return info.Version, nil
	}

	tpl, err := template.New("version").Parse(versionTemplate)
	if err != nil {
		return "", fmt.Errorf("parsing version template: %w", err)
	}
	var buf bytes.Buffer
	err = tpl.Execute(&buf, info)
	if err != nil {
		return "", fmt.Errorf("rendering version: %w", err)
	}
	return buf.String(), nil
}
