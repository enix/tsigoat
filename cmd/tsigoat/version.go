package main

import (
	"bytes"
	"fmt"
	"io"
	"text/template"

	"github.com/spf13/cobra"

	"github.com/enix/tsigoat/internal/product"
)

const (
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

func newVersionCommand(stdout io.Writer) *cobra.Command {
	options := &versionOptions{}
	command := &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return options.run(stdout)
		},
	}
	command.Flags().BoolVarP(&options.short, "short", "s", false, "print the version number only")
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
