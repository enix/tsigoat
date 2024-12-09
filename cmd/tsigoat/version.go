package main

import (
	"bytes"
	"fmt"
	"io"
	"text/template"

	"github.com/enix/tsigoat/internal/product"
	"github.com/enix/tsigoat/pkg/cmd"

	"github.com/spf13/cobra"
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return options.run(settings.Stdout)
		},
	}

	flags := command.Flags()
	flags.BoolVarP(&options.short, "short", "s", false, "Print the version number only")

	return command
}

func (o *versionOptions) run(out io.Writer) error {
	fmt.Fprintln(out, formatVersion(o.short))
	return nil
}

func formatVersion(short bool) string {
	v := product.BuildInfo()

	if short {
		if len(v.GitCommit) >= 7 {
			return fmt.Sprintf("%s+g%s", v.Version, v.GitCommit[:7])
		}
		return v.Version
	}

	var buf bytes.Buffer
	tpl, _ := template.New("").Parse(versionTemplate)
	tpl.Execute(&buf, v)
	return buf.String()
}
