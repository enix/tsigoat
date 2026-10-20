// Command tsigoat serves RFC 2136 dynamic DNS updates authenticated with TSIG
// and applies them through the API of a DNS provider.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	// Embedded TLS roots, used when the system has none, as in the scratch
	// container image.
	_ "golang.org/x/crypto/x509roots/fallback"

	"github.com/enix/tsigoat/internal/product"
)

// defaultConfigPath is the configuration file read when --config is not set.
const defaultConfigPath = "/etc/tsigoat/config.yaml"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the command line and returns the exit code.
func run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := newRootCommand(stdout, stderr)
	root.SetArgs(args)
	if err := root.ExecuteContext(ctx); err != nil {
		for line := range strings.SplitSeq(err.Error(), "\n") {
			_, _ = fmt.Fprintln(stderr, "error:", line)
		}
		return 1
	}
	return 0
}

func newRootCommand(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:   product.Slug,
		Short: "A gateway from RFC 2136 dynamic DNS updates to DNS provider APIs",
		Long: product.Name + ` receives DNS UPDATE messages (RFC 2136) authenticated with TSIG
(RFC 8945), checks them against the policy of each zone, and applies them
through the API of the DNS provider that holds the zone (PowerDNS, Cloudflare,
OVHcloud, Scaleway), or relays them to a name server that implements RFC 2136
or to an HTTP endpoint.`,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(
		newServeCommand(stderr),
		newCheckConfigCommand(stdout),
		newVersionCommand(stdout),
	)
	return root
}
