// Command tsigoat serves RFC 2136 dynamic DNS updates authenticated with TSIG
// and applies them through the API of a DNS provider.
package main

import (
	"os"
	"path/filepath"

	// Embedded TLS roots, used when the system has none, as in the scratch
	// container image.
	_ "golang.org/x/crypto/x509roots/fallback"

	"github.com/enix/tsigoat/pkg/cmd"
)

func main() {
	baseName := filepath.Base(os.Args[0])
	settings := cmd.New()
	err := newCmdRoot(baseName, settings).Execute()
	cmd.CheckError(err)
}
