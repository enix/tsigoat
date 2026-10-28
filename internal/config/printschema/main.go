// Command printschema prints the JSON schema of the configuration file of
// tsigoat, which task doc:helm inserts into the schema of the values of the
// chart.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/enix/tsigoat/internal/config"
)

func main() {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config.Schema()); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
