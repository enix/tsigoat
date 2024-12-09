package main

import (
	"os"
	"path/filepath"

	"github.com/enix/tsigoat/pkg/cmd"
)

func main() {
	baseName := filepath.Base(os.Args[0])
	settings := cmd.New()
	err := newCmdRoot(baseName, settings).Execute()
	cmd.CheckError(err)
}
