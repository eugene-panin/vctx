// Command vctx runs the Vault CLI against one of several Vault instances,
// switching between them by named sets of environment variables.
package main

import (
	"os"

	"github.com/eugene-panin/vctx/internal/cli"
)

func main() {
	os.Exit(cli.Main())
}
