// Command vctx runs the Vault CLI against one of several Vault instances,
// switching between them by named sets of environment variables.
package main

import (
	"os"
	"runtime/debug"

	"github.com/eugene-panin/vctx/internal/cli"
)

// version is set with -ldflags "-X main.version=..." in release builds.
var version = "dev"

// buildVersion falls back to the module version Go stamps into the binary:
// v0.1.0 for go install ...@v0.1.0, a pseudo-version for a local checkout.
func buildVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

func main() { os.Exit(cli.Main(buildVersion())) }
