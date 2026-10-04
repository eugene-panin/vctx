package cli

import (
	"path/filepath"
	"strings"

	"github.com/eugene-panin/vctx/internal/shell"
)

func (a *app) shellSetup() shell.Setup {
	return shell.Setup{
		Home:       a.home,
		ZDotDir:    a.getenv("ZDOTDIR"),
		ConfigHome: a.xdgDir("XDG_CONFIG_HOME", ".config"),
		Self:       a.self,
	}
}

// initShell hooks the integration into the rc file of the user's shell, or of
// the one given with --shell; `vctx init <shell>` prints the integration itself.
func (a *app) initShell(args []string) error {
	sh := filepath.Base(a.getenv("SHELL"))
	switch {
	case len(args) == 0:
	case len(args) == 2 && args[0] == "--shell":
		sh = args[1]
	case len(args) == 1 && !strings.HasPrefix(args[0], "-"):
		return a.shellSetup().Print(args[0], a.stdout)
	default:
		return usageError("usage: vctx init [--shell zsh|bash|fish]")
	}
	return a.shellSetup().Install(sh, a.stdout)
}
