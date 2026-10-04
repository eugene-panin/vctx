package cli

import (
	"errors"
	"path/filepath"

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

// initShell hooks the integration into the rc file of sh, or of the user's
// shell when sh is empty.
func (a *app) initShell(sh string) error {
	if sh == "" {
		if v := a.getenv("SHELL"); v != "" {
			sh = filepath.Base(v)
		}
	}
	if sh == "" {
		return usageError("cannot tell your shell: $SHELL is not set; run 'vctx init --shell zsh|bash|fish'")
	}
	return asShellUsage(a.shellSetup().Install(sh, a.stdout))
}

// asShellUsage makes a shell vctx does not support a malformed command line.
func asShellUsage(err error) error {
	if errors.Is(err, shell.ErrUnsupported) {
		return usageError(err.Error() + " (see 'vctx init -h')")
	}
	return err
}
