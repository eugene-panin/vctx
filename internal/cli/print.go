package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/charmbracelet/x/term"
	"github.com/eugene-panin/vctx/internal/config"
	"github.com/eugene-panin/vctx/internal/environ"
	"github.com/eugene-panin/vctx/internal/safefile"
	"github.com/eugene-panin/vctx/internal/shell"
)

func isTerminal(f *os.File) bool {
	return term.IsTerminal(f.Fd())
}

func (a *app) printUsing(name string, cfg *config.Config) {
	vars, _ := cfg.Vars(name, a.home)
	addr := config.RedactAddr(config.VaultAddr(vars))
	override := a.shellOverride(name)
	integrated := shell.Integrated(a.environ)
	if integrated {
		override = "" // the shell integration switches this terminal right after
	}
	if !a.stderrTTY {
		fmt.Fprintf(a.stderr, "using %s (%s)\n", name, addr)
		if override != "" {
			fmt.Fprintf(a.stderr, "note: this shell has %s=%s, it takes precedence\n", environ.Context, override)
		}
		return
	}
	p := a.palette(a.stderr)
	fmt.Fprintf(a.stderr, "%s %s %s\n", p.Accent.Render("●"), p.Bold.Render(name), p.Dim.Render(addr))
	if integrated {
		return
	}
	if override != "" {
		fmt.Fprintln(a.stderr, p.Warn.Render(fmt.Sprintf("  this shell has %s=%s, it takes precedence here", environ.Context, override)))
	}
	// Shown once: the integration is what makes plain `vault` follow `vctx use`.
	marker := filepath.Join(a.stateDir, "hint-init")
	if _, err := os.Stat(marker); errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(a.stderr, p.Dim.Render("  tip: run `vctx init` once, and this terminal and plain `vault` follow `vctx use`"))
		_ = safefile.Write(marker, nil, 0o600)
	}
}
