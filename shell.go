package main

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// initMarker identifies the line `vctx init` adds, so running it again changes nothing.
const initMarker = "# vctx shell integration"

// posixInit makes `vctx use` and a choice in the UI switch the current shell,
// and starts new shells in the default context; a shell started inside a
// context (the UI's shell, `vctx exec -- zsh`) keeps it.
const posixInit = `vctx() {
  VCTX_SHELL=1 command vctx "$@" || return
  case "$1" in
    use|ui|"") eval "$(command vctx env --default)" ;;
  esac
}
if [ -z "$VCTX_CONTEXT" ]; then
  eval "$(command vctx env --default 2>/dev/null)"
fi
`

const fishInit = `function vctx
    VCTX_SHELL=1 command vctx $argv; or return
    switch "$argv[1]"
        case use ui ''
            command vctx env --shell fish --default | source
    end
end
if not set -q VCTX_CONTEXT
    command vctx env --shell fish --default 2>/dev/null | source
end
`

// rcFile is where `vctx init` hooks into shell: the file that shell reads for
// every interactive session.
func (a *app) rcFile(shell string) (string, error) {
	switch shell {
	case "zsh":
		dir := a.getenv("ZDOTDIR")
		if dir == "" {
			dir = a.home
		}
		return filepath.Join(dir, ".zshrc"), nil
	case "bash":
		// Terminal apps on macOS start login shells, which read .bash_profile.
		if runtime.GOOS == "darwin" {
			return filepath.Join(a.home, ".bash_profile"), nil
		}
		return filepath.Join(a.home, ".bashrc"), nil
	case "fish":
		return filepath.Join(a.xdgDir("XDG_CONFIG_HOME", ".config"), "fish", "conf.d", "vctx.fish"), nil
	}
	return "", fmt.Errorf("unsupported shell %q: vctx supports zsh, bash and fish", shell)
}

func initLine(shell string) string {
	if shell == "fish" {
		return "command vctx init fish | source"
	}
	return `eval "$(command vctx init ` + shell + `)"`
}

// initShell hooks the integration into the rc file of the user's shell, or of
// the one given with --shell; `vctx init <shell>` prints the integration itself.
func (a *app) initShell(args []string) error {
	shell := filepath.Base(a.getenv("SHELL"))
	switch {
	case len(args) == 0:
	case len(args) == 2 && args[0] == "--shell":
		shell = args[1]
	case len(args) == 1 && !strings.HasPrefix(args[0], "-"):
		return a.printInit(args[0])
	default:
		return usageError("usage: vctx init [--shell zsh|bash|fish]")
	}
	rc, err := a.rcFile(shell)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(rc)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if strings.Contains(string(b), initMarker) {
		fmt.Fprintf(a.stdout, "already set up in %s\n", rc)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(rc), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(rc, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	block := initMarker + "\n" + initLine(shell) + "\n"
	if len(b) > 0 && !strings.HasSuffix(string(b), "\n") {
		block = "\n" + block
	}
	if _, err := io.WriteString(f, block); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "added to %s\nopen a new terminal; then `vctx use <context>` switches it, and vault follows\n", rc)
	return nil
}

func (a *app) printInit(shell string) error {
	switch shell {
	case "zsh", "bash":
		_, err := io.WriteString(a.stdout, posixInit)
		return err
	case "fish":
		_, err := io.WriteString(a.stdout, fishInit)
		return err
	}
	return fmt.Errorf("unsupported shell %q: vctx supports zsh, bash and fish", shell)
}

// writeFishEnv is writeShellEnv for fish.
func writeFishEnv(w io.Writer, environ []string, vars map[string]string) {
	p := planEnv(environ, vars)
	for _, k := range slices.Sorted(maps.Keys(p.unset)) {
		if envKeyRe.MatchString(k) {
			fmt.Fprintf(w, "set -e %s\n", k)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(p.set)) {
		fmt.Fprintf(w, "set -gx %s %s\n", k, fishQuote(p.set[k]))
	}
}

func fishQuote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}
