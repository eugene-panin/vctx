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

// initMarker labels the line `vctx init` adds.
const initMarker = "# vctx shell integration"

// envChoiceFile names the file the shell function creates for each call:
// vctx writes the context it switched to there, and the function then
// switches the terminal. Nothing else changes the terminal's context.
const envChoiceFile = "VCTX_CHOICE_FILE"

// posixInit is the zsh and bash integration, for interactive shells only. It
// calls vctx by absolute path, so a context whose PATH lacks vctx cannot lock
// the terminal in. New shells start in the default context, unless started
// inside one (the UI's shell, `vctx exec -- zsh`).
const posixInit = `case $- in
*i*)
vctx() {
  local choice rc
  choice=$(mktemp "${TMPDIR:-/tmp}/vctx.XXXXXX") || return
  VCTX_CHOICE_FILE="$choice" %[1]s "$@"
  rc=$?
  if [ -s "$choice" ]; then
    eval "$(%[1]s env "$(cat "$choice")")"
  fi
  rm -f "$choice"
  return $rc
}
if [ -z "${VCTX_CONTEXT:-}" ]; then
  eval "$(%[1]s env --default 2>/dev/null)"
fi
;;
esac
`

const fishInit = `if status is-interactive
    function vctx
        set -l choice (mktemp)
        VCTX_CHOICE_FILE=$choice %[1]s $argv
        set -l rc $status
        if test -s $choice
            %[1]s env --shell fish (cat $choice) | source
        end
        rm -f $choice
        return $rc
    end
    if not set -q VCTX_CONTEXT
        %[1]s env --shell fish --default 2>/dev/null | source
    end
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
		if runtime.GOOS != "darwin" {
			return filepath.Join(a.home, ".bashrc"), nil
		}
		// Terminal apps on macOS start login shells. Those read the first of
		// these that exists, so creating .bash_profile would hide the others.
		for _, name := range []string{".bash_profile", ".bash_login", ".profile"} {
			if p := filepath.Join(a.home, name); fileExists(p) {
				return p, nil
			}
		}
		return filepath.Join(a.home, ".bash_profile"), nil
	case "fish":
		return filepath.Join(a.xdgDir("XDG_CONFIG_HOME", ".config"), "fish", "conf.d", "vctx.fish"), nil
	}
	return "", fmt.Errorf("unsupported shell %q: vctx supports zsh, bash and fish", shell)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// initLine loads the integration, and does nothing once vctx is uninstalled.
func initLine(shell string) string {
	if shell == "fish" {
		return "type -q vctx; and vctx init fish | source"
	}
	return `command -v vctx >/dev/null 2>&1 && eval "$(vctx init ` + shell + `)"`
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
	// The line itself, not the marker: it may have been added by hand, or deleted with the marker left.
	if strings.Contains(string(b), "vctx init "+shell) {
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
		_, err := fmt.Fprintf(a.stdout, posixInit, shellQuote(a.self))
		return err
	case "fish":
		_, err := fmt.Fprintf(a.stdout, fishInit, fishQuote(a.self))
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

// announceChoice tells the shell function, when it called vctx, which context
// to switch the terminal to. The function created the file; vctx only fills it.
func (a *app) announceChoice(name string) {
	path := a.getenv(envChoiceFile)
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Mode().IsRegular() {
		_, _ = io.WriteString(f, name)
	}
}
