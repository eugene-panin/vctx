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
	"strconv"
	"strings"
	"syscall"
)

// initMarker labels the line `vctx init` adds.
const initMarker = "# vctx shell integration"

// The shell function learns which context vctx switched to through
// envChoiceFD in zsh and bash: a descriptor feeding a command substitution,
// while vctx's own output still goes to the terminal; no temporary file to
// leave behind when Ctrl-C ends the function. fish, which cannot redirect
// like that, passes a temporary file in envChoiceFile instead. Nothing else
// changes the terminal's context.
const (
	envChoiceFD   = "VCTX_CHOICE_FD"
	envChoiceFile = "VCTX_CHOICE_FILE"
)

// zshInit and bashInit are the integration, for interactive shells only. They
// call vctx by absolute path, so a context whose PATH lacks vctx cannot lock
// the terminal in. Ctrl-C reaches the shell too while it waits for vctx: a
// handler (not an ignore, which vctx and vault would inherit) keeps the
// function going, so a login cancelled with Ctrl-C still switches the
// terminal. New shells start in the default context, unless started inside
// one (the UI's shell, `vctx exec -- zsh`).
const zshInit = `case $- in
*i*)
vctx() {
  setopt local_options local_traps
  local choice rc
  trap ':' INT
  { choice=$(VCTX_CHOICE_FD=3 %[1]s "$@" 3>&1 1>&4 4>&-); rc=$?; } 4>&1
  if [ -n "$choice" ]; then
    eval "$(%[1]s env "$choice")"
  fi
  return $rc
}
if [ -z "${VCTX_CONTEXT:-}" ]; then
  eval "$(%[1]s env --default 2>/dev/null)"
fi
;;
esac
`

// bashInit restores the caller's INT trap by hand: bash has no local traps.
const bashInit = `case $- in
*i*)
vctx() {
  local choice rc int_trap
  int_trap=$(trap -p INT)
  trap ':' INT
  { choice=$(VCTX_CHOICE_FD=3 %[1]s "$@" 3>&1 1>&4 4>&-); rc=$?; } 4>&1
  if [ -n "$int_trap" ]; then eval "$int_trap"; else trap - INT; fi
  if [ -n "$choice" ]; then
    eval "$(%[1]s env "$choice")"
  fi
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
        set -l choice (mktemp); or return
        VCTX_CHOICE_FILE=$choice %[1]s $argv
        set -l rc $status
        if test -s "$choice"
            %[1]s env --shell fish (cat "$choice") | source
        end
        rm -f "$choice"
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
	case "zsh":
		_, err := fmt.Fprintf(a.stdout, zshInit, shellQuote(a.self))
		return err
	case "bash":
		_, err := fmt.Fprintf(a.stdout, bashInit, shellQuote(a.self))
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
// to switch the terminal to.
func (a *app) announceChoice(name string) {
	if f := choiceFD(a.environ); f != nil {
		_, _ = io.WriteString(f, name)
		f.Close()
		return
	}
	path := a.getenv(envChoiceFile)
	if path == "" {
		return
	}
	// The function created the file; vctx only fills it.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Mode().IsRegular() {
		_, _ = io.WriteString(f, name)
	}
}

// choiceFD opens the descriptor named by VCTX_CHOICE_FD, if it is a pipe as
// the shell function sets up; nil otherwise.
func choiceFD(environ []string) *os.File {
	fd, err := strconv.Atoi(envValue(environ, envChoiceFD))
	if err != nil || fd < 3 || fd > 9 {
		return nil
	}
	f := os.NewFile(uintptr(fd), "choice")
	if fi, err := f.Stat(); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		return nil
	}
	return f
}

// keepChoiceFD stops the choice descriptor from reaching anything vctx runs:
// a daemon holding it open would keep the shell function waiting.
func keepChoiceFD(environ []string) {
	if fd, err := strconv.Atoi(envValue(environ, envChoiceFD)); err == nil && fd >= 3 && fd <= 9 {
		syscall.CloseOnExec(fd)
	}
}
