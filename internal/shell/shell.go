// Package shell hooks vctx into zsh, bash and fish, so 'vctx use' switches the terminal.
package shell

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/eugene-panin/vctx/internal/environ"
)

// initMarker labels the line `vctx init` adds.
const initMarker = "# vctx shell integration"

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

// Setup knows where a user's shells keep their configuration.
type Setup struct {
	Home       string
	ZDotDir    string // $ZDOTDIR, empty for the home directory
	ConfigHome string // $XDG_CONFIG_HOME or ~/.config
	Self       string // the vctx binary the integration calls
}

// RCFile is the file shell reads for every interactive session.
func (s Setup) RCFile(shell string) (string, error) {
	switch shell {
	case "zsh":
		dir := s.ZDotDir
		if dir == "" {
			dir = s.Home
		}
		return filepath.Join(dir, ".zshrc"), nil
	case "bash":
		if runtime.GOOS != "darwin" {
			return filepath.Join(s.Home, ".bashrc"), nil
		}
		// Terminal apps on macOS start login shells. Those read the first of
		// these that exists, so creating .bash_profile would hide the others.
		for _, name := range []string{".bash_profile", ".bash_login", ".profile"} {
			if p := filepath.Join(s.Home, name); fileExists(p) {
				return p, nil
			}
		}
		return filepath.Join(s.Home, ".bash_profile"), nil
	case "fish":
		return filepath.Join(s.ConfigHome, "fish", "conf.d", "vctx.fish"), nil
	}
	return "", unsupported(shell)
}

// ErrUnsupported is a shell vctx has no integration for.
var ErrUnsupported = errors.New("unsupported shell")

func unsupported(shell string) error {
	return fmt.Errorf("%w %q: vctx supports zsh, bash and fish", ErrUnsupported, shell)
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

// Install hooks the integration into the rc file of shell, unless it is
// there already, and says what it did on out.
func (s Setup) Install(shell string, out io.Writer) error {
	rc, err := s.RCFile(shell)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(rc)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// The line itself, not the marker: it may have been added by hand, or deleted with the marker left.
	if strings.Contains(string(b), "vctx init "+shell) {
		fmt.Fprintf(out, "already set up in %s\n", rc)
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
	fmt.Fprintf(out, "added to %s\nopen a new terminal; then `vctx use <context>` switches it, and vault follows\n", rc)
	return nil
}

// Print writes the integration for shell, what the rc line loads.
func (s Setup) Print(shell string, out io.Writer) error {
	switch shell {
	case "zsh":
		_, err := fmt.Fprintf(out, zshInit, environ.ShellQuote(s.Self))
		return err
	case "bash":
		_, err := fmt.Fprintf(out, bashInit, environ.ShellQuote(s.Self))
		return err
	case "fish":
		_, err := fmt.Fprintf(out, fishInit, environ.FishQuote(s.Self))
		return err
	}
	return unsupported(shell)
}

// Announce tells the shell function, when it called vctx with osEnv, which
// context to switch the terminal to.
func Announce(osEnv []string, name string) {
	if f := choiceFD(osEnv); f != nil {
		_, _ = io.WriteString(f, name)
		f.Close()
		return
	}
	path := environ.Value(osEnv, environ.ChoiceFile)
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

// Integrated reports whether the shell function called vctx.
func Integrated(osEnv []string) bool {
	return environ.Value(osEnv, environ.ChoiceFD) != "" || environ.Value(osEnv, environ.ChoiceFile) != ""
}

// choiceFD opens the descriptor named by VCTX_CHOICE_FD, if it is a pipe as
// the shell function sets up; nil otherwise.
func choiceFD(osEnv []string) *os.File {
	fd, err := strconv.Atoi(environ.Value(osEnv, environ.ChoiceFD))
	if err != nil || fd < 3 || fd > 9 {
		return nil
	}
	// Check before os.NewFile: a dropped *os.File would close the descriptor
	// when collected, by then perhaps reused for something else.
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFIFO {
		return nil
	}
	return os.NewFile(uintptr(fd), "choice")
}

// KeepChoiceFD stops the choice descriptor from reaching anything vctx runs:
// a daemon holding it open would keep the shell function waiting.
func KeepChoiceFD(osEnv []string) {
	if fd, err := strconv.Atoi(environ.Value(osEnv, environ.ChoiceFD)); err == nil && fd >= 3 && fd <= 9 {
		syscall.CloseOnExec(fd)
	}
}
