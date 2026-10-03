// Command vctx runs the Vault CLI against one of several Vault instances,
// selected by a named set of environment variables.
package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"
)

const usage = `vctx - switch between several Vault instances by environment variables.

Usage:
  vctx                               interactive UI: status, switch, login, shell
  vctx <context> [vault args...]     run vault against <context>
  vctx exec [<context>] -- cmd ...   run any command with <context> variables
  vctx env [<context>]               print shell exports: eval "$(vctx env prod)"
  vctx env --clear                   print unsets for everything vctx manages
  vctx use [<context>]               set the default context (UI without a name)
  vctx current                       print the active context
  vctx ls                            list contexts
  vctx check [<context>...]          show reachability, version and seal status
  vctx logout [<context>]            forget the stored token of <context>

The context is taken from the explicit name, then $VCTX_CONTEXT,
then the default set by 'vctx use'.

Config: $VCTX_CONFIG or ~/.config/vctx/config.yaml

  defaults:                  # applied to every context
    VAULT_FORMAT: json
  contexts:
    dev:
      VAULT_ADDR: https://vault.dev.example.com:8200
      VAULT_SKIP_VERIFY: "true"
    prod:
      VAULT_ADDR: https://vault.example.com:8200
      VAULT_NAMESPACE: admin
      VAULT_CACERT: ~/certs/prod-ca.pem

Before running a command vctx calls the unauthenticated sys/health endpoint,
so a VPN or tunnel that is down, or an ingress rejecting your IP, fails in
seconds. VCTX_CHECK_TIMEOUT sets the timeout (default 3s), 0 disables it.

Inherited VAULT_* variables are dropped before a context is applied, so an
address or token of one instance never leaks into another.

Tokens from 'vault login' are stored per context under $VCTX_STATE_DIR/tokens
(default ~/.local/state/vctx): vctx sets VAULT_CONFIG_PATH to a generated
config that registers vctx itself as the Vault token helper.
`

type app struct {
	home       string
	configPath string
	stateDir   string
	self       string
	environ    []string
	stdin      io.Reader
	stdout     io.Writer
	stderr     io.Writer
	exec       func(argv0 string, argv, envv []string) error
}

func main() {
	a, err := newApp()
	if err == nil {
		err = a.run(os.Args[1:])
	}
	switch {
	case errors.Is(err, errAborted):
		os.Exit(130)
	case errors.Is(err, errSilent):
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vctx:", err)
		os.Exit(1)
	}
}

func newApp() (*app, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if p, err := filepath.EvalSymlinks(self); err == nil {
		self = p
	}
	a := &app{
		home:    home,
		self:    self,
		environ: os.Environ(),
		stdin:   os.Stdin,
		stdout:  os.Stdout,
		stderr:  os.Stderr,
		exec:    syscall.Exec,
	}
	a.configPath = a.getenv("VCTX_CONFIG")
	if a.configPath == "" {
		a.configPath = filepath.Join(a.xdgDir("XDG_CONFIG_HOME", ".config"), "vctx", "config.yaml")
	}
	a.stateDir = a.getenv("VCTX_STATE_DIR")
	if a.stateDir == "" {
		a.stateDir = filepath.Join(a.xdgDir("XDG_STATE_HOME", ".local/state"), "vctx")
	}
	return a, nil
}

func (a *app) xdgDir(env, fallback string) string {
	if d := a.getenv(env); filepath.IsAbs(d) {
		return d
	}
	return filepath.Join(a.home, fallback)
}

func (a *app) getenv(key string) string {
	return lookupEnv(a.environ, key)
}

func (a *app) run(args []string) error {
	if len(args) == 1 && isHelperOp(args[0]) {
		return a.tokenHelper(args[0])
	}
	if len(args) == 0 {
		if isTerminal(a.stdin) && isTerminal(a.stdout) {
			return a.ui()
		}
		fmt.Fprint(a.stdout, usage)
		return nil
	}

	switch cmd, rest := args[0], args[1:]; cmd {
	case "help", "-h", "--help":
		fmt.Fprint(a.stdout, usage)
		return nil
	case "ui":
		return a.ui()
	case "ls", "list":
		return a.list()
	case "use":
		if len(rest) > 1 {
			return errors.New("usage: vctx use [<context>]")
		}
		if len(rest) == 0 {
			return a.ui()
		}
		cfg, err := a.loadConfig()
		if err != nil {
			return err
		}
		if err := a.use(cfg, rest[0]); err != nil {
			return err
		}
		a.printUsing(rest[0], cfg)
		return nil
	case "current":
		name, err := a.contextName("")
		if err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, name)
		return nil
	case "env":
		return a.env(rest)
	case "check":
		return a.check(rest)
	case "logout":
		if len(rest) > 1 {
			return errors.New("usage: vctx logout [<context>]")
		}
		var arg string
		if len(rest) == 1 {
			arg = rest[0]
		}
		name, err := a.contextName(arg)
		if err != nil {
			return err
		}
		cfg, err := a.loadConfig()
		if err != nil {
			return err
		}
		if _, ok := cfg.Contexts[name]; !ok {
			return fmt.Errorf("unknown context %q", name)
		}
		if err := os.Remove(a.tokenPath(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	case "exec":
		name, argv := splitExec(rest)
		if len(argv) == 0 {
			return errors.New("usage: vctx exec [<context>] -- command [args...]")
		}
		return a.execIn(name, argv)
	default:
		cfg, err := a.loadConfig()
		if err != nil {
			return err
		}
		if _, ok := cfg.Contexts[cmd]; !ok {
			return fmt.Errorf("unknown command or context %q, see 'vctx help'", cmd)
		}
		return a.execWith(cfg, cmd, append([]string{a.vaultBin()}, rest...))
	}
}

// splitExec splits "[name] [--] cmd args..." into the context name and the command.
func splitExec(args []string) (string, []string) {
	if len(args) > 0 && args[0] == "--" {
		return "", args[1:]
	}
	if len(args) == 0 {
		return "", nil
	}
	name, argv := args[0], args[1:]
	if len(argv) > 0 && argv[0] == "--" {
		argv = argv[1:]
	}
	return name, argv
}

func (a *app) vaultBin() string {
	if bin := a.getenv("VCTX_VAULT_BIN"); bin != "" {
		return bin
	}
	return "vault"
}

func (a *app) loadConfig() (*config, error) {
	return loadConfig(a.configPath)
}

func (a *app) currentFile() string {
	return filepath.Join(a.stateDir, "current")
}

// contextName resolves the context: explicit argument, then $VCTX_CONTEXT, then the saved default.
// The name ends up in file paths, so it is validated whatever its source.
func (a *app) contextName(arg string) (string, error) {
	name, from := arg, "argument"
	if name == "" {
		name, from = a.getenv(envContext), "$"+envContext
	}
	if name == "" {
		b, err := os.ReadFile(a.currentFile())
		if errors.Is(err, fs.ErrNotExist) {
			return "", errors.New("no context selected: pass a name or run 'vctx use <context>'")
		}
		if err != nil {
			return "", err
		}
		name, from = strings.TrimSpace(string(b)), a.currentFile()
	}
	if !nameRe.MatchString(name) {
		return "", fmt.Errorf("invalid context name %q in %s", name, from)
	}
	return name, nil
}

func (a *app) list() error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	current, _ := a.contextName("")
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	for _, name := range slices.Sorted(maps.Keys(cfg.Contexts)) {
		vars := cfg.Contexts[name]
		mark := " "
		if name == current {
			mark = "*"
		}
		token := "-"
		if a.hasToken(name) {
			token = "token"
		}
		ns := vars["VAULT_NAMESPACE"]
		if ns == "" {
			ns = "-"
		}
		fmt.Fprintf(tw, "%s %s\t%s\t%s\t%s\n", mark, name, vars["VAULT_ADDR"], ns, token)
	}
	return tw.Flush()
}

func (a *app) use(cfg *config, name string) error {
	if _, ok := cfg.Contexts[name]; !ok {
		return fmt.Errorf("unknown context %q", name)
	}
	if err := writeFileAtomic(a.currentFile(), []byte(name+"\n"), 0o600); err != nil {
		return fmt.Errorf("save current context: %w", err)
	}
	return nil
}

// shellOverride returns the $VCTX_CONTEXT of this shell when it differs from name.
func (a *app) shellOverride(name string) string {
	if shell := a.getenv(envContext); shell != name {
		return shell
	}
	return ""
}

func (a *app) env(args []string) error {
	if len(args) == 1 && args[0] == "--clear" {
		writeShellEnv(a.stdout, a.environ, nil)
		return nil
	}
	if len(args) > 1 {
		return errors.New("usage: vctx env [<context> | --clear]")
	}
	var arg string
	if len(args) == 1 {
		arg = args[0]
	}
	name, err := a.contextName(arg)
	if err != nil {
		return err
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	vars, err := a.contextVars(cfg, name)
	if err != nil {
		return err
	}
	writeShellEnv(a.stdout, a.environ, vars)
	return nil
}

func (a *app) execIn(arg string, argv []string) error {
	name, err := a.contextName(arg)
	if err != nil {
		return err
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	return a.execWith(cfg, name, argv)
}

func (a *app) execWith(cfg *config, name string, argv []string) error {
	vars, err := a.contextVars(cfg, name)
	if err != nil {
		return err
	}
	bin, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	env := applyEnv(a.environ, vars)
	if err := a.ensureReachable(name, env); err != nil {
		return err
	}
	if err := a.exec(bin, argv, env); err != nil {
		return fmt.Errorf("exec %s: %w", bin, err)
	}
	return nil
}
