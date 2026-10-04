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
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"
)

const usage = `vctx - switch between several Vault instances by environment variables.

Usage:
  vctx                             interactive UI: status, switch, login, shell
  vctx <context> [vault args...]   run vault against <context>
  vctx exec [<context>] -- cmd     run any command with <context> variables
  vctx env [<context>]             print exports: eval "$(vctx env prod)"
  vctx env --clear                 print commands that undo 'vctx env'
  vctx use [<context>]             set the default context (UI without a name)
  vctx current                     print the active context
  vctx ls                          list contexts
  vctx check [<context>...]        show reachability, version and seal status
  vctx logout [<context>]          forget the stored token of <context>

The context is taken from the explicit name, then $VCTX_CONTEXT,
then the default set by 'vctx use'.

Config: $VCTX_CONFIG or $XDG_CONFIG_HOME/vctx/config.yaml (~/.config by default)

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
address or token of one instance never leaks into another. vctx refuses vault's
-address and -agent-address flags: the token helper cannot see them and would
hand the context's token to that server. In a shell set up with 'vctx env'
nothing stops them, so do not pass them there. Other variables a context sets,
PATH or HTTPS_PROXY say, get your own values back when you switch away.

Tokens from 'vault login' are stored per context and bound to the address
they were issued for: in the macOS Keychain by default, elsewhere in files
under $VCTX_STATE_DIR/tokens (default $XDG_STATE_HOME/vctx, that is
~/.local/state/vctx); VCTX_TOKEN_STORE=file or keychain chooses. The
Keychain keeps tokens off disk and out of backups, but like a 0600 file it
does not hide them from other programs running as you. vctx sets
VAULT_CONFIG_PATH to a generated config that registers vctx itself as the
Vault token helper.

The config and the state directory must not be writable by other users.

Environment:
  VCTX_CONFIG         config file
  VCTX_STATE_DIR      tokens, default context, generated Vault config
  VCTX_TOKEN_STORE    file or keychain
  VCTX_CHECK_TIMEOUT  reachability check timeout, 0 disables it
  VCTX_VAULT_BIN      vault binary to run (default: vault on PATH)
  VCTX_CONTEXT        set by 'vctx env': this shell's context (and
                      VCTX_CONTEXT_ADDR, VCTX_VARS, VCTX_SAVED_*)
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
	// Whether stdin, stdout and stderr are terminals; tests leave them false.
	stdinTTY, stdoutTTY, stderrTTY bool
	exec                           func(argv0 string, argv, envv []string) error
	keyring                        secretService // nil means the system keychain
}

// errSilent ends the program with status 1 but no message: the failure is already on screen.
var errSilent = errors.New("failed")

// usageError is a malformed command line; it exits with status 2.
type usageError string

func (e usageError) Error() string { return string(e) }

func main() {
	a, err := newApp()
	if err == nil {
		err = a.run(os.Args[1:])
	}
	var uerr usageError
	switch {
	case err == nil:
	case errors.Is(err, errSilent):
		os.Exit(1)
	case errors.As(err, &uerr):
		fmt.Fprintln(os.Stderr, "vctx:", err)
		os.Exit(2)
	default:
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
	// On macOS os.Executable keeps the path as invoked: a package manager's symlink
	// survives upgrades, the versioned file it points to does not. (Linux reads
	// /proc/self/exe, already resolved.) Resolve only if the path is unusable.
	if !helperPathRe.MatchString(self) {
		if p, err := filepath.EvalSymlinks(self); err == nil {
			self = p
		}
	}
	a := &app{
		home:      home,
		self:      self,
		environ:   os.Environ(),
		stdin:     os.Stdin,
		stdout:    os.Stdout,
		stderr:    os.Stderr,
		stdinTTY:  isTerminal(os.Stdin),
		stdoutTTY: isTerminal(os.Stdout),
		stderrTTY: isTerminal(os.Stderr),
		exec:      syscall.Exec,
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
	return envValue(a.environ, key)
}

func (a *app) run(args []string) error {
	if len(args) == 1 && isHelperOp(args[0]) {
		return a.tokenHelper(args[0])
	}
	if len(args) == 0 {
		if a.stdinTTY && a.stdoutTTY {
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
		if len(rest) > 0 {
			return usageError("usage: vctx ls")
		}
		return a.list()
	case "use":
		if len(rest) > 1 || len(rest) == 1 && strings.HasPrefix(rest[0], "-") {
			return usageError("usage: vctx use [<context>]")
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
		if len(rest) > 0 {
			return usageError("usage: vctx current")
		}
		name, err := a.contextName("")
		if err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, name)
		return nil
	case "env":
		return a.env(rest)
	case "check":
		if slices.ContainsFunc(rest, func(arg string) bool { return strings.HasPrefix(arg, "-") }) {
			return usageError("usage: vctx check [<context>...]")
		}
		return a.check(rest)
	case "logout":
		if len(rest) > 1 || len(rest) == 1 && strings.HasPrefix(rest[0], "-") {
			return usageError("usage: vctx logout [<context>]")
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
		store, err := a.tokens()
		if err != nil {
			return err
		}
		// A context renamed or removed from the config may still have a token to forget.
		if _, ok := cfg.Contexts[name]; !ok {
			if _, stored, err := store.addr(name); err != nil || !stored {
				return errors.Join(fmt.Errorf("unknown context %q", name), err)
			}
		}
		return store.del(name)
	case "exec":
		name, argv := splitExec(rest)
		if len(argv) == 0 {
			return usageError("usage: vctx exec [<context>] -- command [args...]")
		}
		return a.execIn(name, argv)
	default:
		cfg, err := a.loadConfig()
		if err != nil {
			return err
		}
		if _, ok := cfg.Contexts[cmd]; !ok {
			return usageError(fmt.Sprintf("unknown command or context %q, see 'vctx help'", cmd))
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

// addressFlag returns a vault flag that points vault at another server than the
// context's. The token helper sees only the environment, not flags, so it would
// hand the context's token to that server.
func addressFlag(args []string) string {
	for _, arg := range args {
		if arg == "--" {
			break
		}
		name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if strings.HasPrefix(arg, "-") && (name == "address" || name == "agent-address") {
			return arg
		}
	}
	return ""
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
	names := slices.Sorted(maps.Keys(cfg.Contexts))
	tokens, err := a.tokenStatus(cfg, names)
	if err != nil {
		fmt.Fprintln(a.stderr, "vctx: token status:", err)
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	for _, name := range names {
		vars, err := cfg.vars(name, a.home)
		if err != nil {
			return err
		}
		mark := " "
		if name == current {
			mark = "*"
		}
		token := "-"
		switch tokens[name] {
		case tokenOK:
			token = "token"
		case tokenStale:
			token = "stale"
		}
		ns := vars["VAULT_NAMESPACE"]
		if ns == "" {
			ns = "-"
		}
		fmt.Fprintf(tw, "%s %s\t%s\t%s\t%s\n", mark, name, redactAddr(vaultAddr(vars)), ns, token)
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
	if len(args) > 1 || len(args) == 1 && strings.HasPrefix(args[0], "-") {
		return usageError("usage: vctx env [<context> | --clear]")
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
	if err := a.registerHelper(vars); err != nil {
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
	if bin := filepath.Base(argv[0]); bin == "vault" || bin == filepath.Base(a.vaultBin()) {
		if flag := addressFlag(argv[1:]); flag != "" {
			return fmt.Errorf("%s would send the %s token to another server; set the address in the context instead", flag, name)
		}
	}
	vars, err := a.contextVars(cfg, name)
	if err != nil {
		return err
	}
	if err := a.registerHelper(vars); err != nil {
		return err
	}
	env := applyEnv(a.environ, vars)
	bin, err := lookPath(argv[0], env)
	if err != nil {
		return err
	}
	if err := a.ensureReachable(name, env); err != nil {
		return err
	}
	if err := a.exec(bin, argv, env); err != nil {
		return fmt.Errorf("exec %s: %w", bin, err)
	}
	return nil
}
