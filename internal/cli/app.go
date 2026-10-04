// Package cli parses vctx's command line and wires the other packages together.
package cli

import (
	"encoding/json"
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

	"github.com/eugene-panin/vctx/internal/config"
	"github.com/eugene-panin/vctx/internal/environ"
	"github.com/eugene-panin/vctx/internal/safefile"
	"github.com/eugene-panin/vctx/internal/shell"
	"github.com/eugene-panin/vctx/internal/style"
	"github.com/eugene-panin/vctx/internal/token"
)

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
	keyring                        token.SecretService // nil means the system keychain
	version                        string
	noInput                        bool // --no-input: never ask
	noColor                        bool // --no-color
}

// colorEnv is the environment styling decides by: NO_COLOR, TERM.
func (a *app) colorEnv() []string {
	if a.noColor {
		return append(slices.Clip(a.environ), "NO_COLOR=1")
	}
	return a.environ
}

// palette styles text written to w.
func (a *app) palette(w io.Writer) style.Palette {
	return style.New(w, a.colorEnv())
}

// errSilent ends the program with status 1 but no message: the failure is already on screen.
var errSilent = errors.New("failed")

// usageError is a malformed command line; it exits with status 2.
type usageError string

func (e usageError) Error() string { return string(e) }

// Main runs vctx with the process's arguments and returns its exit status:
// 2 for a malformed command line, 1 for any other failure. version is what
// 'vctx version' prints.
func Main(version string) int {
	a, err := newApp()
	if err == nil {
		a.version = version
		err = a.run(os.Args[1:])
	}
	var uerr usageError
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errSilent):
		return 1
	case errors.As(err, &uerr):
		fmt.Fprintln(os.Stderr, "vctx:", err)
		return 2
	}
	fmt.Fprintln(os.Stderr, "vctx:", err)
	return 1
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
	if !token.HelperPathOK(self) {
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
	shell.KeepChoiceFD(a.environ)
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
	return environ.Value(a.environ, key)
}

func (a *app) run(args []string) error {
	root := a.rootCmd(args)
	root.SetArgs(args)
	root.SetIn(a.stdin)
	root.SetOut(a.stdout)
	root.SetErr(a.stderr)
	return root.Execute()
}

// logout is 'vctx logout [<name>]'.
func (a *app) logout(arg string) error {
	store, err := a.tokens()
	if err != nil {
		return err
	}
	// In a context shell, forget the token vault would use there, which
	// may be an address key if VAULT_ADDR was changed by hand.
	if arg == "" && a.getenv(environ.Context) != "" {
		name, err := a.contextName("")
		if err != nil {
			return err
		}
		key := token.Key(a.environ)
		what := "the token of " + name
		if key != name {
			addr, _ := config.AddrFrom(a.getenv)
			what = "the token for " + config.RedactAddr(config.NormalizeAddr(addr))
		}
		return a.forget(store, key, what)
	}
	name, err := a.contextName(arg)
	if err != nil {
		return err
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	// A context renamed or removed from the config may still have a token to forget.
	if _, ok := cfg.Contexts[name]; !ok {
		if _, stored, err := store.Addr(name); err != nil || !stored {
			return errors.Join(fmt.Errorf("unknown context %q", name), err)
		}
	}
	return a.forget(store, name, "the token of "+name)
}

// forget deletes the token under key and says whether there was one to forget.
func (a *app) forget(store token.Store, key, what string) error {
	_, stored, err := store.Addr(key)
	if err != nil {
		return err
	}
	if !stored {
		fmt.Fprintf(a.stderr, "no %s stored\n", strings.TrimPrefix(what, "the "))
		return nil
	}
	if err := store.Del(key); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "forgot %s\n", what)
	return nil
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

func (a *app) loadConfig() (*config.Config, error) {
	cfg, err := config.Load(a.configPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no config at %s: create it, the format is in 'vctx help'", a.configPath)
	}
	if err != nil {
		return nil, err
	}
	commands := a.commandNames()
	for _, name := range slices.Sorted(maps.Keys(cfg.Contexts)) {
		if slices.Contains(commands, name) {
			return nil, fmt.Errorf("%s: context name %q is a vctx command", a.configPath, name)
		}
	}
	return cfg, nil
}

func (a *app) currentFile() string {
	return filepath.Join(a.stateDir, "current")
}

// contextName resolves the context: explicit argument, then $VCTX_CONTEXT, then the saved default.
// The name ends up in file paths, so it is validated whatever its source.
func (a *app) contextName(arg string) (string, error) {
	name, from := arg, "argument"
	if name == "" {
		name, from = a.getenv(environ.Context), "$"+environ.Context
	}
	if name == "" {
		return a.defaultContext()
	}
	if !config.ValidName(name) {
		return "", fmt.Errorf("invalid context name %q in %s", name, from)
	}
	return name, nil
}

// defaultContext is the context saved by `vctx use`, whatever this shell has.
func (a *app) defaultContext() (string, error) {
	b, err := os.ReadFile(a.currentFile())
	if errors.Is(err, fs.ErrNotExist) {
		return "", errors.New("no context selected: pass a name or run 'vctx use <context>'")
	}
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(string(b))
	if !config.ValidName(name) {
		return "", fmt.Errorf("invalid context name %q in %s", name, a.currentFile())
	}
	return name, nil
}

// lsEntry is one context in 'vctx ls --json'; the field names are an interface.
type lsEntry struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	Namespace string `json:"namespace"`
	Token     string `json:"token"`
	Current   bool   `json:"current"`
}

func (a *app) list(asJSON bool) error {
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
	entries := make([]lsEntry, 0, len(names))
	for _, name := range names {
		vars, err := cfg.Vars(name, a.home)
		if err != nil {
			return err
		}
		entries = append(entries, lsEntry{
			Name:      name,
			Address:   config.RedactAddr(config.VaultAddr(vars)),
			Namespace: vars["VAULT_NAMESPACE"],
			Token:     tokens[name].String(),
			Current:   name == current,
		})
	}
	if asJSON {
		return writeJSON(a.stdout, entries)
	}

	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	if a.stdoutTTY {
		fmt.Fprintln(tw, "  CONTEXT\tADDRESS\tNAMESPACE\tTOKEN")
	}
	for _, e := range entries {
		mark := " "
		if e.Current {
			mark = "*"
		}
		tok := e.Token
		if tok == "none" {
			tok = "-"
		}
		ns := e.Namespace
		if ns == "" {
			ns = "-"
		}
		fmt.Fprintf(tw, "%s %s\t%s\t%s\t%s\n", mark, e.Name, e.Address, ns, tok)
	}
	return tw.Flush()
}

// writeJSON prints v as one indented JSON document.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (a *app) use(cfg *config.Config, name string) error {
	if _, ok := cfg.Contexts[name]; !ok {
		return fmt.Errorf("unknown context %q", name)
	}
	if err := safefile.Write(a.currentFile(), []byte(name+"\n"), 0o600); err != nil {
		return fmt.Errorf("save current context: %w", err)
	}
	return nil
}

// shellOverride returns the $VCTX_CONTEXT of this shell when it differs from name.
func (a *app) shellOverride(name string) string {
	if shell := a.getenv(environ.Context); shell != name {
		return shell
	}
	return ""
}

// env is 'vctx env': exports for name, the default context, or undoing a switch.
func (a *app) env(name string, fromDefault, clear, fish bool) error {
	write := environ.WritePOSIX
	if fish {
		write = environ.WriteFish
	}
	if clear {
		write(a.stdout, a.environ, nil)
		return nil
	}

	var err error
	if fromDefault {
		name, err = a.defaultContext()
	} else {
		name, err = a.contextName(name)
	}
	if err != nil {
		return err
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	vars, err := environ.ContextVars(cfg, name, a.home)
	if err != nil {
		return err
	}
	if err := token.RegisterHelper(vars, a.stateDir, a.self); err != nil {
		return err
	}
	write(a.stdout, a.environ, vars)
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

func (a *app) execWith(cfg *config.Config, name string, argv []string) error {
	if bin := filepath.Base(argv[0]); bin == "vault" || bin == filepath.Base(a.vaultBin()) {
		if flag := addressFlag(argv[1:]); flag != "" {
			return fmt.Errorf("%s would send the %s token to another server; set the address in the context instead", flag, name)
		}
	}
	vars, err := environ.ContextVars(cfg, name, a.home)
	if err != nil {
		return err
	}
	if err := token.RegisterHelper(vars, a.stateDir, a.self); err != nil {
		return err
	}
	env := environ.Apply(a.environ, vars)
	bin, err := environ.LookPath(argv[0], env)
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
