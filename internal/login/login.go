// Package login logs in to a context with the Vault CLI when it has no working token.
//
// vault itself asks for the credential; vctx keeps no secret.
package login

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/eugene-panin/vctx/internal/config"
	"github.com/eugene-panin/vctx/internal/environ"
	"github.com/eugene-panin/vctx/internal/probe"
	"github.com/eugene-panin/vctx/internal/safefile"
	"github.com/eugene-panin/vctx/internal/style"
	"github.com/eugene-panin/vctx/internal/termsafe"
	"github.com/eugene-panin/vctx/internal/token"
	"github.com/muesli/cancelreader"
)

// Runner logs in to contexts. Its fields are what vctx knows about the
// environment it runs in.
type Runner struct {
	Environ     []string
	Home        string
	StateDir    string
	Self        string // the vctx binary, vault's token helper
	VaultBin    string
	Timeout     time.Duration // probe timeout; probe.DefaultTimeout when zero
	Tokens      func() (token.Store, error)
	In          io.Reader
	Out         io.Writer // where vctx reports and asks, stderr for the CLI
	Interactive bool      // In and Out are a terminal: there is someone to ask
	// NoAsk says why nothing is asked when Interactive is false, such as
	// "no terminal" or "--no-input".
	NoAsk   string
	NoColor bool // --no-color
}

// colorEnv is the environment styling decides by.
func (r *Runner) colorEnv() []string {
	if r.NoColor {
		return append(slices.Clip(r.Environ), "NO_COLOR=1")
	}
	return r.Environ
}

// ErrCancelled is a login given up with Ctrl-C.
var ErrCancelled = errors.New("cancelled")

// Interruptible catches Ctrl-C until stop is called. The terminal sends
// SIGINT to the whole foreground group: vault, when it runs, handles it
// itself, and vctx turns it into cancelling ctx instead of dying, so it can
// still report and the shell function still switches the terminal.
func Interruptible() (ctx context.Context, stop func()) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

// answers reads replies to vctx's own questions; Ctrl-C ends a pending read.
type answers struct {
	r     *bufio.Reader
	close func()
}

func newAnswers(ctx context.Context, in io.Reader) *answers {
	if f, ok := in.(*os.File); ok {
		if cr, err := cancelreader.NewReader(f); err == nil {
			stop := context.AfterFunc(ctx, func() { cr.Cancel() })
			return &answers{r: bufio.NewReader(cr), close: func() { stop(); cr.Close() }}
		}
	}
	return &answers{r: bufio.NewReader(in), close: func() {}}
}

// ask reads one answer, def when the line is empty.
func (a *answers) ask(out io.Writer, prompt, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(out, "  %s [%s]: ", prompt, def)
	} else {
		fmt.Fprintf(out, "  %s: ", prompt)
	}
	line, err := a.r.ReadString('\n')
	if errors.Is(err, cancelreader.ErrCanceled) {
		fmt.Fprintln(out)
		return "", ErrCancelled
	}
	if err != nil && (line == "" || !errors.Is(err, io.EOF)) {
		return "", fmt.Errorf("no answer: %w", err)
	}
	if line = strings.TrimSpace(line); line != "" {
		return line, nil
	}
	return def, nil
}

// runVault runs vault with env and the terminal, for a short check; its output is returned.
func (r *Runner) runVault(ctx context.Context, env []string, args ...string) ([]byte, error) {
	bin, err := environ.LookPath(r.VaultBin, env)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	return cmd.CombinedOutput()
}

// tokenWorks asks vault whether the token it would use with env is accepted.
// Call it only when there is a token: vault answers a missing one with the
// same bare 403 as a working token that may not look itself up (no default
// policy), which counts as working. It is an error, not a no, when vault could
// not tell.
func (r *Runner) tokenWorks(ctx context.Context, env []string) (bool, error) {
	out, err := r.runVault(ctx, env, "token", "lookup", "-format=json")
	text := string(out)
	switch {
	case err == nil:
		return true, nil
	case ctx.Err() != nil:
		return false, ErrCancelled
	case strings.Contains(text, "invalid token"):
		return false, nil
	case strings.Contains(text, "Code: 403"):
		return true, nil
	}
	return false, fmt.Errorf("check token: %s", vaultError(text))
}

// vaultHasToken asks vault whether it has a token at all with env, for a
// context whose token helper is not vctx. The token is read, never shown.
func (r *Runner) vaultHasToken(ctx context.Context, env []string) (bool, error) {
	bin, err := environ.LookPath(r.VaultBin, env)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "print", "token")
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return false, ErrCancelled
		}
		return false, fmt.Errorf("ask vault for its token: %w", err)
	}
	return strings.TrimSpace(string(out)) != "", nil
}

// vaultError keeps the useful part of a vault CLI error: the HTTP code and the
// first reason, the first nested one when vault lists several.
func vaultError(out string) string {
	var code, reason string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case code == "" && strings.HasPrefix(line, "Code:"):
			code = strings.TrimSuffix(line, " Errors:")
		case reason == "" && strings.HasPrefix(line, "* ") && !strings.HasSuffix(line, "occurred:"):
			reason = strings.TrimPrefix(line, "* ")
		}
	}
	if code == "" && reason == "" {
		code, _, _ = strings.Cut(strings.TrimSpace(out), "\n")
	}
	return termsafe.String(strings.TrimSpace(code+" "+reason), 200)
}

// Ensure makes sure context name has a working token after `vctx use`:
// with none, or one vault refuses, it logs in. It only reports problems: the
// switch has happened either way. ctx ends with Ctrl-C, and then Ensure
// returns ErrCancelled. With no one to ask it only says what is missing.
func (r *Runner) Ensure(ctx context.Context, cfg *config.Config, name string) error {
	if !r.Interactive {
		r.noLogin(cfg, name)
		return nil
	}
	r.ensure(ctx, cfg, name)
	if ctx.Err() != nil {
		return ErrCancelled
	}
	return nil
}

// noLogin says so when context name has no token vctx could use, and there is
// no one to log in: otherwise vault fails later with a bare 403.
func (r *Runner) noLogin(cfg *config.Config, name string) {
	vars, err := cfg.Vars(name, r.Home)
	if err != nil || vars["VAULT_AGENT_ADDR"] != "" || vars["VAULT_TOKEN"] != "" || vars["VAULT_CONFIG_PATH"] != "" {
		return // vctx's store does not decide these
	}
	store, err := r.Tokens()
	if err != nil {
		return
	}
	state, err := token.StateOf(store, cfg, r.Home, name)
	if err != nil || state == token.OK {
		return
	}
	what := "has no token yet"
	if state == token.Stale {
		what = "has a token for another address"
	}
	why := r.NoAsk
	if why == "" {
		why = "nothing can be asked"
	}
	p := style.New(r.Out, r.colorEnv())
	fmt.Fprintln(r.Out, p.Warn.Render(fmt.Sprintf("  %s %s; not logging in (%s): 'vctx use %s' in a terminal logs in", name, what, why, name)))
}

func (r *Runner) ensure(ctx context.Context, cfg *config.Config, name string) {
	p := style.New(r.Out, r.colorEnv())
	warn := func(format string, args ...any) {
		fmt.Fprintln(r.Out, p.Warn.Render("  "+fmt.Sprintf(format, args...)))
	}
	report := func(err error) {
		if errors.Is(err, ErrCancelled) {
			warn("login cancelled")
			return
		}
		warn("%v", err)
	}
	env, err := r.helperEnv(cfg, name)
	if err != nil {
		report(err)
		return
	}
	if ok, why := r.loginPossible(ctx, env); !ok {
		if ctx.Err() != nil {
			report(ErrCancelled)
			return
		}
		warn("not logging in: %s", why)
		return
	}
	vars, err := cfg.Vars(name, r.Home)
	if err != nil {
		report(err)
		return
	}

	var reason string
	switch {
	case vars["VAULT_AGENT_ADDR"] != "":
		return // vault agent authenticates for vault; nothing to log in to
	case vars["VAULT_TOKEN"] != "":
		// vault takes the token from the context; a login would not change it.
		if ok, err := r.tokenWorks(ctx, env); err != nil {
			report(err)
		} else if !ok {
			warn("vault refuses the token from VAULT_TOKEN for %s", name)
		}
		return
	case vars["VAULT_CONFIG_PATH"] != "":
		// The context brings its own token helper, so vctx's store tells nothing.
		has, err := r.vaultHasToken(ctx, env)
		if err != nil {
			report(err)
			return
		}
		reason = "no token yet"
		if has {
			ok, err := r.tokenWorks(ctx, env)
			if err != nil {
				report(err)
				return
			}
			if ok {
				return
			}
			reason = "the token expired"
		}
	default:
		store, err := r.Tokens()
		if err != nil {
			report(err)
			return
		}
		state, err := token.StateOf(store, cfg, r.Home, name)
		if err != nil {
			report(err)
			return
		}
		reason = "no token yet"
		switch state {
		case token.Stale:
			reason = "the token is for another address"
		case token.OK:
			ok, err := r.tokenWorks(ctx, env)
			if err != nil {
				report(err)
				return
			}
			if ok {
				return
			}
			reason = "the token expired"
		}
	}
	if err := r.login(ctx, cfg, name, reason, env, r.In, r.Out); err != nil {
		if errors.Is(err, ErrCancelled) {
			report(err)
			return
		}
		warn("login failed: %v", err)
	}
}

// loginPossible probes the instance: a login only makes sense against one
// that answers and can serve requests (not sealed, TLS working).
func (r *Runner) loginPossible(ctx context.Context, env []string) (bool, string) {
	t, err := probe.TargetFor(env)
	if err != nil {
		_, long := probe.Classify(err)
		return false, long
	}
	timeout := r.Timeout
	if timeout == 0 {
		timeout = probe.DefaultTimeout
	}
	res := probe.Probe(ctx, t, env, timeout)
	switch {
	case res.Err != nil:
		_, long := probe.Classify(res.Err)
		return false, long
	case !res.Health.Usable():
		return false, "the server is " + res.Health.String()
	}
	return true, ""
}

// helperEnv is the environment vault runs with for context name, vctx being its token helper.
func (r *Runner) helperEnv(cfg *config.Config, name string) ([]string, error) {
	vars, err := environ.ContextVars(cfg, name, r.Home)
	if err != nil {
		return nil, err
	}
	if err := token.RegisterHelper(vars, r.StateDir, r.Self); err != nil {
		return nil, err
	}
	return environ.Apply(r.Environ, vars), nil
}

// login runs `vault login` for context name. The method comes from the
// config, or from the answers given the last time; with neither it asks, and
// remembers the answers once a login with them succeeds. When a remembered
// method fails, it offers to choose another.
func (r *Runner) login(ctx context.Context, cfg *config.Config, name, reason string, env []string, in io.Reader, out io.Writer) error {
	p := style.New(out, r.colorEnv())
	ans := newAnswers(ctx, in)
	defer ans.close()

	args, fromConfig := cfg.Login(name), true
	if args == nil {
		args, fromConfig = r.remembered(name), false
	}
	asked := false
	if args == nil {
		fmt.Fprintf(out, "%s %s: %s. How do you log in?\n", p.Accent.Render("●"), p.Bold.Render(name), reason)
		var err error
		if args, err = askLogin(ans, out, environ.Value(r.Environ, "USER")); err != nil {
			return err
		}
		asked = true
	} else {
		fmt.Fprintln(out, p.Dim.Render("  "+reason+", logging in: vault login "+strings.Join(args, " ")))
	}

	for {
		err := r.vaultLogin(env, args, in, out)
		switch {
		case err == nil:
			if asked {
				if err := r.remember(name, args); err != nil {
					fmt.Fprintln(out, p.Warn.Render("  could not remember the login method: "+err.Error()))
				}
			}
			// -no-print keeps the token off the screen, and vault's success message with it.
			fmt.Fprintln(out, p.OK.Render("  logged in"))
			return nil
		case ctx.Err() != nil:
			return ErrCancelled
		case fromConfig:
			return err
		}
		// A remembered or just chosen method may be the wrong one, not only the password.
		again, aerr := ans.ask(out, "login failed; choose another method? [y/N]", "")
		if aerr != nil {
			return aerr
		}
		if !strings.EqualFold(again, "y") {
			return err
		}
		if args, err = askLogin(ans, out, environ.Value(r.Environ, "USER")); err != nil {
			return err
		}
		asked = true
	}
}

// vaultLogin runs `vault login` with the terminal: vault asks for the
// password or opens the browser. A terminal hands lines over one at a time,
// so the answers read before left nothing buffered.
func (r *Runner) vaultLogin(env, args []string, in io.Reader, out io.Writer) error {
	bin, err := environ.LookPath(r.VaultBin, env)
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, append([]string{"login", "-no-print"}, args...)...)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = out, out
	// Only the terminal itself: exec would copy any other reader into vault
	// whole, swallowing the answers to the questions that may follow.
	if f, ok := in.(*os.File); ok {
		cmd.Stdin = f
	}
	return cmd.Run()
}

var loginMethods = []string{"userpass", "ldap", "oidc", "token", "okta", "github", "radius", "other"}

// askLogin asks for a login method and what it needs besides the credential,
// which vault asks for itself.
func askLogin(ans *answers, out io.Writer, user string) ([]string, error) {
	for i, m := range loginMethods {
		fmt.Fprintf(out, "  %d) %s", i+1, m)
	}
	fmt.Fprintln(out)
	choice, err := ans.ask(out, "method", "1")
	if err != nil {
		return nil, err
	}
	method := choice
	if n, err := strconv.Atoi(choice); err == nil && n >= 1 && n <= len(loginMethods) {
		method = loginMethods[n-1]
	}
	if !slices.Contains(loginMethods, method) {
		return nil, fmt.Errorf("unknown method %q", choice)
	}

	switch method {
	case "other":
		line, err := ans.ask(out, "arguments for vault login", "")
		if err != nil {
			return nil, err
		}
		return config.LoginArgs(line)
	case "token":
		return []string{"-method=token"}, nil
	}
	args := []string{"-method=" + method}
	path, err := ans.ask(out, "mount path", method)
	if err != nil {
		return nil, err
	}
	if path != method {
		args = append(args, "-path="+path)
	}
	switch method {
	case "userpass", "ldap", "okta", "radius":
		u, err := ans.ask(out, "username", user)
		if err != nil {
			return nil, err
		}
		args = append(args, "username="+u)
	case "oidc":
		role, err := ans.ask(out, "role (empty for the default)", "")
		if err != nil {
			return nil, err
		}
		if role != "" {
			args = append(args, "role="+role)
		}
	}
	return config.NormalizeLoginArgs(args)
}

// rememberedPath keeps the login answers for context name: not secrets.
func (r *Runner) rememberedPath(name string) string {
	return filepath.Join(r.StateDir, "login", name+".json")
}

// remembered is the login method answered for context name, nil when none was.
func (r *Runner) remembered(name string) []string {
	b, err := os.ReadFile(r.rememberedPath(name))
	if err != nil {
		return nil
	}
	var args []string
	if json.Unmarshal(b, &args) != nil || len(args) == 0 {
		return nil
	}
	args, err = config.NormalizeLoginArgs(args)
	if err != nil {
		return nil
	}
	return args
}

// Method is the login method of context name: from the config, else the
// remembered answers; nil when there is neither.
func (r *Runner) Method(cfg *config.Config, name string) []string {
	if args := cfg.Login(name); args != nil {
		return args
	}
	return r.remembered(name)
}

// remember keeps args as the login method of context name.
func (r *Runner) remember(name string, args []string) error {
	b, err := json.Marshal(args)
	if err != nil {
		return err
	}
	return safefile.Write(r.rememberedPath(name), b, 0o600)
}

// Cmd is a login run under the UI, which hands the terminal over for the
// questions and vault's own prompts; it fits tea.ExecCommand.
type Cmd struct {
	r    *Runner
	cfg  *config.Config
	name string
	in   io.Reader
	out  io.Writer
}

func (l *Cmd) SetStdin(r io.Reader)  { l.in = r }
func (l *Cmd) SetStdout(w io.Writer) { l.out = w }
func (l *Cmd) SetStderr(io.Writer)   {}

// Run waits for Enter after a failure, so vault's message is read before the UI covers it.
func (l *Cmd) Run() error {
	ctx, stop := Interruptible()
	defer stop()
	env, err := l.r.helperEnv(l.cfg, l.name)
	if err == nil {
		err = l.r.login(ctx, l.cfg, l.name, "login requested", env, l.in, l.out)
	}
	if err != nil && !errors.Is(err, ErrCancelled) {
		fmt.Fprintf(l.out, "  %s login failed: %v\n", l.name, err)
		ans := newAnswers(ctx, l.in)
		defer ans.close()
		_, _ = ans.ask(l.out, "press Enter to return to vctx", "")
	}
	return err
}

// Cmd returns the login for context name, for the UI.
func (r *Runner) Cmd(cfg *config.Config, name string) *Cmd {
	return &Cmd{r: r, cfg: cfg, name: name}
}
