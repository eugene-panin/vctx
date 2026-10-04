package main

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
	"unicode"
)

// loginFlags are the only vault login flags a login setting may carry: the
// others either change the server, namespace or output (-address, -namespace,
// -no-print=false, -output-curl-string) or carry a secret (-header, -mfa).
var loginFlags = []string{"method", "path"}

// secretKeyParts mark key=value arguments that carry a credential; vault asks
// for those itself, and the config is no place for them.
var secretKeyParts = []string{"secret", "password", "passcode", "token", "key", "jwt", "totp", "credential"}

// loginArgs splits the login setting of a context into `vault login`
// arguments, the way a shell would for simple quoting, and checks them.
func loginArgs(s string) ([]string, error) {
	args, err := splitArgs(s)
	if err != nil {
		return nil, err
	}
	return normalizeLoginArgs(args)
}

// normalizeLoginArgs checks login arguments and writes each flag as
// -name=value. Flags must come first: vault ignores them after key=value.
func normalizeLoginArgs(args []string) ([]string, error) {
	var out []string
	seenKV := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			if seenKV {
				return nil, fmt.Errorf("%s: put flags before key=value arguments, vault ignores them after", arg)
			}
			name, value, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
			if !slices.Contains(loginFlags, name) {
				return nil, fmt.Errorf("%s: only -method and -path are allowed here", arg)
			}
			if !hasValue && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && !strings.Contains(args[i+1], "=") {
				i++
				value = args[i]
			}
			if value == "" {
				return nil, fmt.Errorf("-%s needs a value", name)
			}
			out = append(out, "-"+name+"="+value)
			continue
		}
		key, _, hasValue := strings.Cut(arg, "=")
		if !hasValue {
			return nil, fmt.Errorf("%q: write -flag=value or key=value; vault would take a bare word as a token", arg)
		}
		lower := strings.ToLower(key)
		for _, part := range secretKeyParts {
			if strings.Contains(lower, part) {
				return nil, fmt.Errorf("%s= looks like a secret; leave it out, vault asks for it", key)
			}
		}
		seenKV = true
		out = append(out, arg)
	}
	return out, nil
}

// splitArgs splits s at white space (newlines included) outside single or double quotes.
func splitArgs(s string) ([]string, error) {
	var args []string
	var cur strings.Builder
	var quote rune
	inArg := false
	for _, r := range s {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote != 0:
			cur.WriteRune(r)
		case r == '\'' || r == '"':
			quote, inArg = r, true
		case unicode.IsSpace(r):
			if inArg {
				args = append(args, cur.String())
				cur.Reset()
				inArg = false
			}
		default:
			cur.WriteRune(r)
			inArg = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if inArg {
		args = append(args, cur.String())
	}
	return args, nil
}

// keepInterrupts stops Ctrl-C from ending vctx while vault runs in the
// foreground: the terminal sends SIGINT to the whole process group, and vctx
// must live on to report, and to have switched. The returned func undoes it.
func keepInterrupts() func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	return func() { signal.Stop(ch) }
}

// tokenWorks asks vault whether the token it would use with env is accepted.
// Call it only when there is a token: vault answers a missing one with the
// same bare 403 as a working token that may not look itself up (no default
// policy), which counts as working. It is an error, not a no, when vault could
// not tell.
func (a *app) tokenWorks(env []string) (bool, error) {
	bin, err := lookPath(a.vaultBin(), env)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "token", "lookup", "-format=json")
	cmd.Env = env
	restore := keepInterrupts()
	out, err := cmd.CombinedOutput()
	restore()
	text := string(out)
	switch {
	case err == nil:
		return true, nil
	case strings.Contains(text, "invalid token"):
		return false, nil
	case strings.Contains(text, "Code: 403"):
		return true, nil
	}
	return false, fmt.Errorf("check token: %s", vaultError(text))
}

// vaultHasToken asks vault whether it has a token at all with env, for a
// context whose token helper is not vctx. The token is read, never shown.
func (a *app) vaultHasToken(env []string) (bool, error) {
	bin, err := lookPath(a.vaultBin(), env)
	if err != nil {
		return false, err
	}
	cmd := exec.Command(bin, "print", "token")
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("ask vault for its token: %w", err)
	}
	return strings.TrimSpace(string(out)) != "", nil
}

// vaultError keeps the useful part of a vault CLI error: the HTTP code and the first reason.
func vaultError(out string) string {
	var code, reason string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case code == "" && strings.HasPrefix(line, "Code:"):
			code = strings.TrimSuffix(line, " Errors:")
		case reason == "" && strings.HasPrefix(line, "* "):
			reason = strings.TrimPrefix(line, "* ")
		}
	}
	if code == "" && reason == "" {
		code, _, _ = strings.Cut(strings.TrimSpace(out), "\n")
	}
	return sanitize(strings.TrimSpace(code+" "+reason), 200)
}

// ensureLogin makes sure context name has a working token after `vctx use`:
// with none, or one vault refuses, it logs in. It only reports problems: the
// switch has happened either way.
func (a *app) ensureLogin(cfg *config, name string) {
	if !a.stdinTTY || !a.stderrTTY {
		return // nothing to ask in a script
	}
	p := newPalette(a.stderr)
	warn := func(format string, args ...any) {
		fmt.Fprintln(a.stderr, p.warn.Render("  "+fmt.Sprintf(format, args...)))
	}
	env, err := a.helperEnv(cfg, name)
	if err != nil {
		warn("%v", err)
		return
	}
	if ok, why := a.loginPossible(env); !ok {
		warn("not logging in: %s", why)
		return
	}
	vars, err := cfg.vars(name, a.home)
	if err != nil {
		warn("%v", err)
		return
	}

	var reason string
	switch {
	case vars["VAULT_TOKEN"] != "" || vars["VAULT_AGENT_ADDR"] != "":
		// vault takes the token from the context or the agent; a login would not change it.
		if ok, err := a.tokenWorks(env); err != nil {
			warn("%v", err)
		} else if !ok {
			warn("vault refuses the token from VAULT_TOKEN or vault agent for %s", name)
		}
		return
	case vars["VAULT_CONFIG_PATH"] != "":
		// The context brings its own token helper, so vctx's store tells nothing.
		has, err := a.vaultHasToken(env)
		if err != nil {
			warn("%v", err)
			return
		}
		reason = "no token yet"
		if has {
			ok, err := a.tokenWorks(env)
			if err != nil {
				warn("%v", err)
				return
			}
			if ok {
				return
			}
			reason = "the token expired"
		}
	default:
		store, err := a.tokens()
		if err != nil {
			warn("%v", err)
			return
		}
		state, err := a.tokenStateOf(store, cfg, name)
		if err != nil {
			warn("%v", err)
			return
		}
		reason = "no token yet"
		switch state {
		case tokenStale:
			reason = "the token is for another address"
		case tokenOK:
			ok, err := a.tokenWorks(env)
			if err != nil {
				warn("%v", err)
				return
			}
			if ok {
				return
			}
			reason = "the token expired"
		}
	}
	if err := a.login(cfg, name, reason, env, a.stdin, a.stderr); err != nil {
		warn("login failed: %v", err)
	}
}

// loginPossible probes the instance: a login only makes sense against one
// that answers and can serve requests (not sealed, TLS working).
func (a *app) loginPossible(env []string) (bool, string) {
	t, err := targetFor(env)
	if err != nil {
		_, long := classify(err)
		return false, long
	}
	timeout, _ := a.checkTimeout()
	if timeout == 0 {
		timeout = defaultCheckTimeout
	}
	r := probe(context.Background(), t, env, timeout)
	switch {
	case r.err != nil:
		_, long := classify(r.err)
		return false, long
	case !r.health.usable():
		return false, "the server is " + r.health.String()
	}
	return true, ""
}

// helperEnv is the environment vault runs with for context name, vctx being its token helper.
func (a *app) helperEnv(cfg *config, name string) ([]string, error) {
	vars, err := a.contextVars(cfg, name)
	if err != nil {
		return nil, err
	}
	if err := a.registerHelper(vars); err != nil {
		return nil, err
	}
	return applyEnv(a.environ, vars), nil
}

// login runs `vault login` for context name. The method comes from the
// config, or from the answers given the last time; with neither it asks,
// and remembers the answers once a login with them succeeds.
func (a *app) login(cfg *config, name, reason string, env []string, in io.Reader, out io.Writer) error {
	p := newPalette(out)
	lines := bufio.NewReader(in)
	args, asked := a.loginFor(cfg, name), false
	if args == nil {
		fmt.Fprintf(out, "%s %s: %s. How do you log in?\n", p.accent.Render("●"), p.bold.Render(name), reason)
		var err error
		if args, err = askLogin(lines, out, a.getenv("USER")); err != nil {
			return err
		}
		asked = true
	} else {
		fmt.Fprintln(out, p.dim.Render("  "+reason+", logging in: vault login "+strings.Join(args, " ")))
	}
	bin, err := lookPath(a.vaultBin(), env)
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, append([]string{"login", "-no-print"}, args...)...)
	cmd.Env = env
	// vault needs the terminal itself to ask for a password; a terminal hands
	// lines over one at a time, so the answers above left nothing buffered.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, out
	restore := keepInterrupts()
	err = cmd.Run()
	restore()
	if err != nil {
		return err
	}
	if asked {
		if err := a.rememberLogin(name, args); err != nil {
			fmt.Fprintln(out, p.warn.Render("  could not remember the login method: "+err.Error()))
		}
	}
	// -no-print keeps the token off the screen, and vault's success message with it.
	fmt.Fprintln(out, p.ok.Render("  logged in"))
	return nil
}

var loginMethods = []string{"userpass", "ldap", "oidc", "token", "okta", "github", "radius", "other"}

// askLogin asks for a login method and what it needs besides the credential,
// which vault asks for itself.
func askLogin(in *bufio.Reader, out io.Writer, user string) ([]string, error) {
	for i, m := range loginMethods {
		fmt.Fprintf(out, "  %d) %s", i+1, m)
	}
	fmt.Fprintln(out)
	choice, err := ask(in, out, "method", "1")
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

	var args []string
	switch method {
	case "other":
		line, err := ask(in, out, "arguments for vault login", "")
		if err != nil {
			return nil, err
		}
		return loginArgs(line)
	case "token":
		return []string{"-method=token"}, nil
	}
	args = append(args, "-method="+method)
	path, err := ask(in, out, "mount path", method)
	if err != nil {
		return nil, err
	}
	if path != method {
		args = append(args, "-path="+path)
	}
	switch method {
	case "userpass", "ldap", "okta", "radius":
		u, err := ask(in, out, "username", user)
		if err != nil {
			return nil, err
		}
		args = append(args, "username="+u)
	case "oidc":
		role, err := ask(in, out, "role (empty for the default)", "")
		if err != nil {
			return nil, err
		}
		if role != "" {
			args = append(args, "role="+role)
		}
	}
	return normalizeLoginArgs(args)
}

// ask reads one answer, def when the line is empty.
func ask(in *bufio.Reader, out io.Writer, prompt, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(out, "  %s [%s]: ", prompt, def)
	} else {
		fmt.Fprintf(out, "  %s: ", prompt)
	}
	line, err := in.ReadString('\n')
	if err != nil && (line == "" || !errors.Is(err, io.EOF)) {
		return "", fmt.Errorf("no answer: %w", err)
	}
	if line = strings.TrimSpace(line); line != "" {
		return line, nil
	}
	return def, nil
}

func (a *app) rememberedLoginPath(name string) string {
	return filepath.Join(a.stateDir, "login", name+".json")
}

// loginFor is the login method of context name: from the config, else the
// remembered answers; nil when there is neither.
func (a *app) loginFor(cfg *config, name string) []string {
	if args := cfg.login(name); args != nil {
		return args
	}
	b, err := os.ReadFile(a.rememberedLoginPath(name))
	if err != nil {
		return nil
	}
	var args []string
	if json.Unmarshal(b, &args) != nil || len(args) == 0 {
		return nil
	}
	args, err = normalizeLoginArgs(args)
	if err != nil {
		return nil
	}
	return args
}

func (a *app) rememberLogin(name string, args []string) error {
	b, err := json.Marshal(args)
	if err != nil {
		return err
	}
	return writeFileAtomic(a.rememberedLoginPath(name), b, 0o600)
}

// loginExec runs login under the UI as a tea.ExecCommand, so the UI hands the
// terminal over for the questions and vault's own prompts.
type loginExec struct {
	a        *app
	cfg      *config
	name     string
	in       io.Reader
	out, err io.Writer
}

func (l *loginExec) SetStdin(r io.Reader)  { l.in = r }
func (l *loginExec) SetStdout(w io.Writer) { l.out = w }
func (l *loginExec) SetStderr(w io.Writer) { l.err = w }

func (l *loginExec) Run() error {
	env, err := l.a.helperEnv(l.cfg, l.name)
	if err != nil {
		return err
	}
	return l.a.login(l.cfg, l.name, "login requested", env, l.in, l.out)
}
