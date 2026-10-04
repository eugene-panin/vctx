package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// secretArgs are `vault login` key=value arguments that carry a credential;
// vault asks for those itself, and the config is no place for them.
var secretArgs = []string{"token", "password", "passcode", "secret_id", "jwt", "role_id_secret"}

// loginArgs splits the login setting of a context into `vault login`
// arguments, the way a shell would for simple quoting, and refuses ones that
// carry a credential or point vault at another server.
func loginArgs(s string) ([]string, error) {
	args, err := splitArgs(s)
	if err != nil {
		return nil, err
	}
	for _, arg := range args {
		switch key, _, hasValue := strings.Cut(arg, "="); {
		case strings.HasPrefix(arg, "-"):
			if name := strings.TrimLeft(key, "-"); name == "address" || name == "agent-address" {
				return nil, fmt.Errorf("%s: the context's address is used", arg)
			}
		case !hasValue:
			return nil, fmt.Errorf("%q looks like a token; leave it out, vault asks for it", arg)
		case slices.Contains(secretArgs, strings.ToLower(key)):
			return nil, fmt.Errorf("%s= is a secret; leave it out, vault asks for it", key)
		}
	}
	return args, nil
}

// splitArgs splits s at spaces outside single or double quotes.
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
		case r == ' ' || r == '\t':
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

// tokenWorks asks vault whether the context's stored token is still accepted.
// It is an error, not a no, when vault could not tell.
func (a *app) tokenWorks(env []string) (bool, error) {
	bin, err := lookPath(a.vaultBin(), env)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "token", "lookup", "-format=json")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	switch {
	case err == nil:
		return true, nil
	case bytes.Contains(out, []byte("Code: 403")), bytes.Contains(out, []byte("permission denied")):
		return false, nil
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return false, fmt.Errorf("check token: %s", sanitize(line, 200))
}

// ensureLogin logs in to context name when it has no working token, with the
// login arguments from the config; vault asks for whatever credential the
// method needs. It only reports problems: the switch has happened either way.
func (a *app) ensureLogin(cfg *config, name string) {
	if !a.stdinTTY || !a.stderrTTY {
		return // nothing to ask in a script
	}
	p := newPalette(a.stderr)
	warn := func(format string, args ...any) {
		fmt.Fprintln(a.stderr, p.warn.Render("  "+fmt.Sprintf(format, args...)))
	}

	vars, err := a.contextVars(cfg, name)
	if err == nil {
		err = a.registerHelper(vars)
	}
	if err != nil {
		warn("%v", err)
		return
	}
	env := applyEnv(a.environ, vars)
	if err := a.ensureReachable(name, env); err != nil {
		warn("not logging in: %v", err)
		return
	}
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
	reason := "no token yet"
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

	args := cfg.login(name)
	if args == nil {
		warn("%s: run `vault login`, or set `login:` for %s in %s", reason, name, a.configPath)
		return
	}
	fmt.Fprintln(a.stderr, p.dim.Render("  "+reason+", logging in: vault login "+strings.Join(args, " ")))
	bin, err := lookPath(a.vaultBin(), env)
	if err != nil {
		warn("%v", err)
		return
	}
	cmd := exec.Command(bin, append([]string{"login", "-no-print"}, args...)...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = a.stdin, a.stderr, a.stderr
	if err := cmd.Run(); err != nil {
		warn("login failed: %v", err)
		return
	}
	// -no-print keeps the token off the screen, and vault's success message with it.
	fmt.Fprintln(a.stderr, p.ok.Render("  logged in"))
}
