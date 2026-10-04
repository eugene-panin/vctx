package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/eugene-panin/vctx/internal/token"
	"github.com/eugene-panin/vctx/internal/vaulttest"
)

const testConfig = `
defaults:
  VAULT_FORMAT: json
contexts:
  dev:
    VAULT_ADDR: http://127.0.0.1:8201
    VAULT_CACERT: ~/ca.pem
  prod:
    VAULT_ADDR: https://vault.example.com
    VAULT_NAMESPACE: admin
    HTTPS_PROXY: http://proxy:3128
`

// helperRunner returns a function that runs a token helper operation the way
// vault does: env on top of the app's environment, input on stdin. It returns stdout.
func helperRunner(t *testing.T, a *app, out *bytes.Buffer) func(op, input string, env ...string) string {
	base := a.environ
	return func(op, input string, env ...string) string {
		t.Helper()
		out.Reset()
		a.environ = withEnv(base, env...)
		a.stdin = strings.NewReader(input)
		if err := a.run([]string{op}); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		return out.String()
	}
}

// withEnv returns env with kvs taking precedence; the first occurrence of a key wins.
func withEnv(env []string, kvs ...string) []string {
	return append(slices.Clip(kvs), env...)
}

type execCall struct {
	argv0 string
	argv  []string
	env   []string
}

func newTestApp(t *testing.T, environ ...string) (*app, *bytes.Buffer, *execCall) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	call := &execCall{}
	a := &app{
		home:       "/home/u",
		configPath: cfg,
		stateDir:   filepath.Join(dir, "state"),
		self:       "/usr/local/bin/vctx",
		environ:    withEnv([]string{"PATH=" + os.Getenv("PATH"), "VCTX_VAULT_BIN=/bin/sh", "VCTX_CHECK_TIMEOUT=0", "VCTX_TOKEN_STORE=file"}, environ...),
		stdin:      strings.NewReader(""),
		stdout:     &out,
		stderr:     &bytes.Buffer{},
		keyring:    noKeyring{},
		exec: func(argv0 string, argv, env []string) error {
			*call = execCall{argv0, argv, env}
			return nil
		},
	}
	return a, &out, call
}

func TestContextNameIsNoCommand(t *testing.T) {
	a, _, _ := newTestApp(t)
	writeContexts(t, a, map[string]string{"env": "http://v"})
	if _, err := a.loadConfig(); err == nil || !strings.Contains(err.Error(), "is a vctx command") {
		t.Errorf("err = %v", err)
	}
}

// commands must list every subcommand run dispatches on: a context named
// like a new one would no longer run with "vctx <context>".
func TestCommandsListsEverySubcommand(t *testing.T) {
	f, err := parser.ParseFile(gotoken.NewFileSet(), "app.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var cases []string
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "run" {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if cc, ok := n.(*ast.CaseClause); ok {
				for _, e := range cc.List {
					if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == gotoken.STRING {
						cases = append(cases, strings.Trim(lit.Value, `"`))
					}
				}
			}
			return true
		})
		return false
	})
	if len(cases) == 0 {
		t.Fatal("no subcommands found in run")
	}
	for _, op := range []string{"get", "store", "erase"} {
		if !token.IsHelperOp(op) {
			t.Errorf("%s is no token helper operation", op)
		}
		cases = append(cases, op)
	}
	slices.Sort(cases)
	want := slices.Sorted(slices.Values(commands))
	if !slices.Equal(cases, want) {
		t.Errorf("run dispatches on %q, commands lists %q", cases, want)
	}
}

func TestRunContextShortcut(t *testing.T) {
	a, _, call := newTestApp(t,
		"HOME=/home/u",
		"VAULT_TOKEN=leaked",
		"VAULT_ADDR=http://other",
		"VCTX_CONTEXT=prod",
		"VCTX_VARS=HTTPS_PROXY",
		"HTTPS_PROXY=http://proxy:3128",
	)
	if err := a.run([]string{"dev", "kv", "get", "secret/x"}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"/bin/sh", "kv", "get", "secret/x"}; !slices.Equal(call.argv, want) {
		t.Errorf("argv = %q, want %q", call.argv, want)
	}
	for _, kv := range []string{
		"HOME=/home/u",
		"VAULT_ADDR=http://127.0.0.1:8201",
		"VAULT_CACERT=/home/u/ca.pem",
		"VAULT_FORMAT=json",
		"VCTX_CONTEXT=dev",
		"VAULT_CONFIG_PATH=" + filepath.Join(a.stateDir, "vault.hcl"),
	} {
		if !slices.Contains(call.env, kv) {
			t.Errorf("env missing %s", kv)
		}
	}
	for _, kv := range call.env {
		if strings.HasPrefix(kv, "VAULT_TOKEN=") || strings.HasPrefix(kv, "HTTPS_PROXY=") || strings.HasPrefix(kv, "VCTX_VARS=") {
			t.Errorf("env leaked %s", kv)
		}
	}
	b, err := os.ReadFile(filepath.Join(a.stateDir, "vault.hcl"))
	if err != nil || string(b) != "token_helper = \"/usr/local/bin/vctx\"\n" {
		t.Errorf("vault.hcl = %q, %v", b, err)
	}
}

func TestExecUsesCurrentContext(t *testing.T) {
	a, _, call := newTestApp(t)
	if err := a.run([]string{"exec", "--", "sh", "-c", "true"}); err == nil {
		t.Fatal("exec without a selected context succeeded")
	}
	if err := a.run([]string{"use", "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := a.run([]string{"exec", "--", "sh", "-c", "true"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(call.env, "VAULT_NAMESPACE=admin") || !slices.Contains(call.env, "VCTX_VARS=HTTPS_PROXY") {
		t.Errorf("env = %q", call.env)
	}
}

func TestEnvShell(t *testing.T) {
	a, out, _ := newTestApp(t, "VAULT_TOKEN=x", "VAULT_ADDR=y")
	if err := a.run([]string{"env", "prod"}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, line := range []string{
		"unset VAULT_TOKEN\n",
		"export VAULT_ADDR='https://vault.example.com'\n",
		"export HTTPS_PROXY='http://proxy:3128'\n",
		"export VCTX_VARS='HTTPS_PROXY'\n",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("output missing %q:\n%s", line, got)
		}
	}
	if strings.Contains(got, "unset VAULT_ADDR") {
		t.Errorf("VAULT_ADDR unset although it is exported:\n%s", got)
	}

	out.Reset()
	a.environ = withEnv(a.environ, "VCTX_VARS=HTTPS_PROXY", "HTTPS_PROXY=p", "VCTX_CONTEXT=prod")
	if err := a.run([]string{"env", "--clear"}); err != nil {
		t.Fatal(err)
	}
	want := "unset HTTPS_PROXY\nunset VAULT_ADDR\nunset VAULT_TOKEN\nunset VCTX_CONTEXT\nunset VCTX_VARS\n"
	if out.String() != want {
		t.Errorf("clear output:\n%s\nwant:\n%s", out, want)
	}
}

func TestTokenHelperAndLogout(t *testing.T) {
	a, out, _ := newTestApp(t)
	base := a.environ
	helper := helperRunner(t, a, out)

	helper("store", "tok-dev\n", "VCTX_CONTEXT=dev")
	helper("store", "tok-prod", "VCTX_CONTEXT=prod")
	if got := helper("get", "", "VCTX_CONTEXT=dev"); got != "tok-dev" {
		t.Errorf("dev token = %q", got)
	}
	helper("erase", "", "VCTX_CONTEXT=dev")
	if got := helper("get", "", "VCTX_CONTEXT=dev"); got != "" {
		t.Errorf("dev token after erase = %q", got)
	}

	a.environ = base
	if err := a.run([]string{"logout", "prod"}); err != nil {
		t.Fatal(err)
	}
	if hasToken(t, a, "prod") {
		t.Error("prod token still present after logout")
	}
}

func TestVaultConfigRejectsUnsafePath(t *testing.T) {
	for _, self := range []string{"/Users/me/My Tools/vctx"} {
		a, _, _ := newTestApp(t)
		a.self = self
		writeContexts(t, a, map[string]string{"dev": vaulttest.Serve(t, vaulttest.Handler(200, vaulttest.ActiveBody))})
		if err := a.run([]string{"dev", "status"}); err == nil || !strings.Contains(err.Error(), "token helper") {
			t.Errorf("%s accepted as token helper path: %v", self, err)
		}
		// Probing needs no token helper.
		if err := a.run([]string{"check", "dev"}); err != nil {
			t.Errorf("%s: check failed: %v", self, err)
		}
	}
}

func TestContextNameRejectsPaths(t *testing.T) {
	a, _, _ := newTestApp(t)
	victim := filepath.Join(filepath.Dir(a.stateDir), "victim")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"logout", "../../victim"}, {"logout", "nope"}} {
		if err := a.run(args); err == nil {
			t.Errorf("%v succeeded", args)
		}
	}
	a.environ = withEnv(a.environ, "VCTX_CONTEXT=../../victim")
	if err := a.run([]string{"logout"}); err == nil || !strings.Contains(err.Error(), "invalid context name") {
		t.Errorf("logout with bad $VCTX_CONTEXT: %v", err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("file outside the token directory was touched: %v", err)
	}
}

func TestPrivatePaths(t *testing.T) {
	a, _, _ := newTestApp(t)
	if err := os.Chmod(a.configPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := a.run([]string{"ls"}); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("group-writable config: %v", err)
	}
	if err := os.Chmod(a.configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.run([]string{"ls"}); err != nil {
		t.Errorf("0644 config: %v", err)
	}

	if err := os.MkdirAll(a.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(a.stateDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := a.run([]string{"dev", "status"}); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("world-writable state dir: %v", err)
	}
}

func TestSplitExec(t *testing.T) {
	tests := []struct {
		args     []string
		name     string
		wantArgv []string
	}{
		{[]string{"--", "vault", "status"}, "", []string{"vault", "status"}},
		{[]string{"prod", "--", "vault"}, "prod", []string{"vault"}},
		{[]string{"prod", "vault"}, "prod", []string{"vault"}},
		{nil, "", nil},
	}
	for _, tc := range tests {
		name, argv := splitExec(tc.args)
		if name != tc.name || !slices.Equal(argv, tc.wantArgv) {
			t.Errorf("%q: got %q %q", tc.args, name, argv)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	a, _, _ := newTestApp(t)
	var uerr usageError
	for _, args := range [][]string{
		{"exec"}, {"use", "a", "b"}, {"env", "a", "b"}, {"logout", "a", "b"},
		{"env", "--bogus"}, {"nosuchcommand"}, {"use"},
	} {
		if err := a.run(args); !errors.As(err, &uerr) {
			t.Errorf("%q: err = %v, want a usage error", args, err)
		}
	}
}

func TestListShowsDefaults(t *testing.T) {
	a, out, _ := newTestApp(t)
	cfg := "defaults:\n  VAULT_NAMESPACE: shared\ncontexts:\n  dev:\n    VAULT_ADDR: http://v\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.run([]string{"ls"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "shared") {
		t.Errorf("namespace from defaults missing:\n%s", out)
	}
}

func TestAddressFlagRefused(t *testing.T) {
	a, _, call := newTestApp(t, "VCTX_VAULT_BIN=vault")
	for _, args := range [][]string{
		{"dev", "token", "lookup", "-address=http://other"},
		{"dev", "login", "-address", "http://other"},
		{"dev", "kv", "get", "--agent-address=http://other", "x"},
		{"exec", "dev", "--", "vault", "-address=http://other", "status"},
	} {
		*call = execCall{}
		if err := a.run(args); err == nil || !strings.Contains(err.Error(), "another server") || call.argv0 != "" {
			t.Errorf("%q: err %v, ran %v", args, err, call.argv0 != "")
		}
	}
	if got := addressFlag([]string{"kv", "put", "x", "--", "-address=literal"}); got != "" {
		t.Errorf("value after -- treated as a flag: %q", got)
	}
}

func TestAddrFromDefaults(t *testing.T) {
	a, out, _ := newTestApp(t)
	cfg := "defaults:\n  VAULT_ADDR: https://vault.example.com\ncontexts:\n  team-a:\n    VAULT_NAMESPACE: a\n  team-b:\n    VAULT_NAMESPACE: b\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.run([]string{"ls"}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "https://vault.example.com") != 2 {
		t.Errorf("ls:\n%s", out)
	}
}

func TestAddressFlagWithCustomVaultBin(t *testing.T) {
	a, _, call := newTestApp(t, "VCTX_VAULT_BIN=/opt/bin/vault-1.15")
	if err := a.run([]string{"exec", "dev", "--", "vault", "-address=http://evil"}); err == nil || call.argv0 != "" {
		t.Errorf("err %v, ran %v", err, call.argv0 != "")
	}
}

func TestUsageMessages(t *testing.T) {
	a, _, _ := newTestApp(t)
	var uerr usageError
	for _, args := range [][]string{{"check", "-x"}, {"ls", "x"}, {"current", "x"}} {
		if err := a.run(args); !errors.As(err, &uerr) {
			t.Errorf("%q: err = %v, want a usage error", args, err)
		}
	}
	err := a.run([]string{"nosuch"})
	if !errors.As(err, &uerr) || strings.HasPrefix(err.Error(), "usage:") {
		t.Errorf("unknown command: %v", err)
	}
}

func TestLogoutRemovedContext(t *testing.T) {
	a, _, _ := newTestApp(t, "VCTX_CONTEXT=gone", "VAULT_ADDR=http://v")
	a.stdin = strings.NewReader("tok")
	if err := a.run([]string{"store"}); err != nil {
		t.Fatal(err)
	}
	a.environ = withEnv(a.environ, "VCTX_CONTEXT=") // logout by name, not by this shell
	if err := a.run([]string{"logout", "gone"}); err != nil {
		t.Fatalf("logout of a context no longer in the config: %v", err)
	}
	if hasToken(t, a, "gone") {
		t.Error("token left")
	}
	if err := a.run([]string{"logout", "never"}); err == nil {
		t.Error("logout of an unknown context without a token succeeded")
	}
}

func TestUseHidesCredentials(t *testing.T) {
	a, _, _ := newTestApp(t)
	var stderr bytes.Buffer
	a.stderr = &stderr
	writeContexts(t, a, map[string]string{"cred": "http://user:s3cret@127.0.0.1:18200"})
	if err := a.run([]string{"use", "cred"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr.String(), "s3cret") {
		t.Errorf("use printed the password: %q", stderr.String())
	}
}

// -h anywhere on the line shows the command's help, even next to invalid arguments.
func TestHelpWinsOverEverything(t *testing.T) {
	for _, args := range [][]string{
		{"check", "-h"}, {"check", "--bogus", "-h"}, {"use", "a", "b", "--help"}, {"logout", "-h"},
		{"ls", "x", "-h"}, {"list", "-h"}, {"env", "--bogus", "-h"}, {"init", "-h"}, {"exec", "-h"},
		{"current", "-h"}, {"version", "-h"}, {"help", "check"},
	} {
		a, out, call := newTestApp(t)
		if err := a.run(args); err != nil {
			t.Errorf("%q: %v", args, err)
			continue
		}
		cmd := args[0]
		if cmd == "help" {
			cmd = args[1]
		}
		if cmd == "list" {
			cmd = "ls"
		}
		if !strings.HasPrefix(out.String(), "usage: vctx "+cmd) || call.argv0 != "" {
			t.Errorf("%q printed:\n%s", args, out)
		}
	}
}

func TestHelpAfterDashDashBelongsToCommand(t *testing.T) {
	a, out, call := newTestApp(t)
	if err := a.run([]string{"exec", "dev", "--", "sh", "-h"}); err != nil {
		t.Fatal(err)
	}
	if out.Len() > 0 || !slices.Equal(call.argv, []string{"sh", "-h"}) {
		t.Errorf("out %q, argv %q", out, call.argv)
	}
}

func TestEveryCommandHasHelp(t *testing.T) {
	for _, cmd := range commands {
		if strings.HasPrefix(cmd, "-") || cmd == "help" || cmd == "list" || token.IsHelperOp(cmd) {
			continue
		}
		if _, ok := commandHelp[cmd]; !ok {
			t.Errorf("no help for %s", cmd)
		}
	}
}

func TestTypoSuggestion(t *testing.T) {
	a, _, call := newTestApp(t)
	for args, want := range map[string]string{"chek": `did you mean "check"`, "prd": `did you mean "prod"`, "lst": `did you mean "ls"`} {
		err := a.run([]string{args})
		var uerr usageError
		if !errors.As(err, &uerr) || !strings.Contains(err.Error(), want) || call.argv0 != "" {
			t.Errorf("%s: %v", args, err)
		}
	}
	if err := a.run([]string{"zzzzzz"}); err == nil || strings.Contains(err.Error(), "did you mean") {
		t.Errorf("far word: %v", err)
	}
}

func TestLogoutSaysWhatItForgot(t *testing.T) {
	a, out, _ := newTestApp(t)
	var stderr bytes.Buffer
	a.stderr = &stderr
	helperRunner(t, a, out)("store", "tok", "VCTX_CONTEXT=dev")
	a.environ = withEnv(a.environ, "VCTX_CONTEXT=")
	for _, want := range []string{"forgot the token of dev\n", "no token of dev stored\n"} {
		stderr.Reset()
		if err := a.run([]string{"logout", "dev"}); err != nil {
			t.Fatal(err)
		}
		if stderr.String() != want {
			t.Errorf("stderr %q, want %q", stderr.String(), want)
		}
	}
}

func TestListJSON(t *testing.T) {
	a, out, _ := newTestApp(t)
	if err := a.run([]string{"use", "prod"}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := a.run([]string{"ls", "--json"}); err != nil {
		t.Fatal(err)
	}
	var got []lsEntry
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	want := []lsEntry{
		{Name: "dev", Address: "http://127.0.0.1:8201", Token: "none"},
		{Name: "prod", Address: "https://vault.example.com", Namespace: "admin", Token: "none", Current: true},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v", got)
	}
}

func TestListHeaderOnlyOnTerminal(t *testing.T) {
	a, out, _ := newTestApp(t)
	if err := a.run([]string{"ls"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "CONTEXT") {
		t.Errorf("header in piped output:\n%s", out)
	}
	out.Reset()
	a.stdoutTTY = true
	if err := a.run([]string{"ls"}); err != nil {
		t.Fatal(err)
	}
	if first, _, _ := strings.Cut(out.String(), "\n"); !strings.Contains(first, "CONTEXT") {
		t.Errorf("no header on a terminal:\n%s", out)
	}
}

func TestInitWithoutShell(t *testing.T) {
	a, _, _ := newTestApp(t, "SHELL=")
	err := a.run([]string{"init"})
	var uerr usageError
	if !errors.As(err, &uerr) || !strings.Contains(err.Error(), "--shell") {
		t.Errorf("err = %v", err)
	}
}

// The variables vault runs with bind tokens to the context: a login through
// vctx lands under the context's name and shows as ok.
func TestContextBindingEndToEnd(t *testing.T) {
	a, out, call := newTestApp(t)
	cfg := "contexts:\n  dev:\n    VAULT_ADDR: http://127.0.0.1:8201/\n    VAULT_NAMESPACE: admin\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.run([]string{"dev", "login"}); err != nil {
		t.Fatal(err)
	}
	for _, kv := range []string{"VCTX_CONTEXT_ADDR=http://127.0.0.1:8201", "VCTX_CONTEXT_NAMESPACE=admin"} {
		if !slices.Contains(call.env, kv) {
			t.Errorf("vault env lacks %s", kv)
		}
	}
	a.environ = call.env // what the token helper sees when vault runs it
	helperRunner(t, a, out)("store", "tok")
	if got, err := a.tokenStatus(loadTestConfig(t, a), []string{"dev"}); err != nil || got["dev"] != token.OK {
		t.Errorf("status after login = %v, %v", got, err)
	}

	out.Reset()
	if err := a.run([]string{"env", "--clear"}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"VCTX_CONTEXT_ADDR", "VCTX_CONTEXT_NAMESPACE"} {
		if !strings.Contains(out.String(), "unset "+k+"\n") {
			t.Errorf("--clear keeps %s:\n%s", k, out)
		}
	}
}

func TestLogoutInContextShellForgetsVaultsToken(t *testing.T) {
	a, out, _ := newTestApp(t)
	helper := helperRunner(t, a, out)
	ctx := []string{"VCTX_CONTEXT=dev", "VCTX_CONTEXT_ADDR=http://127.0.0.1:8201"}
	helper("store", "dev-token", append(ctx, "VAULT_ADDR=http://127.0.0.1:8201")...)
	helper("store", "other-token", append(ctx, "VAULT_ADDR=http://other")...)

	a.environ = withEnv(a.environ, append(ctx, "VAULT_ADDR=http://other")...)
	if err := a.run([]string{"logout"}); err != nil {
		t.Fatal(err)
	}
	if got := helper("get", "", append(ctx, "VAULT_ADDR=http://other")...); got != "" {
		t.Errorf("token vault uses is still there: %q", got)
	}
	if got := helper("get", "", append(ctx, "VAULT_ADDR=http://127.0.0.1:8201")...); got != "dev-token" {
		t.Errorf("context token = %q", got)
	}
}
