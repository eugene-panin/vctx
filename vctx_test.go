package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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
		environ:    append([]string{"PATH=" + os.Getenv("PATH"), "VCTX_VAULT_BIN=/bin/sh", "VCTX_CHECK_TIMEOUT=0"}, environ...),
		stdin:      strings.NewReader(""),
		stdout:     &out,
		stderr:     &bytes.Buffer{},
		exec: func(argv0 string, argv, env []string) error {
			*call = execCall{argv0, argv, env}
			return nil
		},
	}
	return a, &out, call
}

func TestLoadConfigErrors(t *testing.T) {
	tests := []struct {
		name, yaml, want string
	}{
		{"empty", "", "no contexts"},
		{"no addr", "contexts:\n  dev:\n    VAULT_NAMESPACE: x\n", "VAULT_ADDR is required"},
		{"reserved name", "contexts:\n  env:\n    VAULT_ADDR: x\n", "invalid context name"},
		{"bad name", "contexts:\n  ../x:\n    VAULT_ADDR: x\n", "invalid context name"},
		{"bad key", "contexts:\n  dev:\n    VAULT_ADDR: x\n    BAD-KEY: y\n", "invalid variable name"},
		{"reserved key", "defaults:\n  VCTX_CONTEXT: x\ncontexts:\n  dev:\n    VAULT_ADDR: x\n", "reserved"},
		{"unknown field", "contex:\n  dev:\n    VAULT_ADDR: x\n", "not found"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "c.yaml")
			if err := os.WriteFile(p, []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadConfig(p)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
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
	a.environ = append(a.environ, "VCTX_VARS=HTTPS_PROXY", "HTTPS_PROXY=p", "VCTX_CONTEXT=prod")
	if err := a.run([]string{"env", "--clear"}); err != nil {
		t.Fatal(err)
	}
	want := "unset HTTPS_PROXY\nunset VAULT_ADDR\nunset VAULT_TOKEN\nunset VCTX_CONTEXT\nunset VCTX_VARS\n"
	if out.String() != want {
		t.Errorf("clear output:\n%s\nwant:\n%s", out, want)
	}
}

func TestShellQuote(t *testing.T) {
	if got, want := shellQuote(`it's $HOME`), `'it'\''s $HOME'`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestTokenHelperIsolation(t *testing.T) {
	a, out, _ := newTestApp(t)
	base := a.environ

	helper := func(op, input string, env ...string) string {
		t.Helper()
		out.Reset()
		a.environ = append(slices.Clip(base), env...)
		a.stdin = strings.NewReader(input)
		if err := a.run([]string{op}); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}

	helper("store", "tok-dev\n", "VCTX_CONTEXT=dev")
	helper("store", "tok-prod", "VCTX_CONTEXT=prod")
	helper("store", "tok-raw", "VAULT_ADDR=http://raw:8200")

	if got := helper("get", "", "VCTX_CONTEXT=dev"); got != "tok-dev" {
		t.Errorf("dev token = %q", got)
	}
	if got := helper("get", "", "VCTX_CONTEXT=prod"); got != "tok-prod" {
		t.Errorf("prod token = %q", got)
	}
	if got := helper("get", "", "VAULT_ADDR=http://raw:8200"); got != "tok-raw" {
		t.Errorf("raw token = %q", got)
	}
	if got := helper("get", "", "VAULT_ADDR=http://raw:8200", "VAULT_NAMESPACE=ns"); got != "" {
		t.Errorf("namespaced token = %q, want none", got)
	}

	fi, err := os.Stat(a.tokenPath("dev"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %v, %v", fi.Mode(), err)
	}

	helper("erase", "", "VCTX_CONTEXT=dev")
	if got := helper("get", "", "VCTX_CONTEXT=dev"); got != "" {
		t.Errorf("dev token after erase = %q", got)
	}
	helper("erase", "", "VCTX_CONTEXT=dev")

	a.environ = base
	if err := a.run([]string{"logout", "prod"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a.tokenPath("prod")); !os.IsNotExist(err) {
		t.Errorf("prod token still present after logout: %v", err)
	}
}

func TestVaultConfigRejectsUnsafePath(t *testing.T) {
	a, _, _ := newTestApp(t)
	a.self = "/Users/me/My Tools/vctx"
	if err := a.run([]string{"dev", "status"}); err == nil {
		t.Fatal("expected error for helper path with a space")
	}
}

func TestTokenBoundToAddress(t *testing.T) {
	a, out, _ := newTestApp(t)
	base := a.environ
	helper := func(op, input string, env ...string) string {
		t.Helper()
		out.Reset()
		a.environ = append(slices.Clip(base), env...)
		a.stdin = strings.NewReader(input)
		if err := a.run([]string{op}); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}

	helper("store", "tok", "VCTX_CONTEXT=dev", "VAULT_ADDR=https://vault.example.com/")
	if got := helper("get", "", "VCTX_CONTEXT=dev", "VAULT_ADDR=https://vault.example.com"); got != "tok" {
		t.Errorf("same address: %q", got)
	}
	if got := helper("get", "", "VCTX_CONTEXT=dev", "VAULT_ADDR=https://evil.example.com"); got != "" {
		t.Errorf("token handed to another address: %q", got)
	}

	if err := os.WriteFile(a.tokenPath("prod"), []byte("legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := helper("get", "", "VCTX_CONTEXT=prod", "VAULT_ADDR=https://anything"); got != "legacy" {
		t.Errorf("legacy token file: %q", got)
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
	a.environ = append(a.environ, "VCTX_CONTEXT=../../victim")
	if err := a.run([]string{"logout"}); err == nil || !strings.Contains(err.Error(), "invalid context name") {
		t.Errorf("logout with bad $VCTX_CONTEXT: %v", err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("file outside the token directory was touched: %v", err)
	}
}

func TestIsTerminalDevNull(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Error("/dev/null detected as a terminal")
	}
}
