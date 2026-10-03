package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
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
		environ:    append([]string{"PATH=" + os.Getenv("PATH"), "VCTX_VAULT_BIN=/bin/sh", "VCTX_CHECK_TIMEOUT=0", "VCTX_TOKEN_STORE=file"}, environ...),
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
	for _, self := range []string{"/Users/me/My Tools/vctx", "/opt/{a,b}/vctx", "/tmp/$(id)/vctx"} {
		a, _, _ := newTestApp(t)
		a.self = self
		if err := a.run([]string{"dev", "status"}); err == nil {
			t.Errorf("%s accepted as token helper path", self)
		}
		// Probing needs no token helper.
		if err := a.run([]string{"check", "dev"}); err != nil && strings.Contains(err.Error(), "token helper") {
			t.Errorf("%s: check needs the helper: %v", self, err)
		}
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
	out.Reset()
	a.environ = append(slices.Clip(base), "VCTX_CONTEXT=dev", "VAULT_ADDR=https://evil.example.com")
	if err := a.run([]string{"get"}); err == nil || out.Len() > 0 {
		t.Errorf("token handed to another address: err %v, out %q", err, out)
	}

	// An empty token written by an earlier version must not come back as the address.
	if err := os.WriteFile(a.tokenPath("stale"), []byte("https://vault.example.com\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := helper("get", "", "VCTX_CONTEXT=stale", "VAULT_ADDR=https://vault.example.com"); got != "" {
		t.Errorf("address returned as token: %q", got)
	}

	helper("store", "\n", "VCTX_CONTEXT=dev", "VAULT_ADDR=https://vault.example.com")
	if got := helper("get", "", "VCTX_CONTEXT=dev", "VAULT_ADDR=https://vault.example.com"); got != "" {
		t.Errorf("empty store left %q", got)
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

func TestShellEnvSkipsUnsafeNames(t *testing.T) {
	a, out, _ := newTestApp(t, "VAULT_x;echo pwned=1", "VCTX_VARS=a;id OK_NAME")
	if err := a.run([]string{"env", "--clear"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), ";") {
		t.Errorf("unsafe name reached eval output:\n%s", out)
	}
	if !strings.Contains(out.String(), "unset OK_NAME\n") {
		t.Errorf("valid name dropped:\n%s", out)
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

func TestAddrKeysNeverCollide(t *testing.T) {
	a, _, _ := newTestApp(t, "VAULT_ADDR=https://vault.example.com")
	if key := a.tokenKey(); nameRe.MatchString(strings.SplitN(key, "/", 2)[0]) {
		t.Errorf("address key %q can collide with a context name", key)
	}
}

func TestCallerAddrPrefersAgent(t *testing.T) {
	a, _, _ := newTestApp(t, "VAULT_ADDR=https://vault:8200/", "VAULT_AGENT_ADDR=http://127.0.0.1:8100/")
	if got := a.callerAddr(); got != "http://127.0.0.1:8100" {
		t.Errorf("callerAddr = %q", got)
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
	var usage usageError
	for _, args := range [][]string{{"exec"}, {"use", "a", "b"}, {"env", "a", "b"}, {"logout", "a", "b"}} {
		if err := a.run(args); !errors.As(err, &usage) {
			t.Errorf("%q: err = %v, want a usage error", args, err)
		}
	}
}

func TestLookPathUsesContextPath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "vault")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := lookPath("vault", []string{"PATH=relative:" + dir}); err != nil || got != bin {
		t.Errorf("got %q, %v", got, err)
	}
	if _, err := lookPath("vault", []string{"PATH=relative"}); err == nil {
		t.Error("relative PATH entry used")
	}
}

func TestCheckPrivateOwner(t *testing.T) {
	fi := fakeInfo{mode: 0o600, sys: &syscall.Stat_t{Uid: uint32(os.Getuid() + 1)}}
	if err := checkPrivate("cfg", fi); err == nil || !strings.Contains(err.Error(), "another user") {
		t.Errorf("err = %v", err)
	}
}

type fakeInfo struct {
	mode os.FileMode
	sys  any
}

func (f fakeInfo) Name() string       { return "f" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any           { return f.sys }

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
