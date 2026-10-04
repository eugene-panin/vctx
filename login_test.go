package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestLoginArgs(t *testing.T) {
	for in, want := range map[string][]string{
		"":                                      nil,
		"-method=userpass username=me":          {"-method=userpass", "username=me"},
		`-method=oidc role="dev team"`:          {"-method=oidc", "role=dev team"},
		"-method=ldap   -path=corp  username=x": {"-method=ldap", "-path=corp", "username=x"},
	} {
		got, err := loginArgs(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"hvs.CAESIJ", "-method=userpass password=x", "token=hvs.x", "-address=http://evil", `role="open`} {
		if _, err := loginArgs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestLoginInConfig(t *testing.T) {
	a, _, _ := newTestApp(t)
	cfg := "defaults:\n  login: -method=oidc\ncontexts:\n  dev:\n    VAULT_ADDR: http://v\n  ops:\n    VAULT_ADDR: http://o\n    login: -method=userpass username=ops\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c := loadTestConfig(t, a)
	if got := c.login("dev"); !slices.Equal(got, []string{"-method=oidc"}) {
		t.Errorf("dev inherits defaults: %q", got)
	}
	if got := c.login("ops"); !slices.Equal(got, []string{"-method=userpass", "username=ops"}) {
		t.Errorf("ops: %q", got)
	}
	vars, _ := c.vars("ops", a.home)
	if _, ok := vars["login"]; ok {
		t.Error("login leaked into the environment")
	}

	if err := os.WriteFile(a.configPath, []byte("contexts:\n  dev:\n    VAULT_ADDR: http://v\n    login: -method=userpass password=hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.loadConfig(); err == nil || !strings.Contains(err.Error(), "secret") {
		t.Errorf("password in config: %v", err)
	}
}

// fakeVault writes a vault stand-in that logs its arguments, answers
// `token lookup` as lookup says (ok, denied or down), and fails `login`
// when lookup is "loginfails".
func fakeVault(t *testing.T, lookup string) (bin, log string) {
	t.Helper()
	return fakeVaultPrinting(t, lookup, "")
}

// fakeVaultPrinting is fakeVault whose `vault print token` prints printed.
func fakeVaultPrinting(t *testing.T, lookup, printed string) (bin, log string) {
	t.Helper()
	dir := t.TempDir()
	bin, log = filepath.Join(dir, "vault"), filepath.Join(dir, "calls")
	script := `#!/bin/sh
echo "$*" >> "` + log + `"
if [ "$1 $2" = "token lookup" ]; then
  case "` + lookup + `" in
    ok) exit 0 ;;
    denied) printf 'Code: 403. Errors:\n* 2 errors occurred:\n\t* permission denied\n\t* invalid token\n'; exit 2 ;;
    nolookup) printf 'Code: 403. Errors:\n* 1 error occurred:\n\t* permission denied\n'; exit 2 ;;
    *) echo "Error looking up token: dial tcp: connection refused"; exit 2 ;;
  esac
fi
if [ "$1" = login ] && [ "` + lookup + `" = loginfails ]; then exit 2; fi
if [ "$1 $2" = "print token" ]; then echo "` + printed + `"; fi
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, log
}

func TestEnsureLogin(t *testing.T) {
	devAddr := serve(t, vaultHandler(200, activeBody))
	cfg := "contexts:\n  dev:\n    VAULT_ADDR: " + devAddr + "\n    login: -method=userpass username=me\n  bare:\n    VAULT_ADDR: " + serve(t, vaultHandler(200, activeBody)) + "\n"
	tests := []struct {
		name, context, lookup string
		stored, tty           bool
		answers               string
		wantLogin, wantInErr  string
		wantRemembered        bool
	}{
		{"no token", "dev", "ok", false, true, "", "login -no-print -method=userpass username=me", "", false},
		{"working token", "dev", "ok", true, true, "", "", "", false},
		{"expired token", "dev", "denied", true, true, "", "login -no-print -method=userpass username=me", "", false},
		{"vault cannot tell", "dev", "down", true, true, "", "", "check token", false},
		{"token without lookup right works", "dev", "nolookup", true, true, "", "", "", false},
		{"asks the method", "bare", "ok", false, true, "1\n\nwoodman\n", "login -no-print -method=userpass username=woodman", "", true},
		{"asks oidc with a path", "bare", "ok", false, true, "3\nsso\n\n", "login -no-print -method=oidc -path=sso", "", true},
		{"failed login not remembered", "bare", "loginfails", false, true, "2\n\nme\n", "login -no-print -method=ldap username=me", "login failed", false},
		{"script", "dev", "ok", false, false, "", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bin, log := fakeVault(t, tc.lookup)
			a, out, _ := newTestApp(t, "VCTX_VAULT_BIN="+bin)
			if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.stored {
				helperRunner(t, a, out)("store", "tok", "VCTX_CONTEXT=dev", "VAULT_ADDR="+devAddr)
			}
			var stderr bytes.Buffer
			a.stderr, a.stdinTTY, a.stderrTTY = &stderr, tc.tty, tc.tty
			a.stdin = strings.NewReader(tc.answers)
			a.ensureLogin(context.Background(), loadTestConfig(t, a), tc.context)

			calls, _ := os.ReadFile(log)
			gotLogin := ""
			for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
				if strings.HasPrefix(line, "login") {
					gotLogin = line
				}
			}
			if gotLogin != tc.wantLogin {
				t.Errorf("login call %q, want %q", gotLogin, tc.wantLogin)
			}
			if tc.wantInErr != "" && !strings.Contains(stderr.String(), tc.wantInErr) {
				t.Errorf("stderr %q, want %q", stderr.String(), tc.wantInErr)
			}
			_, err := os.Stat(a.rememberedLoginPath(tc.context))
			if remembered := err == nil; remembered != tc.wantRemembered {
				t.Errorf("remembered = %v, want %v", remembered, tc.wantRemembered)
			}
		})
	}
}

func TestDetailShowsLogin(t *testing.T) {
	a, _, _ := newTestApp(t)
	cfg := "contexts:\n  dev:\n    VAULT_ADDR: http://v\n    login: -method=oidc -path=sso\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := newModel(a, loadTestConfig(t, a))
	if err != nil {
		t.Fatal(err)
	}
	m.Update(tea.WindowSizeMsg{Width: 150, Height: 30})
	if view := m.View(); !strings.Contains(view, "-method=oidc -path=sso") {
		t.Errorf("details:\n%s", view)
	}
}

func TestRememberedLoginUsedNextTime(t *testing.T) {
	bin, log := fakeVault(t, "denied")
	a, _, _ := newTestApp(t, "VCTX_VAULT_BIN="+bin)
	writeContexts(t, a, map[string]string{"dev": serve(t, vaultHandler(200, activeBody))})
	if err := a.rememberLogin("dev", []string{"-method=ldap", "username=me"}); err != nil {
		t.Fatal(err)
	}
	cfg := loadTestConfig(t, a)
	if got := a.loginFor(cfg, "dev"); !slices.Equal(got, []string{"-method=ldap", "username=me"}) {
		t.Errorf("loginFor = %q", got)
	}
	var stderr bytes.Buffer
	a.stderr, a.stdinTTY, a.stderrTTY = &stderr, true, true
	a.stdin = strings.NewReader("") // nothing to answer: no questions expected
	a.ensureLogin(context.Background(), cfg, "dev")
	if calls, _ := os.ReadFile(log); !strings.Contains(string(calls), "login -no-print -method=ldap username=me") {
		t.Errorf("calls:\n%s\nstderr:\n%s", calls, stderr.String())
	}
}

func TestLoginFromUI(t *testing.T) {
	bin, log := fakeVault(t, "ok")
	a, _, _ := newTestApp(t, "VCTX_VAULT_BIN="+bin)
	var out bytes.Buffer
	l := &loginExec{a: a, cfg: loadTestConfig(t, a), name: "dev"}
	l.SetStdin(strings.NewReader("4\n"))
	l.SetStdout(&out)
	l.SetStderr(&out)
	if err := l.Run(); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if calls, _ := os.ReadFile(log); !strings.Contains(string(calls), "login -no-print -method=token") {
		t.Errorf("calls:\n%s", calls)
	}
}

func TestNoLoginAgainstUnusableServer(t *testing.T) {
	bin, log := fakeVault(t, "ok")
	sealed := `{"initialized":true,"sealed":true,"version":"1.20.4"}`
	for name, addr := range map[string]string{"sealed": serve(t, vaultHandler(503, sealed)), "down": closedURL(t)} {
		a, _, _ := newTestApp(t, "VCTX_VAULT_BIN="+bin)
		writeContexts(t, a, map[string]string{"x": addr})
		var stderr bytes.Buffer
		a.stderr, a.stdinTTY, a.stderrTTY = &stderr, true, true
		a.ensureLogin(context.Background(), loadTestConfig(t, a), "x")
		if calls, _ := os.ReadFile(log); strings.Contains(string(calls), "login") {
			t.Errorf("%s: logged in anyway: %s", name, calls)
		}
		if !strings.Contains(stderr.String(), "not logging in") {
			t.Errorf("%s: stderr %q", name, stderr.String())
		}
	}
}

func TestExternalTokenNeverLogsIn(t *testing.T) {
	bin, log := fakeVault(t, "denied")
	a, _, _ := newTestApp(t, "VCTX_VAULT_BIN="+bin)
	addr := serve(t, vaultHandler(200, activeBody))
	cfg := "contexts:\n  x:\n    VAULT_ADDR: " + addr + "\n    VAULT_TOKEN: hvs.fromconfig\n    login: -method=userpass username=me\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	a.stderr, a.stdinTTY, a.stderrTTY = &stderr, true, true
	a.ensureLogin(context.Background(), loadTestConfig(t, a), "x")
	if calls, _ := os.ReadFile(log); strings.Contains(string(calls), "login") {
		t.Errorf("logged in although vault uses VAULT_TOKEN: %s", calls)
	}
	if !strings.Contains(stderr.String(), "refuses the token") {
		t.Errorf("stderr %q", stderr.String())
	}
}

func TestLoginArgsWhitelist(t *testing.T) {
	for in, want := range map[string][]string{
		"-method oidc -path sso":           {"-method=oidc", "-path=sso"},
		"-method=userpass\nusername=me":    {"-method=userpass", "username=me"},
		"--method=ldap username=me role=x": {"-method=ldap", "username=me", "role=x"},
		"-method=kerberos keytab_path=/etc/krb5.keytab krb5conf_path=/etc/krb5.conf": {
			"-method=kerberos", "keytab_path=/etc/krb5.keytab", "krb5conf_path=/etc/krb5.conf",
		},
	} {
		got, err := loginArgs(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{
		"-no-print=false", "-header=X-Vault-Token=hvs.x", "-mfa=123", "-output-curl-string", "-namespace=other",
		"aws_secret_access_key=x", "security_token=x", "secret_key=x", "username=me -path=sso", "-method",
	} {
		if _, err := loginArgs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestVaultError(t *testing.T) {
	out := "Error looking up token: Error making API request.\n\nURL: GET http://v/v1/auth/token/lookup-self\nCode: 503. Errors:\n\n* Vault is sealed\n"
	if got := vaultError(out); got != "Code: 503. Vault is sealed" {
		t.Errorf("got %q", got)
	}
	nested := "Code: 403. Errors:\n\n* 2 errors occurred:\n\t* permission denied\n\t* invalid token\n"
	if got := vaultError(nested); got != "Code: 403. permission denied" {
		t.Errorf("nested: %q", got)
	}
}

func TestCancelAtPrompt(t *testing.T) {
	bin, log := fakeVault(t, "ok")
	a, _, _ := newTestApp(t, "VCTX_VAULT_BIN="+bin)
	writeContexts(t, a, map[string]string{"x": serve(t, vaultHandler(200, activeBody))})
	r, w, err := os.Pipe() // a real file, as the terminal is: Ctrl-C must interrupt the read
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	var stderr syncBuffer
	a.stdin, a.stderr, a.stdinTTY, a.stderrTTY = r, &stderr, true, true

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		a.ensureLogin(ctx, loadTestConfig(t, a), "x")
		close(done)
	}()
	for !strings.Contains(stderr.String(), "method [1]") {
		select {
		case <-done:
			t.Fatalf("no question asked:\n%s", stderr.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel() // what Ctrl-C does through interruptible
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the question did not give up on Ctrl-C")
	}
	if !strings.Contains(stderr.String(), "login cancelled") {
		t.Errorf("stderr %q", stderr.String())
	}
	if calls, _ := os.ReadFile(log); strings.Contains(string(calls), "login") {
		t.Errorf("logged in after Ctrl-C: %s", calls)
	}
}

func TestOwnTokenHelperContext(t *testing.T) {
	addr := serve(t, vaultHandler(200, activeBody))
	cfg := "contexts:\n  x:\n    VAULT_ADDR: " + addr + "\n    VAULT_CONFIG_PATH: /etc/vault-cli.hcl\n    login: -method=userpass username=me\n"
	for _, tc := range []struct {
		name, lookup, printed string
		wantLogin             bool
	}{
		{"no token there", "ok", "", true},
		{"working token", "ok", "hvs.x", false},
		{"expired token", "denied", "hvs.x", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin, log := fakeVaultPrinting(t, tc.lookup, tc.printed)
			a, _, _ := newTestApp(t, "VCTX_VAULT_BIN="+bin)
			if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			a.stderr, a.stdinTTY, a.stderrTTY = &bytes.Buffer{}, true, true
			a.ensureLogin(context.Background(), loadTestConfig(t, a), "x")
			calls, _ := os.ReadFile(log)
			if got := strings.Contains(string(calls), "login -no-print"); got != tc.wantLogin {
				t.Errorf("login = %v, want %v; calls:\n%s", got, tc.wantLogin, calls)
			}
		})
	}
}

func TestAgentContextNeverLogsIn(t *testing.T) {
	bin, log := fakeVault(t, "denied")
	a, _, _ := newTestApp(t, "VCTX_VAULT_BIN="+bin)
	addr := serve(t, vaultHandler(200, activeBody))
	cfg := "contexts:\n  x:\n    VAULT_AGENT_ADDR: " + addr + "\n    login: -method=userpass username=me\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	a.stderr, a.stdinTTY, a.stderrTTY = &bytes.Buffer{}, true, true
	a.ensureLogin(context.Background(), loadTestConfig(t, a), "x")
	if calls, _ := os.ReadFile(log); len(calls) > 0 {
		t.Errorf("vault called for an agent context: %s", calls)
	}
}

func TestFailedLoginOffersAnotherMethod(t *testing.T) {
	bin, log := fakeVault(t, "loginfails")
	a, _, _ := newTestApp(t, "VCTX_VAULT_BIN="+bin)
	writeContexts(t, a, map[string]string{"x": serve(t, vaultHandler(200, activeBody))})
	if err := a.rememberLogin("x", []string{"-method=ldap", "username=me"}); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	a.stderr, a.stdinTTY, a.stderrTTY = &stderr, true, true
	a.stdin = strings.NewReader("y\n1\n\nme\nn\n") // pick userpass, then give up
	a.ensureLogin(context.Background(), loadTestConfig(t, a), "x")
	calls, _ := os.ReadFile(log)
	if !strings.Contains(string(calls), "-method=ldap") || !strings.Contains(string(calls), "-method=userpass") {
		t.Errorf("calls:\n%s\nstderr:\n%s", calls, stderr.String())
	}
	if got := a.rememberedLogin("x"); !slices.Equal(got, []string{"-method=ldap", "username=me"}) {
		t.Errorf("remembered after failures = %q, want unchanged", got)
	}
}

func TestLoginFromUIWaitsAfterFailure(t *testing.T) {
	bin, _ := fakeVault(t, "loginfails")
	a, _, _ := newTestApp(t, "VCTX_VAULT_BIN="+bin)
	writeContexts(t, a, map[string]string{"x": serve(t, vaultHandler(200, activeBody))})
	var out bytes.Buffer
	l := &loginExec{a: a, cfg: loadTestConfig(t, a), name: "x"}
	l.SetStdin(strings.NewReader("4\nn\n\n")) // token, no other method, Enter
	l.SetStdout(&out)
	if err := l.Run(); err == nil {
		t.Fatal("failed login reported as success")
	}
	if !strings.Contains(out.String(), "press Enter to return") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestEmptyConfigPathUsesVctxHelper(t *testing.T) {
	a, out, _ := newTestApp(t)
	cfg := "defaults:\n  VAULT_CONFIG_PATH: /etc/x.hcl\ncontexts:\n  x:\n    VAULT_ADDR: http://v\n    VAULT_CONFIG_PATH: \"\"\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.run([]string{"env", "x"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "VAULT_CONFIG_PATH='"+filepath.Join(a.stateDir, "vault.hcl")+"'") {
		t.Errorf("output:\n%s", out.String())
	}
}

// syncBuffer is a bytes.Buffer safe to read while another goroutine writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
