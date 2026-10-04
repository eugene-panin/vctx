package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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

// fakeVault writes a vault stand-in that logs its arguments and answers
// `token lookup` as lookup says: ok, denied or down.
func fakeVault(t *testing.T, lookup string) (bin, log string) {
	t.Helper()
	dir := t.TempDir()
	bin, log = filepath.Join(dir, "vault"), filepath.Join(dir, "calls")
	script := `#!/bin/sh
echo "$*" >> "` + log + `"
if [ "$1 $2" = "token lookup" ]; then
  case "` + lookup + `" in
    ok) exit 0 ;;
    denied) echo "Error looking up token: Code: 403. Errors: * permission denied"; exit 2 ;;
    *) echo "Error looking up token: dial tcp: connection refused"; exit 2 ;;
  esac
fi
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, log
}

func TestEnsureLogin(t *testing.T) {
	const cfg = "contexts:\n  dev:\n    VAULT_ADDR: http://127.0.0.1:8201\n    login: -method=userpass username=me\n  bare:\n    VAULT_ADDR: http://127.0.0.1:8202\n"
	tests := []struct {
		name, context, lookup string
		stored, tty           bool
		wantLogin, wantInErr  string
	}{
		{"no token", "dev", "ok", false, true, "login -no-print -method=userpass username=me", ""},
		{"working token", "dev", "ok", true, true, "", ""},
		{"expired token", "dev", "denied", true, true, "login -no-print -method=userpass username=me", ""},
		{"vault cannot tell", "dev", "down", true, true, "", "check token"},
		{"no method configured", "bare", "ok", false, true, "", "set `login:`"},
		{"script", "dev", "ok", false, false, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bin, log := fakeVault(t, tc.lookup)
			a, out, _ := newTestApp(t, "VCTX_VAULT_BIN="+bin)
			if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.stored {
				helperRunner(t, a, out)("store", "tok", "VCTX_CONTEXT=dev", "VAULT_ADDR=http://127.0.0.1:8201")
			}
			var stderr bytes.Buffer
			a.stderr, a.stdinTTY, a.stderrTTY = &stderr, tc.tty, tc.tty
			a.ensureLogin(loadTestConfig(t, a), tc.context)

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
