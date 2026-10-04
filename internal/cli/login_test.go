package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/eugene-panin/vctx/internal/vaulttest"
)

// writeFakeVault writes a vault stand-in that logs its arguments and has no token.
func writeFakeVault(t *testing.T) (bin, log string) {
	t.Helper()
	dir := t.TempDir()
	bin, log = filepath.Join(dir, "vault"), filepath.Join(dir, "calls")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho \"$*\" >> \""+log+"\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, log
}

func TestUseLogsIn(t *testing.T) {
	bin, log := writeFakeVault(t)
	a, _, _ := newTestApp(t, "VCTX_VAULT_BIN="+bin)
	cfg := "contexts:\n  dev:\n    VAULT_ADDR: " + vaulttest.Serve(t, vaulttest.Handler(200, vaulttest.ActiveBody)) + "\n    login: -method=userpass username=me\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	a.stderr, a.stdinTTY, a.stderrTTY = &stderr, true, true
	if err := a.run([]string{"use", "dev"}); err != nil {
		t.Fatal(err)
	}
	if calls, _ := os.ReadFile(log); !strings.Contains(string(calls), "login -no-print -method=userpass username=me") {
		t.Errorf("calls:\n%s\nstderr:\n%s", calls, stderr.String())
	}
}

func TestUseRejectsBadTimeout(t *testing.T) {
	a, _, _ := newTestApp(t, "VCTX_CHECK_TIMEOUT=soon")
	if err := a.run([]string{"use", "dev"}); err == nil || !strings.Contains(err.Error(), "VCTX_CHECK_TIMEOUT") {
		t.Errorf("err = %v", err)
	}
}

func TestBackendLoginMethodFromConfig(t *testing.T) {
	a, _, _ := newTestApp(t)
	cfg := "contexts:\n  dev:\n    VAULT_ADDR: http://v\n    login: -method=oidc -path=sso\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	b := uiBackend{a, loadTestConfig(t, a), a.loginRunner(0)}
	if got := b.LoginMethod("dev"); !slices.Equal(got, []string{"-method=oidc", "-path=sso"}) {
		t.Errorf("login method = %q", got)
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
