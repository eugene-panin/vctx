package environ

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eugene-panin/vctx/internal/config"
)

func TestQuote(t *testing.T) {
	if got, want := ShellQuote(`it's $HOME`), `'it'\''s $HOME'`; got != want {
		t.Errorf("ShellQuote = %s, want %s", got, want)
	}
	if got, want := FishQuote(`it's \ here`), `'it\'s \\ here'`; got != want {
		t.Errorf("FishQuote = %s, want %s", got, want)
	}
}

func TestValueFirstWins(t *testing.T) {
	if got := Value([]string{"A=1", "A=2"}, "A"); got != "1" {
		t.Errorf("got %q", got)
	}
}

func TestLookPathUsesContextPath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "vault")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := LookPath("vault", []string{"PATH=relative:" + dir}); err != nil || got != bin {
		t.Errorf("got %q, %v", got, err)
	}
	if _, err := LookPath("vault", []string{"PATH=relative"}); err == nil {
		t.Error("relative PATH entry used")
	}
}

func TestSwitchRestoresOwnValues(t *testing.T) {
	cfg := &config.Config{Contexts: map[string]map[string]string{
		"a": {"VAULT_ADDR": "https://a", "PATH": "/opt/a/bin:/usr/bin", "HTTPS_PROXY": "http://proxy-a"},
		"b": {"VAULT_ADDR": "https://b"},
	}}
	user := []string{"PATH=/usr/bin", "HTTPS_PROXY=http://mine", "HOME=/home/u"}
	switchTo := func(osEnv []string, name string) []string {
		t.Helper()
		vars, err := ContextVars(cfg, name, "/home/u")
		if err != nil {
			t.Fatal(err)
		}
		return Apply(osEnv, vars)
	}

	inA := switchTo(user, "a")
	if Value(inA, "PATH") != "/opt/a/bin:/usr/bin" || Value(inA, "VCTX_SAVED_PATH") != "/usr/bin" {
		t.Errorf("in a: %q", inA)
	}
	// Re-applying a must not save a's own value as the user's.
	if again := switchTo(inA, "a"); Value(again, "VCTX_SAVED_PATH") != "/usr/bin" {
		t.Errorf("a again: %q", again)
	}
	inB := switchTo(inA, "b")
	if Value(inB, "PATH") != "/usr/bin" || Value(inB, "HTTPS_PROXY") != "http://mine" {
		t.Errorf("in b: %q", inB)
	}
	for _, kv := range inB {
		if strings.HasPrefix(kv, "VCTX_SAVED_") {
			t.Errorf("saved value left behind: %s", kv)
		}
	}

	var sh bytes.Buffer
	WritePOSIX(&sh, inA, nil)
	if !strings.Contains(sh.String(), "export PATH='/usr/bin'\n") || strings.Contains(sh.String(), "unset PATH") {
		t.Errorf("clear from a:\n%s", sh.String())
	}
}

func TestClearIgnoresForgedSavedVault(t *testing.T) {
	var sh bytes.Buffer
	WritePOSIX(&sh, []string{"VCTX_VARS=VAULT_ADDR", "VCTX_SAVED_VAULT_ADDR=http://evil", "VAULT_ADDR=http://real"}, nil)
	if strings.Contains(sh.String(), "export VAULT_ADDR") || !strings.Contains(sh.String(), "unset VAULT_ADDR") {
		t.Errorf("output:\n%s", sh.String())
	}
}

func TestShellOutputSkipsUnsafeNames(t *testing.T) {
	var sh bytes.Buffer
	WritePOSIX(&sh, []string{"VAULT_x;echo pwned=1", "VCTX_VARS=a;id OK_NAME"}, nil)
	if strings.Contains(sh.String(), ";") {
		t.Errorf("unsafe name reached eval output:\n%s", sh.String())
	}
	if !strings.Contains(sh.String(), "unset OK_NAME\n") {
		t.Errorf("valid name dropped:\n%s", sh.String())
	}
}
