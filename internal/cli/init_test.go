package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvDefaultIgnoresShellContext(t *testing.T) {
	a, out, _ := newTestApp(t, "VCTX_CONTEXT=prod")
	if err := a.run([]string{"use", "dev"}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := a.run([]string{"env", "--default"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "export VCTX_CONTEXT='dev'") {
		t.Errorf("output:\n%s", out)
	}
}

func TestFishEnv(t *testing.T) {
	a, out, _ := newTestApp(t, "VAULT_TOKEN=x")
	if err := a.run([]string{"env", "prod", "--shell", "fish"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"set -e VAULT_TOKEN\n", "set -gx VAULT_ADDR 'https://vault.example.com'\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

func TestUseUnderIntegrationIsQuiet(t *testing.T) {
	choice := filepath.Join(t.TempDir(), "choice")
	if err := os.WriteFile(choice, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	a, _, _ := newTestApp(t, "VCTX_CONTEXT=prod", "VCTX_CHOICE_FILE="+choice)
	var stderr strings.Builder
	a.stderr = &stderr
	if err := a.run([]string{"use", "dev"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr.String(), "precedence") {
		t.Errorf("override note under the integration: %q", stderr.String())
	}
	if b, _ := os.ReadFile(choice); string(b) != "dev" {
		t.Errorf("choice file = %q, want dev", b)
	}
}
