package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func load(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name, yaml, want string
	}{
		{"empty", "", "no contexts"},
		{"no addr", "contexts:\n  dev:\n    VAULT_NAMESPACE: x\n", "VAULT_ADDR or VAULT_AGENT_ADDR is required"},
		{"bad name", "contexts:\n  ../x:\n    VAULT_ADDR: x\n", "invalid context name"},
		{"names differ in case", "contexts:\n  Team:\n    VAULT_ADDR: http://a\n  team:\n    VAULT_ADDR: http://b\n", "differ only in case"},
		{"bad key", "contexts:\n  dev:\n    VAULT_ADDR: x\n    BAD-KEY: y\n", "invalid variable name"},
		{"reserved key", "defaults:\n  VCTX_CONTEXT: x\ncontexts:\n  dev:\n    VAULT_ADDR: x\n", "reserved"},
		{"unknown field", "contex:\n  dev:\n    VAULT_ADDR: x\n", "not found"},
		{"secret in login", "contexts:\n  dev:\n    VAULT_ADDR: http://v\n    login: -method=userpass password=hunter2\n", "secret"},
		{"too large", "contexts:\n  dev:\n    VAULT_ADDR: http://v\n#" + strings.Repeat("x", 1<<20) + "\n", "larger than"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := load(t, tc.yaml); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadRefusesWritableFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte("contexts:\n  dev:\n    VAULT_ADDR: http://v\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("err = %v", err)
	}
}

func TestVarsAndLogin(t *testing.T) {
	c, err := load(t, "defaults:\n  login: -method=oidc\n  VAULT_CACERT: ~/ca.pem\ncontexts:\n  dev:\n    VAULT_ADDR: http://v\n  ops:\n    VAULT_ADDR: http://o\n    login: -method=userpass username=ops\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Login("dev"); !slices.Equal(got, []string{"-method=oidc"}) {
		t.Errorf("dev inherits defaults: %q", got)
	}
	if got := c.Login("ops"); !slices.Equal(got, []string{"-method=userpass", "username=ops"}) {
		t.Errorf("ops: %q", got)
	}
	vars, err := c.Vars("ops", "/home/u")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := vars["login"]; ok {
		t.Error("login leaked into the environment")
	}
	if vars["VAULT_CACERT"] != "/home/u/ca.pem" || vars["VAULT_ADDR"] != "http://o" {
		t.Errorf("vars = %v", vars)
	}
	if _, err := c.Vars("nope", ""); err == nil {
		t.Error("unknown context accepted")
	}
}
