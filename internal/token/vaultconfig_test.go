package token

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegisterHelper(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	vars := map[string]string{}
	if err := RegisterHelper(vars, dir, "/usr/local/bin/vctx"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(vars["VAULT_CONFIG_PATH"])
	if err != nil || string(b) != "token_helper = \"/usr/local/bin/vctx\"\n" {
		t.Errorf("vault config = %q, %v", b, err)
	}

	own := map[string]string{"VAULT_CONFIG_PATH": "/etc/vault.hcl"}
	if err := RegisterHelper(own, dir, "/usr/local/bin/vctx"); err != nil || own["VAULT_CONFIG_PATH"] != "/etc/vault.hcl" {
		t.Errorf("own config replaced: %v, %v", own, err)
	}
}

func TestRegisterHelperRejectsUnsafePath(t *testing.T) {
	for _, self := range []string{"/Users/me/My Tools/vctx", "/opt/{a,b}/vctx", "/tmp/$(id)/vctx"} {
		if err := RegisterHelper(map[string]string{}, t.TempDir(), self); err == nil || !strings.Contains(err.Error(), "token helper") {
			t.Errorf("%s accepted as token helper path: %v", self, err)
		}
	}
}

func TestRegisterHelperNeedsPrivateStateDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := RegisterHelper(map[string]string{}, dir, "/usr/local/bin/vctx"); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("world-writable state dir: %v", err)
	}
}
