package token

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helperRunner returns a function that runs a token helper operation the way
// vault does, with env and input on stdin, against a file store in dir. It
// returns what the helper printed.
func helperRunner(t *testing.T) (run func(op, input string, env ...string) string, dir string) {
	t.Helper()
	s, dir := openStore(t, "file", nil)
	return func(op, input string, env ...string) string {
		t.Helper()
		var out strings.Builder
		if err := Helper(op, env, s, strings.NewReader(input), &out); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		return out.String()
	}, dir
}

func TestHelperIsolation(t *testing.T) {
	helper, dir := helperRunner(t)
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

	helper("erase", "", "VCTX_CONTEXT=dev")
	if got := helper("get", "", "VCTX_CONTEXT=dev"); got != "" {
		t.Errorf("dev token after erase = %q", got)
	}
	helper("erase", "", "VCTX_CONTEXT=dev")
	if _, err := os.Stat(filepath.Join(dir, "tokens", "prod")); err != nil {
		t.Errorf("erasing dev touched prod: %v", err)
	}
}

func TestHelperBindsTokenToAddress(t *testing.T) {
	helper, dir := helperRunner(t)
	helper("store", "tok", "VCTX_CONTEXT=dev", "VAULT_ADDR=https://vault.example.com/")
	if got := helper("get", "", "VCTX_CONTEXT=dev", "VAULT_ADDR=https://vault.example.com"); got != "tok" {
		t.Errorf("same address: %q", got)
	}
	if got := helper("get", "", "VCTX_CONTEXT=dev", "VAULT_ADDR=https://evil.example.com"); got != "" {
		t.Errorf("token handed to another address: %q", got)
	}

	// An empty token written by an earlier version must not come back as the address.
	if err := os.WriteFile(filepath.Join(dir, "tokens", "stale"), []byte("https://vault.example.com\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := helper("get", "", "VCTX_CONTEXT=stale", "VAULT_ADDR=https://vault.example.com"); got != "" {
		t.Errorf("address returned as token: %q", got)
	}

	helper("store", "\n", "VCTX_CONTEXT=dev", "VAULT_ADDR=https://vault.example.com")
	if got := helper("get", "", "VCTX_CONTEXT=dev", "VAULT_ADDR=https://vault.example.com"); got != "" {
		t.Errorf("empty store left %q", got)
	}

	// A token stored without an address could belong to any server.
	if err := os.WriteFile(filepath.Join(dir, "tokens", "prod"), []byte("legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := helper("get", "", "VCTX_CONTEXT=prod", "VAULT_ADDR=https://anything"); got != "" {
		t.Errorf("unbound token handed out: %q", got)
	}
}

func TestHelperLoginAfterAddressChange(t *testing.T) {
	helper, _ := helperRunner(t)
	helper("store", "old", "VCTX_CONTEXT=dev", "VAULT_ADDR=https://old.example.com")
	// vault login asks for the current token before storing the new one.
	if got := helper("get", "", "VCTX_CONTEXT=dev", "VAULT_ADDR=https://new.example.com"); got != "" {
		t.Errorf("old token offered to the new address: %q", got)
	}
	helper("store", "new", "VCTX_CONTEXT=dev", "VAULT_ADDR=https://new.example.com")
	if got := helper("get", "", "VCTX_CONTEXT=dev", "VAULT_ADDR=https://new.example.com"); got != "new" {
		t.Errorf("after login: %q", got)
	}
}

func TestAddressAndContextTokensApart(t *testing.T) {
	helper, _ := helperRunner(t)
	addr := "VAULT_ADDR=https://vault.example.com"
	helper("store", "by-address", addr)
	helper("store", "by-context", addr, "VCTX_CONTEXT=addr")
	if got := helper("get", "", addr); got != "by-address" {
		t.Errorf("address token = %q", got)
	}
	if got := helper("get", "", addr, "VCTX_CONTEXT=addr"); got != "by-context" {
		t.Errorf("context token = %q", got)
	}
}

// In a context shell, vault pointed elsewhere by hand must not replace or
// erase the context's own token.
func TestHandChangedAddressKeepsContextToken(t *testing.T) {
	helper, _ := helperRunner(t)
	ctx := []string{"VCTX_CONTEXT=dev", "VCTX_CONTEXT_ADDR=http://127.0.0.1:8201"}
	helper("store", "dev-token", append(ctx, "VAULT_ADDR=http://127.0.0.1:8201")...)
	helper("store", "other-token", append(ctx, "VAULT_ADDR=http://other:8200")...)
	helper("erase", "", append(ctx, "VAULT_ADDR=http://other:8200")...)
	if got := helper("get", "", append(ctx, "VAULT_ADDR=http://127.0.0.1:8201")...); got != "dev-token" {
		t.Errorf("context token = %q", got)
	}
}

func TestHandChangedNamespaceKeepsContextToken(t *testing.T) {
	helper, _ := helperRunner(t)
	ctx := []string{"VCTX_CONTEXT=dev", "VCTX_CONTEXT_ADDR=http://v", "VCTX_CONTEXT_NAMESPACE=admin", "VAULT_ADDR=http://v"}
	helper("store", "admin-token", append(ctx, "VAULT_NAMESPACE=admin")...)
	helper("store", "team-token", append(ctx, "VAULT_NAMESPACE=admin/team")...)
	if got := helper("get", "", append(ctx, "VAULT_NAMESPACE=admin")...); got != "admin-token" {
		t.Errorf("context token = %q", got)
	}
}

func TestHelperTokenTooLarge(t *testing.T) {
	s, _ := openStore(t, "file", nil)
	env := []string{"VCTX_CONTEXT=dev"}
	err := Helper("store", env, s, strings.NewReader(strings.Repeat("t", 64<<10+1)), &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("err = %v", err)
	}
	if _, _, ok, _ := s.Get("dev"); ok {
		t.Error("a cut token was stored")
	}
}

func TestCallerAddrPrefersAgent(t *testing.T) {
	env := []string{"VAULT_ADDR=https://vault:8200/", "VAULT_AGENT_ADDR=http://127.0.0.1:8100/"}
	if got := callerAddr(env); got != "http://127.0.0.1:8100" {
		t.Errorf("callerAddr = %q", got)
	}
}
