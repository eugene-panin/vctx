package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

type fakeKeyring map[string]string

func (f fakeKeyring) Get(service, user string) (string, error) {
	v, ok := f[service+"/"+user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (f fakeKeyring) Has(service, user string) (bool, error) {
	_, ok := f[service+"/"+user]
	return ok, nil
}

func (f fakeKeyring) Set(service, user, password string) error {
	f[service+"/"+user] = password
	return nil
}

func (f fakeKeyring) Delete(service, user string) error {
	if _, ok := f[service+"/"+user]; !ok {
		return keyring.ErrNotFound
	}
	delete(f, service+"/"+user)
	return nil
}

func loadTestConfig(t *testing.T, a *app) *config {
	t.Helper()
	cfg, err := a.loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestKeychainStore(t *testing.T) {
	const addr = "VAULT_ADDR=http://127.0.0.1:8201" // dev's address in testConfig
	a, out, _ := newTestApp(t, "VCTX_TOKEN_STORE=keychain", "VCTX_CONTEXT=dev", addr)
	kr := fakeKeyring{}
	a.keyring = kr
	cfg := loadTestConfig(t, a)

	// A token file from an earlier version is read as is, without writing anything.
	if err := writeFileAtomic(a.tokenPath("dev"), []byte("http://127.0.0.1:8201\nold-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.run([]string{"get"}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "old-token" || len(kr) != 0 {
		t.Errorf("legacy read: token %q, keychain %v", out, kr)
	}
	if got, err := a.tokenStatus(cfg, []string{"dev", "prod"}); err != nil || got["dev"] != tokenOK || got["prod"] != tokenNone {
		t.Errorf("token status = %v, %v", got, err)
	}

	// The next login moves it into the keychain.
	a.stdin = strings.NewReader("new-token")
	if err := a.run([]string{"store"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a.tokenPath("dev")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("token file left behind: %v", err)
	}
	if kr["vctx/dev"] != "http://127.0.0.1:8201\nnew-token\n" {
		t.Errorf("keychain = %v", kr)
	}

	if err := a.run([]string{"logout", "dev"}); err != nil {
		t.Fatal(err)
	}
	if len(kr) != 0 {
		t.Errorf("keychain after logout = %v", kr)
	}
}

func TestTokenStatusSeesAddressChange(t *testing.T) {
	a, _, _ := newTestApp(t, "VCTX_CONTEXT=dev", "VAULT_ADDR=http://127.0.0.1:8201")
	a.stdin = strings.NewReader("tok")
	if err := a.run([]string{"store"}); err != nil {
		t.Fatal(err)
	}
	cfg := loadTestConfig(t, a)
	if got, _ := a.tokenStatus(cfg, []string{"dev"}); got["dev"] != tokenOK {
		t.Errorf("before: %v", got)
	}
	cfg.Contexts["dev"]["VAULT_ADDR"] = "http://localhost:8201"
	if got, _ := a.tokenStatus(cfg, []string{"dev"}); got["dev"] != tokenStale {
		t.Errorf("after the address changed: %v", got)
	}
}

func TestTokenStoreSelection(t *testing.T) {
	a, _, _ := newTestApp(t, "VCTX_TOKEN_STORE=vault")
	if _, err := a.tokens(); err == nil {
		t.Error("unknown store accepted")
	}
}

type brokenKeyring struct{ fakeKeyring }

func (brokenKeyring) Get(string, string) (string, error) { return "", errors.New("keychain locked") }
func (brokenKeyring) Has(string, string) (bool, error)   { return false, errors.New("keychain locked") }

func TestKeychainErrorsReported(t *testing.T) {
	a, _, _ := newTestApp(t, "VCTX_TOKEN_STORE=keychain", "VCTX_CONTEXT=dev")
	a.keyring = brokenKeyring{fakeKeyring{}}
	if _, err := a.tokenStatus(loadTestConfig(t, a), []string{"dev"}); err == nil || !strings.Contains(err.Error(), "locked") || !strings.Contains(err.Error(), "VCTX_TOKEN_STORE=file") {
		t.Errorf("tokenStatus err = %v", err)
	}
	if err := a.run([]string{"get"}); err == nil {
		t.Error("get hid a keychain failure")
	}
}

func TestHasDoesNotMigrate(t *testing.T) {
	a, _, _ := newTestApp(t, "VCTX_TOKEN_STORE=keychain")
	kr := fakeKeyring{}
	a.keyring = kr
	if err := writeFileAtomic(a.tokenPath("dev"), []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := a.tokenStatus(loadTestConfig(t, a), []string{"dev"}); err != nil || got["dev"] == tokenNone {
		t.Fatalf("status = %v, %v", got, err)
	}
	if len(kr) != 0 {
		t.Errorf("status check migrated the token: %v", kr)
	}
}

type smallKeyring struct{ fakeKeyring }

func (smallKeyring) Set(string, string, string) error { return keyring.ErrSetDataTooBig }

func TestKeychainTokenTooLong(t *testing.T) {
	a, _, _ := newTestApp(t, "VCTX_TOKEN_STORE=keychain", "VCTX_CONTEXT=dev")
	a.keyring = smallKeyring{fakeKeyring{}}
	a.stdin = strings.NewReader(strings.Repeat("t", 4000))
	if err := a.run([]string{"store"}); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("err = %v", err)
	}
}
