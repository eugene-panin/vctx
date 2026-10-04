package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eugene-panin/vctx/internal/atomicfile"
	"github.com/eugene-panin/vctx/internal/config"
	"github.com/eugene-panin/vctx/internal/token"
	"github.com/zalando/go-keyring"
)

// fakeKeyring stands in for the OS keychain; gets counts secret reads,
// which status must not need.
type fakeKeyring struct {
	m    map[string]string
	gets int
}

func newFakeKeyring() *fakeKeyring { return &fakeKeyring{m: map[string]string{}} }

func (f *fakeKeyring) Get(service, user string) (string, error) {
	f.gets++
	v, ok := f.m[service+"/"+user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (f *fakeKeyring) Has(service, user string) (bool, error) {
	_, ok := f.m[service+"/"+user]
	return ok, nil
}

func (f *fakeKeyring) Set(service, user, password string) error {
	f.m[service+"/"+user] = password
	return nil
}

func (f *fakeKeyring) Delete(service, user string) error {
	if _, ok := f.m[service+"/"+user]; !ok {
		return keyring.ErrNotFound
	}
	delete(f.m, service+"/"+user)
	return nil
}

func loadTestConfig(t *testing.T, a *app) *config.Config {
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
	kr := newFakeKeyring()
	a.keyring = kr
	cfg := loadTestConfig(t, a)

	// A token file from an earlier version is read as is, without writing anything.
	if err := atomicfile.Write(a.tokenPath("dev"), []byte("http://127.0.0.1:8201\nold-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.run([]string{"get"}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "old-token" || len(kr.m) != 0 {
		t.Errorf("legacy read: token %q, keychain %v", out, kr)
	}
	if got, err := a.tokenStatus(cfg, []string{"dev", "prod"}); err != nil || got["dev"] != token.OK || got["prod"] != token.None {
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
	if kr.m["vctx/dev"] != "http://127.0.0.1:8201\nnew-token\n" {
		t.Errorf("keychain = %v", kr)
	}

	if err := a.run([]string{"logout", "dev"}); err != nil {
		t.Fatal(err)
	}
	if len(kr.m) != 0 {
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
	if got, _ := a.tokenStatus(cfg, []string{"dev"}); got["dev"] != token.OK {
		t.Errorf("before: %v", got)
	}
	cfg.Contexts["dev"]["VAULT_ADDR"] = "http://localhost:8201"
	if got, _ := a.tokenStatus(cfg, []string{"dev"}); got["dev"] != token.Stale {
		t.Errorf("after the address changed: %v", got)
	}
}

func TestTokenStoreSelection(t *testing.T) {
	a, _, _ := newTestApp(t, "VCTX_TOKEN_STORE=vault")
	if _, err := a.tokens(); err == nil {
		t.Error("unknown store accepted")
	}
}

type brokenKeyring struct{ *fakeKeyring }

func (brokenKeyring) Get(string, string) (string, error) { return "", errors.New("keychain locked") }
func (brokenKeyring) Has(string, string) (bool, error)   { return false, errors.New("keychain locked") }

func TestKeychainErrorsReported(t *testing.T) {
	a, _, _ := newTestApp(t, "VCTX_TOKEN_STORE=keychain", "VCTX_CONTEXT=dev")
	a.keyring = brokenKeyring{newFakeKeyring()}
	if _, err := a.tokenStatus(loadTestConfig(t, a), []string{"dev"}); err == nil || !strings.Contains(err.Error(), "locked") || !strings.Contains(err.Error(), "VCTX_TOKEN_STORE=file") {
		t.Errorf("tokenStatus err = %v", err)
	}
	if err := a.run([]string{"get"}); err == nil {
		t.Error("get hid a keychain failure")
	}
}

func TestStatusDoesNotMigrate(t *testing.T) {
	a, _, _ := newTestApp(t, "VCTX_TOKEN_STORE=keychain")
	kr := newFakeKeyring()
	a.keyring = kr
	if err := atomicfile.Write(a.tokenPath("dev"), []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := a.tokenStatus(loadTestConfig(t, a), []string{"dev"}); err != nil || got["dev"] == token.None {
		t.Fatalf("status = %v, %v", got, err)
	}
	if len(kr.m) != 0 {
		t.Errorf("status check migrated the token: %v", kr)
	}
}

type smallKeyring struct{ *fakeKeyring }

func (smallKeyring) Set(string, string, string) error { return keyring.ErrSetDataTooBig }

func TestKeychainTokenTooLong(t *testing.T) {
	a, _, _ := newTestApp(t, "VCTX_TOKEN_STORE=keychain", "VCTX_CONTEXT=dev")
	a.keyring = smallKeyring{newFakeKeyring()}
	a.stdin = strings.NewReader(strings.Repeat("t", 4000))
	if err := a.run([]string{"store"}); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("err = %v", err)
	}
}

func TestKeychainStatusReadsNoSecret(t *testing.T) {
	a, _, _ := newTestApp(t, "VCTX_TOKEN_STORE=keychain", "VCTX_CONTEXT=dev", "VAULT_ADDR=http://127.0.0.1:8201")
	kr := newFakeKeyring()
	a.keyring = kr
	a.stdin = strings.NewReader("tok")
	if err := a.run([]string{"store"}); err != nil {
		t.Fatal(err)
	}
	kr.gets = 0
	if got, err := a.tokenStatus(loadTestConfig(t, a), []string{"dev"}); err != nil || got["dev"] != token.OK {
		t.Fatalf("status = %v, %v", got, err)
	}
	if kr.gets != 0 {
		t.Errorf("status read the secret %d times", kr.gets)
	}
	if err := a.run([]string{"erase"}); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(filepath.Join(a.stateDir, "keychain-addrs")); len(entries) != 0 {
		t.Errorf("address records left after erase: %v", entries)
	}
}

// The file and keychain stores keep their own addresses, so switching
// VCTX_TOKEN_STORE never pairs one store's token with the other's address.
func TestStoresKeepTheirOwnAddresses(t *testing.T) {
	a, out, _ := newTestApp(t, "VCTX_CONTEXT=dev")
	kr := newFakeKeyring()
	a.keyring = kr
	base := a.environ
	run := helperRunner(t, a, out)
	run("store", "kc-token", "VCTX_TOKEN_STORE=keychain", "VAULT_ADDR=http://127.0.0.1:8201")
	run("store", "file-token", "VCTX_TOKEN_STORE=file", "VAULT_ADDR=http://other:8201")

	a.environ = withEnv(base, "VCTX_TOKEN_STORE=keychain")
	state, _ := a.tokenStatus(loadTestConfig(t, a), []string{"dev"})
	got := run("get", "", "VCTX_TOKEN_STORE=keychain", "VAULT_ADDR=http://127.0.0.1:8201")
	if state["dev"] != token.OK || got != "kc-token" {
		t.Errorf("keychain: status %v, get %q", state["dev"], got)
	}
}

type refusingKeyring struct{ *fakeKeyring }

func (refusingKeyring) Set(string, string, string) error { return errors.New("denied") }

func TestFailedStoreKeepsAddressRecord(t *testing.T) {
	a, _, _ := newTestApp(t, "VCTX_TOKEN_STORE=keychain", "VCTX_CONTEXT=dev", "VAULT_ADDR=http://127.0.0.1:8201")
	kr := newFakeKeyring()
	a.keyring = kr
	a.stdin = strings.NewReader("old")
	if err := a.run([]string{"store"}); err != nil {
		t.Fatal(err)
	}
	a.keyring = refusingKeyring{kr}
	a.environ = withEnv(a.environ, "VAULT_ADDR=http://elsewhere:8201")
	a.stdin = strings.NewReader("new")
	if err := a.run([]string{"store"}); err == nil {
		t.Fatal("store succeeded against a refusing keychain")
	}
	a.keyring = kr
	if got, _ := a.tokenStatus(loadTestConfig(t, a), []string{"dev"}); got["dev"] != token.OK {
		t.Errorf("status after a failed store = %v, want the old token still ok", got["dev"])
	}
}

// Keychain items written before addresses were recorded have the address only
// inside the secret: status reads it from there and writes nothing.
func TestKeychainItemWithoutAddressRecord(t *testing.T) {
	a, _, _ := newTestApp(t, "VCTX_TOKEN_STORE=keychain")
	kr := newFakeKeyring()
	a.keyring = kr
	kr.m["vctx/dev"] = "http://127.0.0.1:8201\ntok\n"
	kr.m["vctx/prod"] = "http://elsewhere\ntok\n"
	got, err := a.tokenStatus(loadTestConfig(t, a), []string{"dev", "prod"})
	if err != nil || got["dev"] != token.OK || got["prod"] != token.Stale {
		t.Errorf("status = %v, %v", got, err)
	}
	if entries, _ := os.ReadDir(filepath.Join(a.stateDir, "keychain-addrs")); len(entries) != 0 {
		t.Errorf("status wrote address records: %v", entries)
	}
}

func TestOldAddressRecordsRemoved(t *testing.T) {
	a, out, _ := newTestApp(t, "VCTX_TOKEN_STORE=keychain")
	old := filepath.Join(a.stateDir, "addrs", "dev")
	if err := atomicfile.Write(old, []byte("http://stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	helper := helperRunner(t, a, out)
	helper("store", "tok", "VCTX_CONTEXT=dev", "VAULT_ADDR=http://127.0.0.1:8201")
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("old record left after store: %v", err)
	}
	if err := atomicfile.Write(old, []byte("http://stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	helper("erase", "", "VCTX_CONTEXT=dev", "VAULT_ADDR=http://127.0.0.1:8201")
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("old record left after erase: %v", err)
	}
}
