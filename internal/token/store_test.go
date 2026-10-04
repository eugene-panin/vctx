package token

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eugene-panin/vctx/internal/config"
	"github.com/eugene-panin/vctx/internal/safefile"
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

const devAddr = "http://127.0.0.1:8201"

var testConfig = &config.Config{Contexts: map[string]map[string]string{
	"dev":  {"VAULT_ADDR": devAddr},
	"prod": {"VAULT_ADDR": "https://vault.example.com"},
}}

func openStore(t *testing.T, kind string, kr SecretService) (Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir, kind, kr)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func status(t *testing.T, s Store, names ...string) map[string]State {
	t.Helper()
	got, err := Status(s, testConfig, "/home/u", names)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestOpenRejectsUnknownStore(t *testing.T) {
	if _, err := Open(t.TempDir(), "vault", nil); err == nil {
		t.Error("unknown store accepted")
	}
}

func TestFileStore(t *testing.T) {
	s, dir := openStore(t, "file", nil)
	if err := s.Set("dev", "tok", devAddr); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "tokens", "dev"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file: %v, %v", fi, err)
	}
	if tok, addr, ok, err := s.Get("dev"); tok != "tok" || addr != devAddr || !ok || err != nil {
		t.Errorf("get = %q %q %v %v", tok, addr, ok, err)
	}
	if err := s.Del("dev"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := s.Get("dev"); ok {
		t.Error("token left after del")
	}
	if err := s.Del("dev"); err != nil {
		t.Errorf("second del: %v", err)
	}
}

func TestStateSeesAddressChange(t *testing.T) {
	s, _ := openStore(t, "file", nil)
	if err := s.Set("dev", "tok", devAddr); err != nil {
		t.Fatal(err)
	}
	if got := status(t, s, "dev", "prod"); got["dev"] != OK || got["prod"] != None {
		t.Errorf("before: %v", got)
	}
	cfg := &config.Config{Contexts: map[string]map[string]string{"dev": {"VAULT_ADDR": "http://localhost:8201"}}}
	if got, _ := StateOf(s, cfg, "/home/u", "dev"); got != Stale {
		t.Errorf("after the address changed: %v", got)
	}
}

func TestKeychainMigratesLegacyFile(t *testing.T) {
	kr := newFakeKeyring()
	s, dir := openStore(t, "keychain", kr)
	legacy := filepath.Join(dir, "tokens", "dev")

	// A token file from an earlier version is read as is, without writing anything.
	if err := safefile.Write(legacy, []byte(devAddr+"\nold-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tok, _, _, err := s.Get("dev"); tok != "old-token" || err != nil || len(kr.m) != 0 {
		t.Errorf("legacy read: token %q, %v, keychain %v", tok, err, kr.m)
	}
	if got := status(t, s, "dev"); got["dev"] != OK || len(kr.m) != 0 {
		t.Errorf("status %v, keychain %v", got, kr.m)
	}

	// The next login moves it into the keychain.
	if err := s.Set("dev", "new-token", devAddr); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("token file left behind: %v", err)
	}
	if kr.m["vctx/dev"] != devAddr+"\nnew-token\n" {
		t.Errorf("keychain = %v", kr.m)
	}
	if err := s.Del("dev"); err != nil {
		t.Fatal(err)
	}
	if len(kr.m) != 0 {
		t.Errorf("keychain after del = %v", kr.m)
	}
}

type brokenKeyring struct{ *fakeKeyring }

func (brokenKeyring) Get(string, string) (string, error) { return "", errors.New("keychain locked") }
func (brokenKeyring) Has(string, string) (bool, error)   { return false, errors.New("keychain locked") }

func TestKeychainErrorsReported(t *testing.T) {
	s, _ := openStore(t, "keychain", brokenKeyring{newFakeKeyring()})
	if _, err := Status(s, testConfig, "/home/u", []string{"dev"}); err == nil || !strings.Contains(err.Error(), "locked") || !strings.Contains(err.Error(), "VCTX_TOKEN_STORE=file") {
		t.Errorf("status err = %v", err)
	}
	if err := Helper("get", []string{"VCTX_CONTEXT=dev"}, s, nil, &strings.Builder{}); err == nil {
		t.Error("get hid a keychain failure")
	}
}

type smallKeyring struct{ *fakeKeyring }

func (smallKeyring) Set(string, string, string) error { return keyring.ErrSetDataTooBig }

func TestKeychainTokenTooLong(t *testing.T) {
	s, _ := openStore(t, "keychain", smallKeyring{newFakeKeyring()})
	if err := s.Set("dev", strings.Repeat("t", 4000), devAddr); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("err = %v", err)
	}
}

func TestKeychainStatusReadsNoSecret(t *testing.T) {
	kr := newFakeKeyring()
	s, dir := openStore(t, "keychain", kr)
	if err := s.Set("dev", "tok", devAddr); err != nil {
		t.Fatal(err)
	}
	kr.gets = 0
	if got := status(t, s, "dev"); got["dev"] != OK {
		t.Fatalf("status = %v", got)
	}
	if kr.gets != 0 {
		t.Errorf("status read the secret %d times", kr.gets)
	}
	if err := s.Del("dev"); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "keychain-addrs")); len(entries) != 0 {
		t.Errorf("address records left after del: %v", entries)
	}
}

// The file and keychain stores keep their own addresses, so switching
// VCTX_TOKEN_STORE never pairs one store's token with the other's address.
func TestStoresKeepTheirOwnAddresses(t *testing.T) {
	dir := t.TempDir()
	kc, _ := Open(dir, "keychain", newFakeKeyring())
	files, _ := Open(dir, "file", nil)
	if err := kc.Set("dev", "kc-token", devAddr); err != nil {
		t.Fatal(err)
	}
	if err := files.Set("dev", "file-token", "http://other:8201"); err != nil {
		t.Fatal(err)
	}
	tok, _, _, _ := kc.Get("dev")
	if got := status(t, kc, "dev"); got["dev"] != OK || tok != "kc-token" {
		t.Errorf("keychain: status %v, get %q", got["dev"], tok)
	}
}

type refusingKeyring struct{ *fakeKeyring }

func (refusingKeyring) Set(string, string, string) error { return errors.New("denied") }

func TestFailedStoreKeepsAddressRecord(t *testing.T) {
	dir := t.TempDir()
	kr := newFakeKeyring()
	s, _ := Open(dir, "keychain", kr)
	if err := s.Set("dev", "old", devAddr); err != nil {
		t.Fatal(err)
	}
	refusing, _ := Open(dir, "keychain", refusingKeyring{kr})
	if err := refusing.Set("dev", "new", "http://elsewhere:8201"); err == nil {
		t.Fatal("set succeeded against a refusing keychain")
	}
	if got := status(t, s, "dev"); got["dev"] != OK {
		t.Errorf("status after a failed set = %v, want the old token still ok", got["dev"])
	}
}

// Keychain items written before addresses were recorded have the address only
// inside the secret: status reads it from there and writes nothing.
func TestKeychainItemWithoutAddressRecord(t *testing.T) {
	kr := newFakeKeyring()
	s, dir := openStore(t, "keychain", kr)
	kr.m["vctx/dev"] = devAddr + "\ntok\n"
	kr.m["vctx/prod"] = "http://elsewhere\ntok\n"
	if got := status(t, s, "dev", "prod"); got["dev"] != OK || got["prod"] != Stale {
		t.Errorf("status = %v", got)
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "keychain-addrs")); len(entries) != 0 {
		t.Errorf("status wrote address records: %v", entries)
	}
}

func TestOldAddressRecordsRemoved(t *testing.T) {
	s, dir := openStore(t, "keychain", newFakeKeyring())
	old := filepath.Join(dir, "addrs", "dev")
	if err := safefile.Write(old, []byte("http://stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("dev", "tok", devAddr); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("old record left after set: %v", err)
	}
	if err := safefile.Write(old, []byte("http://stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Del("dev"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("old record left after del: %v", err)
	}
}
