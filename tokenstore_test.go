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

func TestKeychainStore(t *testing.T) {
	a, out, _ := newTestApp(t, "VCTX_TOKEN_STORE=keychain")
	kr := fakeKeyring{}
	a.keyring = kr

	// A token file from an earlier version moves into the keychain on first read.
	if err := writeFileAtomic(a.tokenPath("dev"), []byte("https://127.0.0.1:8200\nold-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.environ = withEnv(a.environ, "VCTX_CONTEXT=dev")
	if err := a.run([]string{"get"}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "old-token" {
		t.Errorf("migrated token = %q", out.String())
	}
	if _, err := os.Stat(a.tokenPath("dev")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("token file left behind: %v", err)
	}
	if kr["vctx/dev"] != "https://127.0.0.1:8200\nold-token\n" {
		t.Errorf("keychain = %v", kr)
	}

	if got, err := a.tokenStatus([]string{"dev", "prod"}); err != nil || !got["dev"] || got["prod"] {
		t.Errorf("token status = %v, %v", got, err)
	}
	if err := a.run([]string{"logout", "dev"}); err != nil {
		t.Fatal(err)
	}
	if len(kr) != 0 {
		t.Errorf("keychain after logout = %v", kr)
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
	if _, err := a.tokenStatus([]string{"dev"}); err == nil || !strings.Contains(err.Error(), "locked") || !strings.Contains(err.Error(), "VCTX_TOKEN_STORE=file") {
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
	if got, err := a.tokenStatus([]string{"dev"}); err != nil || !got["dev"] {
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
