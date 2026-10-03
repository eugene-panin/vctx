package main

import (
	"errors"
	"os"
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
	if err := writeFileAtomic(a.tokenPath("dev"), []byte("old-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.environ = append(a.environ, "VCTX_CONTEXT=dev")
	if err := a.run([]string{"get"}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "old-token" {
		t.Errorf("migrated token = %q", out.String())
	}
	if _, err := os.Stat(a.tokenPath("dev")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("token file left behind: %v", err)
	}
	if kr["vctx/dev"] != "old-token\n" {
		t.Errorf("keychain = %v", kr)
	}

	if got := a.tokenStatus([]string{"dev", "prod"}); !got["dev"] || got["prod"] {
		t.Errorf("token status = %v", got)
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
