package cli

import (
	"errors"
	"testing"

	"github.com/eugene-panin/vctx/internal/config"
)

// noKeyring fails every call: the CLI tests use the file store, and none may
// reach the real keychain.
type noKeyring struct{}

var errNoKeyring = errors.New("test reached the keychain")

func (noKeyring) Get(string, string) (string, error) { return "", errNoKeyring }
func (noKeyring) Has(string, string) (bool, error)   { return false, errNoKeyring }
func (noKeyring) Set(string, string, string) error   { return errNoKeyring }
func (noKeyring) Delete(string, string) error        { return errNoKeyring }

func loadTestConfig(t *testing.T, a *app) *config.Config {
	t.Helper()
	cfg, err := a.loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// hasToken reports whether the app's token store holds a token for key.
func hasToken(t *testing.T, a *app, key string) bool {
	t.Helper()
	s, err := a.tokens()
	if err != nil {
		t.Fatal(err)
	}
	_, _, ok, err := s.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestTokenStoreSelection(t *testing.T) {
	a, _, _ := newTestApp(t, "VCTX_TOKEN_STORE=vault")
	if _, err := a.tokens(); err == nil {
		t.Error("unknown store accepted")
	}
}
