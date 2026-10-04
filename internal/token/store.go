// Package token stores Vault tokens bound to their address, as Vault's token helper.
package token

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/eugene-panin/vctx/internal/config"
	"github.com/eugene-panin/vctx/internal/safefile"
	"github.com/zalando/go-keyring"
)

const keyringService = "vctx"

// Store keeps one token per key, with the address it was issued for;
// keys are context names or "_addr/<hash>".
type Store interface {
	// Get returns the token stored for key and its address; ok is false when there is none.
	Get(key string) (token, addr string, ok bool, err error)
	// Addr is Get without the token, where the store can avoid reading the secret.
	Addr(key string) (addr string, ok bool, err error)
	Set(key, token, addr string) error
	Del(key string) error
}

// encodeToken is the stored form: address and token, one per line.
func encodeToken(token, addr string) string { return addr + "\n" + token + "\n" }

// decodeToken splits a stored value. A value written before tokens were bound
// to an address has no address and must not be handed to any server.
func decodeToken(v string) (token, addr string) {
	addr, token, bound := strings.Cut(strings.TrimSpace(v), "\n")
	if !bound {
		return "", ""
	}
	return strings.TrimSpace(token), strings.TrimSpace(addr)
}

type fileStore struct{ dir string }

func (s fileStore) path(key string) string { return filepath.Join(s.dir, filepath.FromSlash(key)) }

func (s fileStore) Get(key string) (string, string, bool, error) {
	b, err := os.ReadFile(s.path(key))
	if errors.Is(err, fs.ErrNotExist) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	token, addr := decodeToken(string(b))
	return token, addr, true, nil
}

func (s fileStore) Addr(key string) (string, bool, error) {
	_, addr, ok, err := s.Get(key)
	return addr, ok, err
}

func (s fileStore) Set(key, token, addr string) error {
	return safefile.Write(s.path(key), []byte(encodeToken(token, addr)), 0o600)
}

func (s fileStore) Del(key string) error {
	if err := os.Remove(s.path(key)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// SecretService is the part of the OS keychain vctx uses; tests replace it.
type SecretService interface {
	Get(service, user string) (string, error)
	Has(service, user string) (bool, error)
	Set(service, user, password string) error
	Delete(service, user string) error
}

type systemKeyring struct{}

func (systemKeyring) Get(service, user string) (string, error) { return keyring.Get(service, user) }
func (systemKeyring) Set(service, user, password string) error {
	return keyring.Set(service, user, password)
}
func (systemKeyring) Delete(service, user string) error { return keyring.Delete(service, user) }

// Has checks for an item without reading the secret where the platform allows:
// go-keyring offers only Get, which on macOS runs `security ... -w` and prints it.
func (systemKeyring) Has(service, user string) (bool, error) {
	if runtime.GOOS != "darwin" {
		_, err := keyring.Get(service, user)
		if errors.Is(err, keyring.ErrNotFound) {
			return false, nil
		}
		return err == nil, err
	}
	err := exec.Command("/usr/bin/security", "find-generic-password", "-s", service, "-a", user).Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &exitErr) && exitErr.ExitCode() == 44: // errSecItemNotFound
		return false, nil
	}
	return false, err
}

// keychainError explains the usual causes: go-keyring reports only the exit status of `security`.
func keychainError(err error) error {
	return fmt.Errorf("keychain unavailable (locked, or an ssh session?), set VCTX_TOKEN_STORE=file to use files: %w", err)
}

// keychainStore keeps tokens in the OS keychain and, in plain files under
// addrDir, the address of each, so status needs no secret read. A token file
// written by an earlier version is still read; the next login moves it here,
// as Set removes it. Reads never write.
type keychainStore struct {
	kr      SecretService
	addrDir string
	legacy  fileStore
	// oldAddrDir held address records in the version before addrDir; they
	// are not trusted, only removed when the token they describe changes.
	oldAddrDir string
}

func (s keychainStore) removeOldRecord(key string) error {
	if err := os.Remove(filepath.Join(s.oldAddrDir, filepath.FromSlash(key))); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (s keychainStore) addrPath(key string) string {
	return filepath.Join(s.addrDir, filepath.FromSlash(key))
}

func (s keychainStore) Get(key string) (string, string, bool, error) {
	v, err := s.kr.Get(keyringService, key)
	switch {
	case err == nil:
		token, addr := decodeToken(v)
		return token, addr, true, nil
	case !errors.Is(err, keyring.ErrNotFound):
		return "", "", false, keychainError(err)
	}
	return s.legacy.Get(key)
}

func (s keychainStore) Addr(key string) (string, bool, error) {
	ok, err := s.kr.Has(keyringService, key)
	switch {
	case err != nil:
		return "", false, keychainError(err)
	case !ok:
		return s.legacy.Addr(key)
	}
	b, err := os.ReadFile(s.addrPath(key))
	if err == nil {
		return strings.TrimSpace(string(b)), true, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", false, err
	}
	// An item stored before addresses were recorded: the address is only inside it.
	_, addr, ok, err := s.Get(key)
	return addr, ok, err
}

// Set records the address first and puts the old record back if the keychain
// refuses the token, so the record never describes a token that is not there.
func (s keychainStore) Set(key, token, addr string) error {
	path := s.addrPath(key)
	old, oldErr := os.ReadFile(path)
	if err := safefile.Write(path, []byte(addr+"\n"), 0o600); err != nil {
		return err
	}
	if err := s.kr.Set(keyringService, key, encodeToken(token, addr)); err != nil {
		if oldErr == nil {
			_ = safefile.Write(path, old, 0o600)
		} else {
			_ = os.Remove(path)
		}
		if errors.Is(err, keyring.ErrSetDataTooBig) {
			return fmt.Errorf("token too long for the keychain, set VCTX_TOKEN_STORE=file to use files: %w", err)
		}
		return keychainError(err)
	}
	if err := s.removeOldRecord(key); err != nil {
		return err
	}
	return s.legacy.Del(key)
}

func (s keychainStore) Del(key string) error {
	if err := s.kr.Delete(keyringService, key); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return keychainError(err)
	}
	if err := os.Remove(s.addrPath(key)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := s.removeOldRecord(key); err != nil {
		return err
	}
	return s.legacy.Del(key)
}

// Open returns the store kind names: "keychain", "file", or "" for the
// default (the keychain on macOS, files elsewhere, since a Linux secret
// service is often missing on servers). kr replaces the system keychain.
func Open(stateDir, kind string, kr SecretService) (Store, error) {
	files := fileStore{dir: filepath.Join(stateDir, "tokens")}
	if kind == "" {
		kind = "file"
		if runtime.GOOS == "darwin" {
			kind = "keychain"
		}
	}
	switch kind {
	case "file":
		return files, nil
	case "keychain":
		if kr == nil {
			kr = systemKeyring{}
		}
		return keychainStore{
			kr:         kr,
			addrDir:    filepath.Join(stateDir, "keychain-addrs"),
			legacy:     files,
			oldAddrDir: filepath.Join(stateDir, "addrs"),
		}, nil
	}
	return nil, fmt.Errorf("invalid VCTX_TOKEN_STORE %q, want file or keychain", kind)
}

// State is what a context's stored token is good for.
type State int

const (
	None  State = iota
	OK          // stored for the context's current address
	Stale       // stored for another address, or without one: vault will not get it
)

// String is the state as 'vctx ls --json' reports it.
func (s State) String() string {
	switch s {
	case OK:
		return "ok"
	case Stale:
		return "stale"
	}
	return "none"
}

// Status reports the stored token of each context; on error the map still
// holds every answer that could be got.
func Status(s Store, cfg *config.Config, home string, names []string) (map[string]State, error) {
	out := make(map[string]State, len(names))
	var errs []error
	for _, name := range names {
		state, err := StateOf(s, cfg, home, name)
		out[name] = state
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return out, errors.Join(errs...)
}

// StateOf reports the stored token of context name.
func StateOf(s Store, cfg *config.Config, home, name string) (State, error) {
	addr, ok, err := s.Addr(name)
	if err != nil || !ok {
		return None, err
	}
	vars, err := cfg.Vars(name, home)
	if err != nil {
		return None, err
	}
	if addr == "" || addr != config.NormalizeAddr(config.VaultAddr(vars)) {
		return Stale, nil
	}
	return OK, nil
}
