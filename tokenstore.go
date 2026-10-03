package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/zalando/go-keyring"
)

const keyringService = "vctx"

// tokenStore keeps one token per key, with the address it was issued for;
// keys are context names or "_addr/<hash>".
type tokenStore interface {
	// get returns the token stored for key and its address; ok is false when there is none.
	get(key string) (token, addr string, ok bool, err error)
	// addr is get without the token, where the store can avoid reading the secret.
	addr(key string) (addr string, ok bool, err error)
	set(key, token, addr string) error
	del(key string) error
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

func (s fileStore) get(key string) (string, string, bool, error) {
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

func (s fileStore) addr(key string) (string, bool, error) {
	_, addr, ok, err := s.get(key)
	return addr, ok, err
}

func (s fileStore) set(key, token, addr string) error {
	return writeFileAtomic(s.path(key), []byte(encodeToken(token, addr)), 0o600)
}

func (s fileStore) del(key string) error {
	if err := os.Remove(s.path(key)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// secretService is the part of the OS keychain vctx uses; tests replace it.
type secretService interface {
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
// as set removes it. Reads never write.
type keychainStore struct {
	kr      secretService
	addrDir string
	legacy  fileStore
}

func (s keychainStore) addrPath(key string) string {
	return filepath.Join(s.addrDir, filepath.FromSlash(key))
}

func (s keychainStore) get(key string) (string, string, bool, error) {
	v, err := s.kr.Get(keyringService, key)
	switch {
	case err == nil:
		token, addr := decodeToken(v)
		return token, addr, true, nil
	case !errors.Is(err, keyring.ErrNotFound):
		return "", "", false, keychainError(err)
	}
	return s.legacy.get(key)
}

func (s keychainStore) addr(key string) (string, bool, error) {
	ok, err := s.kr.Has(keyringService, key)
	switch {
	case err != nil:
		return "", false, keychainError(err)
	case !ok:
		return s.legacy.addr(key)
	}
	b, err := os.ReadFile(s.addrPath(key))
	if err == nil {
		return strings.TrimSpace(string(b)), true, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", false, err
	}
	// An item stored before addresses were recorded: the address is only inside it.
	_, addr, ok, err := s.get(key)
	return addr, ok, err
}

// set records the address first and puts the old record back if the keychain
// refuses the token, so the record never describes a token that is not there.
func (s keychainStore) set(key, token, addr string) error {
	path := s.addrPath(key)
	old, oldErr := os.ReadFile(path)
	if err := writeFileAtomic(path, []byte(addr+"\n"), 0o600); err != nil {
		return err
	}
	if err := s.kr.Set(keyringService, key, encodeToken(token, addr)); err != nil {
		if oldErr == nil {
			_ = writeFileAtomic(path, old, 0o600)
		} else {
			_ = os.Remove(path)
		}
		if errors.Is(err, keyring.ErrSetDataTooBig) {
			return fmt.Errorf("token too long for the keychain, set VCTX_TOKEN_STORE=file to use files: %w", err)
		}
		return keychainError(err)
	}
	return s.legacy.del(key)
}

func (s keychainStore) del(key string) error {
	if err := s.kr.Delete(keyringService, key); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return keychainError(err)
	}
	if err := os.Remove(s.addrPath(key)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return s.legacy.del(key)
}

// tokens picks the store from VCTX_TOKEN_STORE: the keychain by default on macOS,
// files elsewhere, since a Linux secret service is often missing on servers.
func (a *app) tokens() (tokenStore, error) {
	files := fileStore{dir: filepath.Join(a.stateDir, "tokens")}
	kind := a.getenv("VCTX_TOKEN_STORE")
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
		kr := a.keyring
		if kr == nil {
			kr = systemKeyring{}
		}
		return keychainStore{kr: kr, addrDir: filepath.Join(a.stateDir, "keychain-addrs"), legacy: files}, nil
	}
	return nil, fmt.Errorf("invalid VCTX_TOKEN_STORE %q, want file or keychain", kind)
}

type tokenState int

const (
	tokenNone  tokenState = iota
	tokenOK               // stored for the context's current address
	tokenStale            // stored for another address, or none: vault will not get it
)

// tokenStatus reports the stored token of each context; on error the map
// still holds every answer that could be got.
func (a *app) tokenStatus(cfg *config, names []string) (map[string]tokenState, error) {
	out := make(map[string]tokenState, len(names))
	store, err := a.tokens()
	if err != nil {
		return out, err
	}
	var errs []error
	for _, name := range names {
		state, err := a.tokenStateOf(store, cfg, name)
		out[name] = state
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return out, errors.Join(errs...)
}

func (a *app) tokenStateOf(store tokenStore, cfg *config, name string) (tokenState, error) {
	addr, ok, err := store.addr(name)
	if err != nil || !ok {
		return tokenNone, err
	}
	vars, err := cfg.vars(name, a.home)
	if err != nil {
		return tokenNone, err
	}
	if addr == "" || addr != normalizeAddr(vaultAddr(vars)) {
		return tokenStale, nil
	}
	return tokenOK, nil
}
