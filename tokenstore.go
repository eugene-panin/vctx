package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/zalando/go-keyring"
)

const keyringService = "vctx"

// tokenStore keeps one secret per key; keys are context names or "_addr/<hash>".
type tokenStore interface {
	get(key string) (value string, ok bool, err error)
	has(key string) (bool, error)
	set(key, value string) error
	del(key string) error
}

type fileStore struct{ dir string }

func (s fileStore) path(key string) string { return filepath.Join(s.dir, filepath.FromSlash(key)) }

func (s fileStore) get(key string) (string, bool, error) {
	b, err := os.ReadFile(s.path(key))
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(b), true, nil
}

func (s fileStore) has(key string) (bool, error) {
	_, err := os.Stat(s.path(key))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (s fileStore) set(key, value string) error {
	return writeFileAtomic(s.path(key), []byte(value), 0o600)
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

// keychainStore keeps tokens in the OS keychain and moves token files
// written by earlier versions into it on first use.
type keychainStore struct {
	kr     secretService
	legacy fileStore
}

func (s keychainStore) get(key string) (string, bool, error) {
	v, err := s.kr.Get(keyringService, key)
	if err == nil {
		return v, true, nil
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		return "", false, keychainError(err)
	}
	v, ok, err := s.legacy.get(key)
	if err != nil || !ok {
		return "", false, err
	}
	if err := s.set(key, v); err != nil {
		return "", false, err
	}
	return v, true, nil
}

// has does not migrate a token file: that happens when vault actually asks for the token.
func (s keychainStore) has(key string) (bool, error) {
	ok, err := s.kr.Has(keyringService, key)
	switch {
	case err != nil:
		return false, keychainError(err)
	case ok:
		return true, nil
	}
	return s.legacy.has(key)
}

func (s keychainStore) set(key, value string) error {
	if err := s.kr.Set(keyringService, key, value); err != nil {
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
		return keychainStore{kr: kr, legacy: files}, nil
	}
	return nil, fmt.Errorf("invalid VCTX_TOKEN_STORE %q, want file or keychain", kind)
}

// tokenStatus reports which contexts have a stored token; on error the map
// still holds every answer that could be got.
func (a *app) tokenStatus(names []string) (map[string]bool, error) {
	out := make(map[string]bool, len(names))
	store, err := a.tokens()
	if err != nil {
		return out, err
	}
	var errs []error
	for _, name := range names {
		ok, err := store.has(name)
		out[name] = ok
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return out, errors.Join(errs...)
}
