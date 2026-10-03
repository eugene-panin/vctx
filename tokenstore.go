package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
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

// secretService is the part of go-keyring vctx uses; tests replace it.
type secretService interface {
	Get(service, user string) (string, error)
	Set(service, user, password string) error
	Delete(service, user string) error
}

type systemKeyring struct{}

func (systemKeyring) Get(service, user string) (string, error) { return keyring.Get(service, user) }
func (systemKeyring) Set(service, user, password string) error {
	return keyring.Set(service, user, password)
}
func (systemKeyring) Delete(service, user string) error { return keyring.Delete(service, user) }

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
		return "", false, fmt.Errorf("keychain: %w", err)
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
	_, err := s.kr.Get(keyringService, key)
	switch {
	case err == nil:
		return true, nil
	case !errors.Is(err, keyring.ErrNotFound):
		return false, fmt.Errorf("keychain: %w", err)
	}
	return s.legacy.has(key)
}

func (s keychainStore) set(key, value string) error {
	if err := s.kr.Set(keyringService, key, value); err != nil {
		return fmt.Errorf("keychain: %w", err)
	}
	return s.legacy.del(key)
}

func (s keychainStore) del(key string) error {
	if err := s.kr.Delete(keyringService, key); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("keychain: %w", err)
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
