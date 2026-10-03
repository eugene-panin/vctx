package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const defaultVaultAddr = "https://127.0.0.1:8200"

func isHelperOp(s string) bool {
	return s == "get" || s == "store" || s == "erase"
}

// tokenPath is where the file store keeps the token of context name.
func (a *app) tokenPath(name string) string {
	return filepath.Join(a.stateDir, "tokens", name)
}

// addrPath records, next to the secret store, the address a token was issued
// for, so status can be shown without reading the secret.
func (a *app) addrPath(key string) string {
	return filepath.Join(a.stateDir, "addrs", filepath.FromSlash(key))
}

func (a *app) storeToken(store tokenStore, key, addr, token string) error {
	if err := store.set(key, addr+"\n"+token+"\n"); err != nil {
		return err
	}
	return writeFileAtomic(a.addrPath(key), []byte(addr+"\n"), 0o600)
}

func (a *app) forgetToken(store tokenStore, key string) error {
	if err := store.del(key); err != nil {
		return err
	}
	if err := os.Remove(a.addrPath(key)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// tokenKey picks the token for the calling vault process: by context when
// vault was started through vctx, otherwise by address and namespace. The "_"
// prefix cannot start a context name, so the two kinds of keys never collide.
func (a *app) tokenKey() string {
	if name := a.getenv(envContext); nameRe.MatchString(name) {
		return name
	}
	sum := sha256.Sum256([]byte(a.callerAddr() + "\x00" + a.getenv("VAULT_NAMESPACE")))
	return "_addr/" + hex.EncodeToString(sum[:12])
}

// callerAddr is the address the calling vault process talks to.
func (a *app) callerAddr() string {
	addr, _ := addrFrom(a.getenv)
	return normalizeAddr(addr)
}

// tokenHelper implements the Vault token helper protocol:
// https://developer.hashicorp.com/vault/docs/commands/token-helper
//
// A stored value holds the address the token was issued for and the token,
// one per line, so a token is never handed to vault talking to another address.
// A token for another address, or one stored without an address, is reported as
// missing rather than as an error: `vault login` asks for the current token
// first and would fail, leaving no way to replace it.
func (a *app) tokenHelper(op string) error {
	store, err := a.tokens()
	if err != nil {
		return err
	}
	key := a.tokenKey()
	switch op {
	case "get":
		v, ok, err := store.get(key)
		if err != nil || !ok {
			return err
		}
		addr, token, bound := strings.Cut(strings.TrimSpace(v), "\n")
		if !bound || strings.TrimSpace(addr) != a.callerAddr() {
			return nil
		}
		_, err = io.WriteString(a.stdout, strings.TrimSpace(token))
		return err
	case "store":
		b, err := io.ReadAll(io.LimitReader(a.stdin, 64<<10))
		if err != nil {
			return fmt.Errorf("read token: %w", err)
		}
		token := strings.TrimSpace(string(b))
		if token == "" {
			return a.forgetToken(store, key)
		}
		return a.storeToken(store, key, a.callerAddr(), token)
	case "erase":
		return a.forgetToken(store, key)
	}
	return fmt.Errorf("unknown token helper operation %q", op)
}
