package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	addr := a.getenv("VAULT_AGENT_ADDR")
	if addr == "" {
		addr = a.getenv("VAULT_ADDR")
	}
	if addr == "" {
		addr = defaultVaultAddr
	}
	return strings.TrimRight(addr, "/")
}

// tokenHelper implements the Vault token helper protocol:
// https://developer.hashicorp.com/vault/docs/commands/token-helper
//
// A stored value holds the address the token was issued for and the token,
// one per line, so a token is never handed to vault talking to another address.
// Vault shows the helper's stderr only when it exits non-zero, so a refusal is an error.
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
		switch {
		case !bound && strings.Contains(addr, "://"):
			return nil // an address with an empty token
		case !bound:
			return errors.New("the stored token predates address binding; log in again")
		case strings.TrimSpace(addr) != a.callerAddr():
			return fmt.Errorf("the stored token is for %s, not %s; log in again", strings.TrimSpace(addr), a.callerAddr())
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
			return store.del(key)
		}
		return store.set(key, a.callerAddr()+"\n"+token+"\n")
	case "erase":
		return store.del(key)
	}
	return fmt.Errorf("unknown token helper operation %q", op)
}
