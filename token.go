package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

const defaultVaultAddr = "https://127.0.0.1:8200"

func isHelperOp(s string) bool {
	return s == "get" || s == "store" || s == "erase"
}

// tokenKey picks the token for the calling vault process: by context when
// vault was started through vctx, otherwise by address and namespace. The "_"
// prefix cannot start a context name, so the two kinds of keys never collide.
//
// In a shell set up with `vctx env`, VAULT_ADDR changed by hand points vault
// away from the context; its token then goes under the address key, so it
// neither replaces nor erases the context's own.
func (a *app) tokenKey() string {
	name, ctxAddr := a.getenv(envContext), a.getenv(envContextAddr)
	if nameRe.MatchString(name) && (ctxAddr == "" || ctxAddr == a.callerAddr()) {
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
// Tokens are stored with the address they were issued for and never handed to
// vault talking to another address. Such a token, or one stored without an
// address, is reported as missing rather than as an error: `vault login` asks
// for the current token first and would fail, leaving no way to replace it.
func (a *app) tokenHelper(op string) error {
	store, err := a.tokens()
	if err != nil {
		return err
	}
	key := a.tokenKey()
	switch op {
	case "get":
		token, addr, ok, err := store.get(key)
		if err != nil || !ok || addr != a.callerAddr() {
			return err
		}
		_, err = io.WriteString(a.stdout, token)
		return err
	case "store":
		const maxToken = 64 << 10
		b, err := io.ReadAll(io.LimitReader(a.stdin, maxToken+1))
		if err != nil {
			return fmt.Errorf("read token: %w", err)
		}
		if len(b) > maxToken {
			return fmt.Errorf("token larger than %d bytes", maxToken)
		}
		token := strings.TrimSpace(string(b))
		if token == "" {
			return store.del(key)
		}
		return store.set(key, token, a.callerAddr())
	case "erase":
		return store.del(key)
	}
	return fmt.Errorf("unknown token helper operation %q", op)
}
