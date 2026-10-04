package token

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/eugene-panin/vctx/internal/config"
	"github.com/eugene-panin/vctx/internal/environ"
)

// IsHelperOp reports whether s is a token helper operation vault calls vctx with.
func IsHelperOp(s string) bool {
	return s == "get" || s == "store" || s == "erase"
}

// Key picks the token for the vault process running with env: by context when
// vault was started through vctx, otherwise by address and namespace. The "_"
// prefix cannot start a context name, so the two kinds of keys never collide.
//
// In a shell set up with `vctx env`, VAULT_ADDR or VAULT_NAMESPACE changed by
// hand points vault away from the context; its token then goes under the
// address key, so it neither replaces nor erases the context's own. Shells set
// up by a vctx without VCTX_CONTEXT_ADDR always use the context name.
func Key(env []string) string {
	get := func(k string) string { return environ.Value(env, k) }
	name, ctxAddr := get(environ.Context), get(environ.ContextAddr)
	ownContext := ctxAddr == "" ||
		ctxAddr == callerAddr(env) && get(environ.ContextNS) == get("VAULT_NAMESPACE")
	if config.ValidName(name) && ownContext {
		return name
	}
	sum := sha256.Sum256([]byte(callerAddr(env) + "\x00" + get("VAULT_NAMESPACE")))
	return "_addr/" + hex.EncodeToString(sum[:12])
}

// callerAddr is the address the vault process running with env talks to.
func callerAddr(env []string) string {
	addr, _ := config.AddrFrom(func(k string) string { return environ.Value(env, k) })
	return config.NormalizeAddr(addr)
}

// Helper runs one operation of the Vault token helper protocol for the vault
// process running with env:
// https://developer.hashicorp.com/vault/docs/commands/token-helper
//
// Tokens are stored with the address they were issued for and never handed to
// vault talking to another address. Such a token, or one stored without an
// address, is reported as missing rather than as an error: `vault login` asks
// for the current token first and would fail, leaving no way to replace it.
func Helper(op string, env []string, s Store, in io.Reader, out io.Writer) error {
	key := Key(env)
	switch op {
	case "get":
		token, addr, ok, err := s.Get(key)
		if err != nil || !ok || addr != callerAddr(env) {
			return err
		}
		_, err = io.WriteString(out, token)
		return err
	case "store":
		const maxToken = 64 << 10
		b, err := io.ReadAll(io.LimitReader(in, maxToken+1))
		if err != nil {
			return fmt.Errorf("read token: %w", err)
		}
		if len(b) > maxToken {
			return fmt.Errorf("token larger than %d bytes", maxToken)
		}
		token := strings.TrimSpace(string(b))
		if token == "" {
			return s.Del(key)
		}
		return s.Set(key, token, callerAddr(env))
	case "erase":
		return s.Del(key)
	}
	return fmt.Errorf("unknown token helper operation %q", op)
}
