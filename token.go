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

func (a *app) tokenPath(name string) string {
	return filepath.Join(a.stateDir, "tokens", name)
}

// tokenFile picks the token file for the calling vault process: by context when
// vault was started through vctx, otherwise by address and namespace.
func (a *app) tokenFile() string {
	if name := a.getenv(envContext); nameRe.MatchString(name) {
		return a.tokenPath(name)
	}
	addr := a.getenv("VAULT_ADDR")
	if addr == "" {
		addr = defaultVaultAddr
	}
	sum := sha256.Sum256([]byte(addr + "\x00" + a.getenv("VAULT_NAMESPACE")))
	return filepath.Join(a.stateDir, "tokens", "by-addr", hex.EncodeToString(sum[:12]))
}

// tokenHelper implements the Vault token helper protocol:
// https://developer.hashicorp.com/vault/docs/commands/token-helper
func (a *app) tokenHelper(op string) error {
	path := a.tokenFile()
	switch op {
	case "get":
		b, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = io.WriteString(a.stdout, strings.TrimSpace(string(b)))
		return err
	case "store":
		b, err := io.ReadAll(io.LimitReader(a.stdin, 64<<10))
		if err != nil {
			return fmt.Errorf("read token: %w", err)
		}
		return writeFileAtomic(path, []byte(strings.TrimSpace(string(b))), 0o600)
	case "erase":
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return fmt.Errorf("unknown token helper operation %q", op)
}
