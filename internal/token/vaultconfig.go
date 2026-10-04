package token

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/eugene-panin/vctx/internal/safefile"
)

// Older Vault versions run the token helper through "$SHELL -c '<path> <op>'",
// newer ones exec it directly; a path of these characters is safe either way.
var helperPathRe = regexp.MustCompile(`^[A-Za-z0-9/._+-]+$`)

// HelperPathOK reports whether vault can run path as its token helper.
func HelperPathOK(path string) bool { return helperPathRe.MatchString(path) }

// RegisterHelper points vault at vctx (self) as its token helper, unless the context
// brings its own Vault config. An empty VAULT_CONFIG_PATH counts as none: vault
// would fall back to ~/.vault and the shared ~/.vault-token.
func RegisterHelper(vars map[string]string, stateDir, self string) error {
	if vars["VAULT_CONFIG_PATH"] != "" {
		return nil
	}
	p, err := writeVaultConfig(stateDir, self)
	if err != nil {
		return err
	}
	vars["VAULT_CONFIG_PATH"] = p
	return nil
}

// writeVaultConfig writes a Vault CLI config that uses this binary as the token helper.
func writeVaultConfig(stateDir, self string) (string, error) {
	if !helperPathRe.MatchString(self) {
		return "", fmt.Errorf("vctx binary path %q is not usable as a vault token helper, move it to a plain path", self)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	fi, err := os.Stat(stateDir)
	if err != nil {
		return "", err
	}
	if err := safefile.CheckPrivate(stateDir, fi); err != nil {
		return "", err
	}
	path := filepath.Join(stateDir, "vault.hcl")
	content := fmt.Sprintf("token_helper = %q\n", self)
	if b, err := os.ReadFile(path); err == nil && string(b) == content {
		return path, nil
	}
	if err := safefile.Write(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("write vault config: %w", err)
	}
	return path, nil
}
