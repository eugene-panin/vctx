package main

import (
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	envContext = "VCTX_CONTEXT"
	// envManaged lists non-VAULT_ variables exported by the active context,
	// so switching away from it in a shell can unset them.
	envManaged = "VCTX_VARS"
)

// contextVars returns every variable to set for context name, including vctx's own bookkeeping.
func (a *app) contextVars(cfg *config, name string) (map[string]string, error) {
	vars, err := cfg.vars(name, a.home)
	if err != nil {
		return nil, err
	}
	var extra []string
	for k := range vars {
		if !strings.HasPrefix(k, "VAULT_") {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		slices.Sort(extra)
		vars[envManaged] = strings.Join(extra, " ")
	}
	vars[envContext] = name
	if _, ok := vars["VAULT_CONFIG_PATH"]; !ok {
		p, err := a.writeVaultConfig()
		if err != nil {
			return nil, err
		}
		vars["VAULT_CONFIG_PATH"] = p
	}
	return vars, nil
}

// managedKeys returns the keys of environ that belong to whatever context was applied before.
func managedKeys(environ []string) map[string]bool {
	keys := make(map[string]bool)
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "VAULT_") || k == envContext || k == envManaged {
			keys[k] = true
		}
		if k == envManaged {
			for _, f := range strings.Fields(v) {
				keys[f] = true
			}
		}
	}
	return keys
}

func applyEnv(environ []string, vars map[string]string) []string {
	drop := managedKeys(environ)
	out := make([]string, 0, len(environ)+len(vars))
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if _, set := vars[k]; !set && !drop[k] {
			out = append(out, kv)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(vars)) {
		out = append(out, k+"="+vars[k])
	}
	return out
}

// writeShellEnv prints POSIX shell commands that turn environ into the environment applyEnv would build.
func writeShellEnv(w io.Writer, environ []string, vars map[string]string) {
	for _, k := range slices.Sorted(maps.Keys(managedKeys(environ))) {
		if _, ok := vars[k]; !ok {
			fmt.Fprintf(w, "unset %s\n", k)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(vars)) {
		fmt.Fprintf(w, "export %s=%s\n", k, shellQuote(vars[k]))
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// writeVaultConfig writes a Vault CLI config that uses this binary as the token helper.
func (a *app) writeVaultConfig() (string, error) {
	// Vault runs the helper through "sh -c '<path> <op>'".
	if strings.ContainsAny(a.self, " \t\n'\"\\$`;&|<>()*?[]") {
		return "", fmt.Errorf("vctx binary path %q is not usable as a vault token helper, move it to a plain path", a.self)
	}
	path := filepath.Join(a.stateDir, "vault.hcl")
	content := fmt.Sprintf("token_helper = %q\n", a.self)
	if b, err := os.ReadFile(path); err == nil && string(b) == content {
		return path, nil
	}
	if err := writeFileAtomic(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("write vault config: %w", err)
	}
	return path, nil
}

func writeFileAtomic(path string, data []byte, perm fs.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(f.Name())
		}
	}()
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
