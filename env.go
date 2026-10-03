package main

import (
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const (
	envContext = "VCTX_CONTEXT"
	// envManaged lists non-VAULT_ variables exported by the active context,
	// so switching away from it in a shell can unset them.
	envManaged = "VCTX_VARS"
)

// Older Vault versions run the token helper through "$SHELL -c '<path> <op>'",
// newer ones exec it directly; a path of these characters is safe either way.
var helperPathRe = regexp.MustCompile(`^[A-Za-z0-9/._+-]+$`)

func lookupEnv(env []string, key string) string {
	for _, kv := range slices.Backward(env) {
		if k, v, _ := strings.Cut(kv, "="); k == key {
			return v
		}
	}
	return ""
}

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
	return vars, nil
}

// registerHelper points vault at vctx as its token helper, unless the context brings its own Vault config.
func (a *app) registerHelper(vars map[string]string) error {
	if _, ok := vars["VAULT_CONFIG_PATH"]; ok {
		return nil
	}
	p, err := a.writeVaultConfig()
	if err != nil {
		return err
	}
	vars["VAULT_CONFIG_PATH"] = p
	return nil
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
// The output is eval'd, so inherited names that are not plain identifiers are skipped.
func writeShellEnv(w io.Writer, environ []string, vars map[string]string) {
	for _, k := range slices.Sorted(maps.Keys(managedKeys(environ))) {
		if _, ok := vars[k]; !ok && envKeyRe.MatchString(k) {
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

// lookPath is exec.LookPath against the PATH the command will run with, which
// the context may set. Relative PATH entries are skipped, as exec.LookPath does.
func lookPath(file string, env []string) (string, error) {
	if strings.Contains(file, "/") {
		return exec.LookPath(file)
	}
	for _, dir := range filepath.SplitList(lookupEnv(env, "PATH")) {
		if !filepath.IsAbs(dir) {
			continue
		}
		p := filepath.Join(dir, file)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: %w", file, exec.ErrNotFound)
}

// writeVaultConfig writes a Vault CLI config that uses this binary as the token helper.
func (a *app) writeVaultConfig() (string, error) {
	if !helperPathRe.MatchString(a.self) {
		return "", fmt.Errorf("vctx binary path %q is not usable as a vault token helper, move it to a plain path", a.self)
	}
	if err := os.MkdirAll(a.stateDir, 0o700); err != nil {
		return "", err
	}
	fi, err := os.Stat(a.stateDir)
	if err != nil {
		return "", err
	}
	if err := checkPrivate(a.stateDir, fi); err != nil {
		return "", err
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
