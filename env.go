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
	// envContextAddr and envContextNS are the active context's address and
	// namespace, so the token helper can tell vault pointed elsewhere by hand
	// from vault talking to the context.
	envContextAddr = "VCTX_CONTEXT_ADDR"
	envContextNS   = "VCTX_CONTEXT_NAMESPACE"
	// envManaged lists non-VAULT_ variables the active context set, so switching
	// away from it can drop them or give back the values they replaced.
	envManaged = "VCTX_VARS"
)

// Older Vault versions run the token helper through "$SHELL -c '<path> <op>'",
// newer ones exec it directly; a path of these characters is safe either way.
var helperPathRe = regexp.MustCompile(`^[A-Za-z0-9/._+-]+$`)

// envValue returns the first value of key in env, as getenv(3) and the Go runtime do.
func envValue(env []string, key string) string {
	v, _ := lookupEnv(env, key)
	return v
}

// lookupEnv is os.LookupEnv over env.
func lookupEnv(env []string, key string) (string, bool) {
	for _, kv := range env {
		if k, v, _ := strings.Cut(kv, "="); k == key {
			return v, true
		}
	}
	return "", false
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
	vars[envContextAddr] = normalizeAddr(vaultAddr(vars))
	vars[envContextNS] = vars["VAULT_NAMESPACE"]
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

// envSavedPrefix keeps the user's own value of a non-VAULT variable a context
// overrides, so switching away from that context puts the value back.
const envSavedPrefix = "VCTX_SAVED_"

// envPlan turns an inherited environment into the one for a context.
type envPlan struct {
	set   map[string]string
	unset map[string]bool // inherited keys to drop that set does not replace
}

// planEnv drops whatever the previous context set, restores the user's values
// it had overridden, and applies vars, saving the values vars overrides now.
func planEnv(environ []string, vars map[string]string) envPlan {
	prev := map[string]bool{} // non-VAULT keys the previous context set
	saved := map[string]string{}
	drop := map[string]bool{}
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		switch {
		case strings.HasPrefix(k, "VAULT_"), k == envContext, k == envContextAddr, k == envContextNS, k == envChoiceFile:
			drop[k] = true
		case k == envManaged:
			drop[k] = true
			for _, f := range strings.Fields(v) {
				if overridable(f) {
					prev[f], drop[f] = true, true
				}
			}
		case strings.HasPrefix(k, envSavedPrefix):
			drop[k] = true
			if name := strings.TrimPrefix(k, envSavedPrefix); overridable(name) {
				if _, dup := saved[name]; !dup {
					saved[name] = v
				}
			}
		}
	}

	set := make(map[string]string, len(vars))
	maps.Copy(set, vars)
	for k := range vars {
		if !overridable(k) {
			continue
		}
		orig, had := saved[k]
		if !prev[k] {
			orig, had = lookupEnv(environ, k)
		}
		if had {
			set[envSavedPrefix+k] = orig
		}
	}
	for k := range prev {
		if v, ok := saved[k]; ok {
			if _, replaced := set[k]; !replaced {
				set[k] = v
			}
		}
	}

	unset := map[string]bool{}
	for k := range drop {
		if _, ok := set[k]; !ok {
			unset[k] = true
		}
	}
	return envPlan{set: set, unset: unset}
}

// overridable reports a variable whose user value a context may replace and
// vctx gives back later; VAULT_* and vctx's own variables are always dropped.
func overridable(k string) bool {
	return envKeyRe.MatchString(k) && !strings.HasPrefix(k, "VAULT_") && !strings.HasPrefix(k, "VCTX_")
}

func applyEnv(environ []string, vars map[string]string) []string {
	p := planEnv(environ, vars)
	out := make([]string, 0, len(environ)+len(p.set))
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if _, replaced := p.set[k]; !replaced && !p.unset[k] {
			out = append(out, kv)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(p.set)) {
		out = append(out, k+"="+p.set[k])
	}
	return out
}

// writeShellEnv prints POSIX shell commands that turn environ into the environment applyEnv would build.
// The output is eval'd, so inherited names that are not plain identifiers are skipped.
func writeShellEnv(w io.Writer, environ []string, vars map[string]string) {
	p := planEnv(environ, vars)
	for _, k := range slices.Sorted(maps.Keys(p.unset)) {
		if envKeyRe.MatchString(k) {
			fmt.Fprintf(w, "unset %s\n", k)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(p.set)) {
		fmt.Fprintf(w, "export %s=%s\n", k, shellQuote(p.set[k]))
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// lookPath is exec.LookPath against the PATH the command will run with, which
// the context may set. Relative PATH entries are skipped where exec.LookPath
// would return exec.ErrDot.
func lookPath(file string, env []string) (string, error) {
	if strings.Contains(file, "/") {
		return exec.LookPath(file)
	}
	for _, dir := range filepath.SplitList(envValue(env, "PATH")) {
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
