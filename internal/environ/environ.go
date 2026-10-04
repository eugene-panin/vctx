// Package environ builds the environment the Vault CLI runs with for a context.
//
// It drops what the previous context set, gives back the user's own values,
// and applies the new context, for a child process or as shell commands.
package environ

import (
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/eugene-panin/vctx/internal/config"
)

const (
	// Context is the active context's name.
	Context = "VCTX_CONTEXT"
	// ContextAddr and ContextNS are the active context's address and
	// namespace, so the token helper can tell vault pointed elsewhere by hand
	// from vault talking to the context.
	ContextAddr = "VCTX_CONTEXT_ADDR"
	ContextNS   = "VCTX_CONTEXT_NAMESPACE"
	// managed lists non-VAULT_ variables the active context set, so switching
	// away from it can drop them or give back the values they replaced.
	managed = "VCTX_VARS"
)

// Value returns the first value of key in env, as getenv(3) and the Go runtime do.
func Value(env []string, key string) string {
	v, _ := lookup(env, key)
	return v
}

// lookup is os.LookupEnv over env.
func lookup(env []string, key string) (string, bool) {
	for _, kv := range env {
		if k, v, _ := strings.Cut(kv, "="); k == key {
			return v, true
		}
	}
	return "", false
}

// ContextVars returns every variable to set for context name, including vctx's own bookkeeping.
func ContextVars(cfg *config.Config, name, home string) (map[string]string, error) {
	vars, err := cfg.Vars(name, home)
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
		vars[managed] = strings.Join(extra, " ")
	}
	vars[Context] = name
	vars[ContextAddr] = config.NormalizeAddr(config.VaultAddr(vars))
	vars[ContextNS] = vars["VAULT_NAMESPACE"]
	return vars, nil
}

// savedPrefix keeps the user's own value of a non-VAULT variable a context
// overrides, so switching away from that context puts the value back.
const savedPrefix = "VCTX_SAVED_"

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
		case strings.HasPrefix(k, "VAULT_"), k == Context, k == ContextAddr, k == ContextNS, k == ChoiceFD, k == ChoiceFile:
			drop[k] = true
		case k == managed:
			drop[k] = true
			for _, f := range strings.Fields(v) {
				if overridable(f) {
					prev[f], drop[f] = true, true
				}
			}
		case strings.HasPrefix(k, savedPrefix):
			drop[k] = true
			if name := strings.TrimPrefix(k, savedPrefix); overridable(name) {
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
			orig, had = lookup(environ, k)
		}
		if had {
			set[savedPrefix+k] = orig
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
	return config.ValidKey(k) && !strings.HasPrefix(k, "VAULT_") && !strings.HasPrefix(k, "VCTX_")
}

// Apply returns environ turned into the environment for vars.
func Apply(environ []string, vars map[string]string) []string {
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

// WritePOSIX prints POSIX shell commands that turn environ into the environment Apply would build.
// The output is eval'd, so inherited names that are not plain identifiers are skipped.
func WritePOSIX(w io.Writer, environ []string, vars map[string]string) {
	p := planEnv(environ, vars)
	for _, k := range slices.Sorted(maps.Keys(p.unset)) {
		if config.ValidKey(k) {
			fmt.Fprintf(w, "unset %s\n", k)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(p.set)) {
		fmt.Fprintf(w, "export %s=%s\n", k, ShellQuote(p.set[k]))
	}
}

// ShellQuote quotes s for a POSIX shell.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// LookPath is exec.LookPath against the PATH the command will run with, which
// the context may set. Relative PATH entries are skipped where exec.LookPath
// would return exec.ErrDot.
func LookPath(file string, env []string) (string, error) {
	if strings.Contains(file, "/") {
		return exec.LookPath(file)
	}
	for _, dir := range filepath.SplitList(Value(env, "PATH")) {
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

// The shell function learns which context vctx switched to through
// ChoiceFD in zsh and bash: a descriptor feeding a command substitution,
// while vctx's own output still goes to the terminal; no temporary file to
// leave behind when Ctrl-C ends the function. fish, which cannot redirect
// like that, passes a temporary file in ChoiceFile instead. Nothing else
// changes the terminal's context.
const (
	ChoiceFD   = "VCTX_CHOICE_FD"
	ChoiceFile = "VCTX_CHOICE_FILE"
)

// WriteFish is WritePOSIX for fish.
func WriteFish(w io.Writer, environ []string, vars map[string]string) {
	p := planEnv(environ, vars)
	for _, k := range slices.Sorted(maps.Keys(p.unset)) {
		if config.ValidKey(k) {
			fmt.Fprintf(w, "set -e %s\n", k)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(p.set)) {
		fmt.Fprintf(w, "set -gx %s %s\n", k, FishQuote(p.set[k]))
	}
}

// FishQuote quotes s for fish.
func FishQuote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}
