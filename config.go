package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

type config struct {
	Defaults map[string]string            `yaml:"defaults"`
	Contexts map[string]map[string]string `yaml:"contexts"`
}

var (
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

	// Context names double as subcommands ("vctx prod ..."), so they must not shadow real ones.
	reservedNames = []string{"help", "ui", "ls", "list", "use", "current", "env", "exec", "check", "logout", "get", "store", "erase"}
)

func loadConfig(path string) (*config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := checkPrivate(path); err != nil {
		return nil, err
	}
	var c config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(c.Contexts) == 0 {
		return nil, fmt.Errorf("%s: no contexts defined", path)
	}
	if err := checkVars(c.Defaults); err != nil {
		return nil, fmt.Errorf("%s: defaults: %w", path, err)
	}
	for _, name := range slices.Sorted(maps.Keys(c.Contexts)) {
		vars := c.Contexts[name]
		if !nameRe.MatchString(name) || slices.Contains(reservedNames, name) {
			return nil, fmt.Errorf("%s: invalid context name %q", path, name)
		}
		if err := checkVars(vars); err != nil {
			return nil, fmt.Errorf("%s: context %s: %w", path, name, err)
		}
		if vars["VAULT_ADDR"] == "" {
			return nil, fmt.Errorf("%s: context %s: VAULT_ADDR is required", path, name)
		}
	}
	return &c, nil
}

// checkPrivate refuses a file or directory another user could modify, as ssh does:
// the config decides which variables (PATH included) vault runs with, and the
// state directory holds the token helper setting vault executes.
func checkPrivate(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others (mode %04o), fix with: chmod go-w %s", path, perm, path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by another user", path)
	}
	return nil
}

func checkVars(vars map[string]string) error {
	for _, k := range slices.Sorted(maps.Keys(vars)) {
		if !envKeyRe.MatchString(k) {
			return fmt.Errorf("invalid variable name %q", k)
		}
		if strings.HasPrefix(k, "VCTX_") {
			return fmt.Errorf("variable %s is reserved", k)
		}
	}
	return nil
}

// vars returns the variables of context name merged over the defaults, with a leading ~/ expanded.
func (c *config) vars(name, home string) (map[string]string, error) {
	ctx, ok := c.Contexts[name]
	if !ok {
		return nil, fmt.Errorf("unknown context %q", name)
	}
	out := make(map[string]string, len(c.Defaults)+len(ctx))
	for k, v := range c.Defaults {
		out[k] = expandHome(v, home)
	}
	for k, v := range ctx {
		out[k] = expandHome(v, home)
	}
	return out, nil
}

func expandHome(v, home string) string {
	if rest, ok := strings.CutPrefix(v, "~/"); ok {
		return filepath.Join(home, rest)
	}
	return v
}
