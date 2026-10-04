package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// loginFlags are the only vault login flags a login setting may carry: the
// others either change the server, namespace or output (-address, -namespace,
// -no-print=false, -output-curl-string) or carry a secret (-header, -mfa).
var loginFlags = []string{"method", "path"}

// secretKeyParts mark key=value arguments that carry a credential; vault asks
// for those itself, and the config is no place for them.
var secretKeyParts = []string{"secret", "password", "passcode", "token", "key", "jwt", "totp", "credential"}

// secretKey reports a key=value argument that carries a credential. A path or
// file naming one (keytab_path, krb5conf_path) is not a secret itself.
func secretKey(key string) bool {
	lower := strings.ToLower(key)
	if strings.HasSuffix(lower, "_path") || strings.HasSuffix(lower, "_file") {
		return false
	}
	for _, part := range secretKeyParts {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}

// LoginArgs splits the login setting of a context into `vault login`
// arguments, the way a shell would for simple quoting, and checks them.
func LoginArgs(s string) ([]string, error) {
	args, err := splitArgs(s)
	if err != nil {
		return nil, err
	}
	return NormalizeLoginArgs(args)
}

// NormalizeLoginArgs checks login arguments and writes each flag as
// -name=value. Flags must come first: vault ignores them after key=value.
func NormalizeLoginArgs(args []string) ([]string, error) {
	var out []string
	seenKV := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			if seenKV {
				return nil, fmt.Errorf("%s: put flags before key=value arguments, vault ignores them after", arg)
			}
			name, value, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
			if !slices.Contains(loginFlags, name) {
				return nil, fmt.Errorf("%s: only -method and -path are allowed here", arg)
			}
			if !hasValue && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && !strings.Contains(args[i+1], "=") {
				i++
				value = args[i]
			}
			if value == "" {
				return nil, fmt.Errorf("-%s needs a value", name)
			}
			out = append(out, "-"+name+"="+value)
			continue
		}
		key, _, hasValue := strings.Cut(arg, "=")
		if !hasValue {
			return nil, fmt.Errorf("%q: write -flag=value or key=value; vault would take a bare word as a token", arg)
		}
		if secretKey(key) {
			return nil, fmt.Errorf("%s= looks like a secret; leave it out, vault asks for it", key)
		}
		seenKV = true
		out = append(out, arg)
	}
	return out, nil
}

// splitArgs splits s at white space (newlines included) outside single or double quotes.
func splitArgs(s string) ([]string, error) {
	var args []string
	var cur strings.Builder
	var quote rune
	inArg := false
	for _, r := range s {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote != 0:
			cur.WriteRune(r)
		case r == '\'' || r == '"':
			quote, inArg = r, true
		case unicode.IsSpace(r):
			if inArg {
				args = append(args, cur.String())
				cur.Reset()
				inArg = false
			}
		default:
			cur.WriteRune(r)
			inArg = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if inArg {
		args = append(args, cur.String())
	}
	return args, nil
}
