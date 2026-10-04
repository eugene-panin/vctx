package cli

import (
	"fmt"
	"slices"
	"strings"
)

// commandHelp is what 'vctx <command> -h' and 'vctx help <command>' print;
// the first line doubles as the usage error.
var commandHelp = map[string]string{
	"ui": `usage: vctx ui

Open the interactive UI: every context with its status, switch with enter,
l logs in, s opens a shell in the context, x forgets its token, r probes again.
'vctx' with no arguments does the same in a terminal.
`,
	"ls": `usage: vctx ls [--json]

List the contexts: * marks the active one, then the address, the namespace and
whether a token is stored ("stale" when it was issued for another address).

  --json   print a JSON array: name, address, namespace, token (none, ok,
           stale) and current
`,
	"use": `usage: vctx use [<context>]

Switch to <context>: it becomes the default for new terminals, and with the
shell integration ('vctx init') this terminal switches too. When the context
has no working token, vctx logs in, asking for the method the first time.
Without a name, opens the interactive UI.

Example:
  vctx use prod
`,
	"current": `usage: vctx current

Print the active context: $VCTX_CONTEXT of this shell, else the default set by
'vctx use'.
`,
	"env": `usage: vctx env [<context> | --default | --clear] [--shell posix|fish]

Print shell commands that switch the current shell to <context>, for shells
without the integration. --default uses the default context, --clear undoes it.

Examples:
  eval "$(vctx env prod)"
  vctx env prod --shell fish | source
`,
	"init": `usage: vctx init [--shell zsh|bash|fish]

Add one line to the rc file of your shell, so that 'vctx use' switches the
terminal it runs in and plain vault follows. The shell comes from $SHELL unless
--shell names it. Run once, then open a new terminal.

'vctx init <shell>' prints the integration that line loads.
`,
	"check": `usage: vctx check [--json] [<context>...]

Probe the given contexts, or all of them: reachability, Vault version and seal
status, through the same TLS and proxy settings as vault. Exits 1 when any
context is not usable.

  --json   print a JSON array: name, endpoint, usable, status, version and
           latency_ms (null when the probe failed)

Example:
  vctx check prod dev
`,
	"logout": `usage: vctx logout [<context>]

Forget the stored token of <context>, or of the active one. In a context shell
it forgets the token vault uses there, which differs when VAULT_ADDR was
changed by hand.
`,
	"exec": `usage: vctx exec [<context>] -- <command> [args...]

Run any command with the variables of <context>, or of the active one.

Example:
  vctx exec prod -- terraform plan
`,
	"version": `usage: vctx version

Print the vctx version.
`,
}

// commandUsage is the first line of the help of cmd.
func commandUsage(cmd string) usageError {
	first, _, _ := strings.Cut(commandHelp[cmd], "\n")
	return usageError(first + fmt.Sprintf(" (see 'vctx %s -h')", cmd))
}

// wantsHelp reports -h or --help among args, up to a "--" that starts a command.
func wantsHelp(args []string) bool {
	for _, arg := range args {
		switch arg {
		case "--":
			return false
		case "-h", "--help":
			return true
		}
	}
	return false
}

// suggest returns the candidate closest to word, if one is close enough to be a typo.
func suggest(word string, candidates []string) string {
	best, bestDist := "", 3
	if len(word) <= 4 {
		bestDist = 2
	}
	for _, c := range candidates {
		if strings.HasPrefix(c, "-") || slices.Contains([]string{"get", "store", "erase"}, c) {
			continue
		}
		if d := editDistance(word, c); d < bestDist {
			best, bestDist = c, d
		}
	}
	return best
}

// editDistance is the Levenshtein distance between a and b.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
