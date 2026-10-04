package cli

import (
	"time"

	"github.com/eugene-panin/vctx/internal/login"
)

// loginRunner is what the login package needs to know about this run of vctx;
// timeout is the probe timeout, from checkTimeout.
func (a *app) loginRunner(timeout time.Duration) *login.Runner {
	return &login.Runner{
		Environ:     a.environ,
		Home:        a.home,
		StateDir:    a.stateDir,
		Self:        a.self,
		VaultBin:    a.vaultBin(),
		Timeout:     timeout,
		Tokens:      a.tokens,
		In:          a.stdin,
		Out:         a.stderr,
		Interactive: a.stdinTTY && a.stderrTTY && !a.noInput,
		NoAsk:       a.noAsk(),
		NoColor:     a.noColor,
	}
}

// noAsk says why vctx asks nothing, if it does not.
func (a *app) noAsk() string {
	if a.noInput {
		return "--no-input"
	}
	if !a.stdinTTY || !a.stderrTTY {
		return "no terminal"
	}
	return ""
}
