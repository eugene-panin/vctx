package cli

import (
	"context"

	"github.com/eugene-panin/vctx/internal/config"
	"github.com/eugene-panin/vctx/internal/login"
)

// loginRunner is what the login package needs to know about this run of vctx.
func (a *app) loginRunner() *login.Runner {
	timeout, _ := a.checkTimeout()
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
		Interactive: a.stdinTTY && a.stderrTTY,
	}
}

func (a *app) ensureLogin(ctx context.Context, cfg *config.Config, name string) {
	a.loginRunner().Ensure(ctx, cfg, name)
}

func (a *app) loginFor(cfg *config.Config, name string) []string {
	return a.loginRunner().For(cfg, name)
}
