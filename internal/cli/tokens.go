package cli

import (
	"github.com/eugene-panin/vctx/internal/config"
	"github.com/eugene-panin/vctx/internal/token"
)

// tokens is the token store VCTX_TOKEN_STORE selects.
func (a *app) tokens() (token.Store, error) {
	return token.Open(a.stateDir, a.getenv("VCTX_TOKEN_STORE"), a.keyring)
}

// tokenStatus reports the stored token of each context.
func (a *app) tokenStatus(cfg *config.Config, names []string) (map[string]token.State, error) {
	store, err := a.tokens()
	if err != nil {
		return map[string]token.State{}, err
	}
	return token.Status(store, cfg, a.home, names)
}

func (a *app) tokenHelper(op string) error {
	store, err := a.tokens()
	if err != nil {
		return err
	}
	return token.Helper(op, a.environ, store, a.stdin, a.stdout)
}
