package cli

import (
	"maps"
	"slices"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/eugene-panin/vctx/internal/config"
	"github.com/eugene-panin/vctx/internal/environ"
	"github.com/eugene-panin/vctx/internal/login"
	"github.com/eugene-panin/vctx/internal/probe"
	"github.com/eugene-panin/vctx/internal/shell"
	"github.com/eugene-panin/vctx/internal/token"
	"github.com/eugene-panin/vctx/internal/tui"
)

// ui runs the full-screen interface; picking a context with enter makes it the default.
func (a *app) ui() error {
	if !a.stdinTTY || !a.stdoutTTY {
		return usageError("the interactive UI needs a terminal; use 'vctx use <context>' to set the default")
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	var contexts []probe.Instance
	for _, name := range slices.Sorted(maps.Keys(cfg.Contexts)) {
		c, err := probe.Resolve(cfg, name, a.environ, a.home)
		if err != nil {
			return err
		}
		contexts = append(contexts, c)
	}
	timeout, err := a.checkTimeout()
	if err != nil {
		return err
	}
	logins := a.loginRunner(timeout)
	chosen, err := tui.Run(uiBackend{a, cfg, logins}, contexts, timeout, a.stdin, a.stdout)
	if err != nil || chosen == "" {
		return err
	}
	ctx, stop := login.Interruptible()
	defer stop()
	shell.Announce(a.environ, chosen)
	a.printUsing(chosen, cfg)
	logins.Ensure(ctx, cfg, chosen)
	return nil
}

// uiBackend serves the UI from the app and its loaded config.
type uiBackend struct {
	a      *app
	cfg    *config.Config
	logins *login.Runner
}

func (b uiBackend) Current() string {
	name, _ := b.a.contextName("")
	return name
}

func (b uiBackend) Use(name string) error            { return b.a.use(b.cfg, name) }
func (b uiBackend) LoginMethod(name string) []string { return b.logins.Method(b.cfg, name) }
func (b uiBackend) Getenv(key string) string         { return b.a.getenv(key) }

func (b uiBackend) TokenStatus(names []string) (map[string]token.State, error) {
	return b.a.tokenStatus(b.cfg, names)
}

func (b uiBackend) Forget(name string) error {
	store, err := b.a.tokens()
	if err != nil {
		return err
	}
	return store.Del(name)
}

func (b uiBackend) CommandEnv(vars map[string]string) ([]string, error) {
	vars = maps.Clone(vars)
	if err := token.RegisterHelper(vars, b.a.stateDir, b.a.self); err != nil {
		return nil, err
	}
	return environ.Apply(b.a.environ, vars), nil
}

func (b uiBackend) Login(name string) tea.ExecCommand {
	return b.logins.Cmd(b.cfg, name)
}
