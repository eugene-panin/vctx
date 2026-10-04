package cli

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/eugene-panin/vctx/internal/login"
	"github.com/eugene-panin/vctx/internal/shell"
	"github.com/spf13/cobra"
)

const rootExample = `  vctx use prod                 switch this terminal to prod, logging in if needed
  vault kv get secret/app       plain vault follows (after 'vctx init' once)
  vctx dev kv get secret/app    one command against dev, without switching
  vctx check                    which instances are reachable`

// rootDetails ends the top-level help: what the commands have in common.
const rootDetails = `Any word that is not a command is a context: 'vctx <context> [vault args...]'
runs vault against it, every argument after the name going to vault as is.
Without a name, a command uses $VCTX_CONTEXT, then the default set by 'vctx use'.

Config: $VCTX_CONFIG or $XDG_CONFIG_HOME/vctx/config.yaml (~/.config by default)

  defaults:                  # applied to every context
    VAULT_FORMAT: json
  contexts:
    dev:
      VAULT_ADDR: https://vault.dev.example.com:8200
      VAULT_SKIP_VERIFY: "true"
      login: -method=userpass username=me
    prod:
      VAULT_ADDR: https://vault.example.com:8200
      VAULT_NAMESPACE: admin
      VAULT_CACERT: ~/certs/prod-ca.pem
      login: -method=oidc -path=sso

When a context has no working token, 'vctx use' and the UI log in. The method
comes from 'login' (not a variable: the arguments for 'vault login'), or from
the answers vctx asked for the first time and remembers once the login works
($VCTX_STATE_DIR/login/<context>.json; a failed login offers to pick again).
vault itself asks for the password or opens the browser, so no secret is kept.

Before running a command vctx calls the unauthenticated sys/health endpoint,
so a VPN or tunnel that is down, or an ingress rejecting your IP, fails in
seconds. VCTX_CHECK_TIMEOUT sets the timeout (default 3s); 0 skips the check
before commands, while 'vctx check' and the UI still probe, with 3s.

Inherited VAULT_* variables are dropped before a context is applied, so an
address or token of one instance never leaks into another. vctx refuses vault's
-address and -agent-address flags: the token helper cannot see them and would
hand the context's token to that server. In a shell set up with 'vctx env'
nothing stops them, so do not pass them there. Other variables a context sets,
PATH or HTTPS_PROXY say, get your own values back when you switch away.

Tokens from 'vault login' are stored per context and bound to the address
they were issued for: in the macOS Keychain by default, elsewhere in files
under $VCTX_STATE_DIR/tokens (default $XDG_STATE_HOME/vctx, that is
~/.local/state/vctx); VCTX_TOKEN_STORE=file or keychain chooses. The
Keychain keeps tokens off disk and out of backups, but like a 0600 file it
does not hide them from other programs running as you. vctx sets
VAULT_CONFIG_PATH to a generated config that registers vctx itself as the
Vault token helper.

The config and the state directory must not be writable by other users.

Environment:
  VCTX_CONFIG         config file
  VCTX_STATE_DIR      tokens, default context, generated Vault config
  VCTX_TOKEN_STORE    file or keychain
  VCTX_CHECK_TIMEOUT  reachability check timeout, 0 skips it before commands
  VCTX_VAULT_BIN      vault binary to run (default: vault on PATH)
  VCTX_CONTEXT        set for vault and in a 'vctx env' shell: the context
                      (with VCTX_CONTEXT_ADDR, VCTX_CONTEXT_NAMESPACE,
                      VCTX_VARS, VCTX_SAVED_*)
  NO_COLOR            no colors (also --no-color)

Exit status: 0 on success, 1 on failure, 2 for a malformed command line.

Docs and issues: https://github.com/eugene-panin/vctx`

// helpTemplate leads with the description, then usage with examples first,
// then whatever a command adds in its "details" annotation.
const helpTemplate = `{{with (or .Long .Short)}}{{. | trimTrailingWhitespaces}}

{{end}}{{.UsageString}}{{with index .Annotations "details"}}
{{.}}
{{end}}`

const usageTemplate = `{{if .HasExample}}Examples:
{{.Example}}

{{end}}Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} <command>{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasAvailableSubCommands}}

Commands:{{range .Commands}}{{if .IsAvailableCommand}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableSubCommands}}

'{{.CommandPath}} <command> -h' shows the help of a command.{{end}}
`

// rootCmd builds the command tree; rawArgs are the arguments it will run
// with, for help to win over flag errors.
func (a *app) rootCmd(rawArgs []string) *cobra.Command {
	cobra.EnableCommandSorting = false // the order below: most used first
	root := &cobra.Command{
		Use:     "vctx [flags] [<context> [vault args...]]",
		Short:   "Switch between several Vault instances by environment variables",
		Long:    "vctx - switch between several Vault instances by environment variables.",
		Example: rootExample,
		Version: a.version,
		// A word that is no command is a context; the dispatch is in root.
		Args:              cobra.ArbitraryArgs,
		ValidArgsFunction: a.completeContexts(1),
		Annotations:       map[string]string{"details": rootDetails},
		SilenceUsage:      true,
		SilenceErrors:     true,
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) == 0 {
				if a.stdinTTY && a.stdoutTTY && !a.noInput {
					return a.ui()
				}
				return c.Help()
			}
			return a.runContext(args[0], args[1:])
		},
	}
	// After the context name every argument belongs to vault, -h included.
	root.Flags().SetInterspersed(false)
	// Declared before cobra adds its own, so --version gets no -v shorthand.
	root.Flags().Bool("version", false, "print the vctx version")
	root.PersistentFlags().BoolVar(&a.noInput, "no-input", false, "never ask anything; skip logging in when it would need answers")
	root.PersistentFlags().BoolVar(&a.noColor, "no-color", false, "no colors")
	root.SetVersionTemplate("vctx {{.Version}}\n")
	root.SetHelpTemplate(helpTemplate)
	root.SetUsageTemplate(usageTemplate)
	root.SetFlagErrorFunc(helpWins(rawArgs))
	root.AddCommand(
		a.useCmd(), a.lsCmd(), a.checkCmd(), a.currentCmd(), a.execCmd(), a.envCmd(),
		a.initCmd(), a.logoutCmd(), a.uiCmd(), a.versionCmd(),
		a.helperCmd("get"), a.helperCmd("store"), a.helperCmd("erase"),
	)
	return root
}

// commandNames are the names and aliases of every subcommand, hidden ones and
// cobra's own included: context names must not shadow them.
func (a *app) commandNames() []string {
	// On a copy: defining the flags again would reset the ones already parsed.
	scratch := *a
	root := scratch.rootCmd(nil)
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	var names []string
	for _, c := range root.Commands() {
		names = append(names, c.Name())
		names = append(names, c.Aliases...)
	}
	return names
}

// maxArgs rejects more than n arguments, and flags where arguments go.
func maxArgs(n int) cobra.PositionalArgs {
	return func(c *cobra.Command, args []string) error {
		if len(args) > n {
			return usageFor(c)
		}
		return nil
	}
}

// usageFor is the usage error of c: its usage line and where to read more.
func usageFor(c *cobra.Command) usageError {
	return usageError(fmt.Sprintf("usage: %s (see '%s -h')", c.UseLine(), c.CommandPath()))
}

// completeContexts completes context names for the first n arguments.
func (a *app) completeContexts(n int) cobra.CompletionFunc {
	return func(c *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if n >= 0 && len(args) >= n {
			return nil, cobra.ShellCompDirectiveDefault
		}
		cfg, err := a.loadConfig()
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		names := slices.DeleteFunc(slices.Sorted(maps.Keys(cfg.Contexts)), func(name string) bool {
			return slices.Contains(args, name)
		})
		return names, cobra.ShellCompDirectiveNoFileComp
	}
}

func (a *app) useCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use [<context>]",
		Short: "Switch to a context, logging in if needed",
		Long: `Switch to <context>: it becomes the default for new terminals, and with the
shell integration ('vctx init') this terminal switches too. When the context
has no working token, vctx logs in, asking for the method the first time.
Without a name, opens the interactive UI.`,
		Example:           "  vctx use prod",
		Args:              maxArgs(1),
		ValidArgsFunction: a.completeContexts(1),
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) == 0 {
				return a.ui()
			}
			return a.switchTo(args[0])
		},
	}
}

func (a *app) lsCmd() *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List contexts",
		Long: `List the contexts: * marks the active one, then the address, the namespace and
whether a token is stored ("stale" when it was issued for another address).`,
		Args: maxArgs(0),
		RunE: func(*cobra.Command, []string) error { return a.list(asJSON) },
	}
	c.Flags().BoolVar(&asJSON, "json", false, "print a JSON array: name, address, namespace, token (none, ok, stale), current")
	return c
}

func (a *app) checkCmd() *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "check [<context>...]",
		Short: "Show reachability, version and seal status",
		Long: `Probe the given contexts, or all of them: reachability, Vault version and seal
status, through the same TLS and proxy settings as vault. Exits 1 when any
context is not usable.`,
		Example:           "  vctx check\n  vctx check prod dev --json",
		ValidArgsFunction: a.completeContexts(-1),
		RunE:              func(_ *cobra.Command, args []string) error { return a.check(args, asJSON) },
	}
	c.Flags().BoolVar(&asJSON, "json", false, "print a JSON array: name, endpoint, usable, status, version, latency_ms")
	return c
}

func (a *app) currentCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "current",
		Short: "Print the active context",
		Long:  "Print the active context: $VCTX_CONTEXT of this shell, else the default set by 'vctx use'.",
		Args:  maxArgs(0),
		RunE: func(*cobra.Command, []string) error {
			name, err := a.contextName("")
			if err != nil {
				return err
			}
			fmt.Fprintln(a.stdout, name)
			return nil
		},
	}
}

func (a *app) execCmd() *cobra.Command {
	c := &cobra.Command{
		Use:               "exec [flags] [<context>] -- <command> [args...]",
		Short:             "Run any command with the variables of a context",
		Long:              "Run any command with the variables of <context>, or of the active one.",
		Example:           "  vctx exec prod -- terraform plan",
		ValidArgsFunction: a.completeContexts(1),
		RunE: func(c *cobra.Command, args []string) error {
			// Flag parsing stops at the context name, so a "--" after it is
			// still among the arguments; one before it is not.
			var name string
			if c.ArgsLenAtDash() != 0 && len(args) > 0 {
				name, args = args[0], args[1:]
				if len(args) > 0 && args[0] == "--" {
					args = args[1:]
				}
			}
			if len(args) == 0 {
				return usageFor(c)
			}
			return a.execIn(name, args)
		},
	}
	// The command's own flags are not vctx's.
	c.Flags().SetInterspersed(false)
	return c
}

func (a *app) envCmd() *cobra.Command {
	var fromDefault, clear bool
	var sh string
	c := &cobra.Command{
		Use:   "env [<context>]",
		Short: "Print exports for a shell without the integration",
		Long: `Print shell commands that switch the current shell to <context>, for shells
without the integration ('vctx init'). --default uses the default context,
--clear undoes the switch.`,
		Example:           "  eval \"$(vctx env prod)\"\n  vctx env prod --shell fish | source\n  eval \"$(vctx env --clear)\"",
		Args:              maxArgs(1),
		ValidArgsFunction: a.completeContexts(1),
		RunE: func(c *cobra.Command, args []string) error {
			var name string
			if len(args) == 1 {
				name = args[0]
			}
			switch {
			case sh != "posix" && sh != "fish":
				return usageError(fmt.Sprintf("--shell is posix or fish, not %q (see 'vctx env -h')", sh))
			case clear && (name != "" || fromDefault):
				return usageError("--clear does not go with a context or --default (see 'vctx env -h')")
			case name != "" && fromDefault:
				return usageError("a context does not go with --default (see 'vctx env -h')")
			}
			return a.env(name, fromDefault, clear, sh == "fish")
		},
	}
	c.Flags().BoolVar(&fromDefault, "default", false, "use the default context, whatever this shell has")
	c.Flags().BoolVar(&clear, "clear", false, "print commands that undo the switch")
	c.Flags().StringVar(&sh, "shell", "posix", "shell syntax: posix or fish")
	_ = c.RegisterFlagCompletionFunc("shell", cobra.FixedCompletions([]string{"posix", "fish"}, cobra.ShellCompDirectiveNoFileComp))
	return c
}

func (a *app) initCmd() *cobra.Command {
	var sh string
	c := &cobra.Command{
		Use:   "init [<shell>]",
		Short: "Set up zsh, bash or fish once, so 'vctx use' switches the terminal",
		Long: `Add one line to the rc file of your shell, so that 'vctx use' switches the
terminal it runs in and plain vault follows. The shell comes from $SHELL unless
--shell names it. Run once, then open a new terminal.

'vctx init <shell>' prints the integration that line loads.`,
		Example:   "  vctx init\n  vctx init --shell fish",
		Args:      maxArgs(1),
		ValidArgs: []string{"zsh", "bash", "fish"},
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) == 1 {
				if sh != "" {
					return usageFor(c)
				}
				return asShellUsage(a.shellSetup().Print(args[0], a.stdout))
			}
			return a.initShell(sh)
		},
	}
	c.Flags().StringVar(&sh, "shell", "", "the shell to set up: zsh, bash or fish (default: from $SHELL)")
	_ = c.RegisterFlagCompletionFunc("shell", cobra.FixedCompletions([]string{"zsh", "bash", "fish"}, cobra.ShellCompDirectiveNoFileComp))
	return c
}

func (a *app) logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout [<context>]",
		Short: "Forget the stored token of a context",
		Long: `Forget the stored token of <context>, or of the active one. In a context shell
it forgets the token vault uses there, which differs when VAULT_ADDR was
changed by hand.`,
		Args:              maxArgs(1),
		ValidArgsFunction: a.completeContexts(1),
		RunE: func(_ *cobra.Command, args []string) error {
			var name string
			if len(args) == 1 {
				name = args[0]
			}
			return a.logout(name)
		},
	}
}

func (a *app) uiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ui",
		Short: "Open the interactive UI",
		Long: `Open the interactive UI: every context with its status, switch with enter,
l logs in, s opens a shell in the context, x forgets its token, r probes again.
'vctx' with no arguments does the same in a terminal.`,
		Args: maxArgs(0),
		RunE: func(*cobra.Command, []string) error { return a.ui() },
	}
}

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the vctx version",
		Args:  maxArgs(0),
		RunE: func(*cobra.Command, []string) error {
			fmt.Fprintln(a.stdout, "vctx", a.version)
			return nil
		},
	}
}

// helperCmd is a Vault token helper operation: vault runs 'vctx get'.
func (a *app) helperCmd(op string) *cobra.Command {
	return &cobra.Command{
		Use:    op,
		Short:  "Vault token helper: " + op,
		Hidden: true,
		Args:   maxArgs(0),
		RunE:   func(*cobra.Command, []string) error { return a.tokenHelper(op) },
	}
}

// switchTo is 'vctx use <name>'.
func (a *app) switchTo(name string) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	timeout, err := a.checkTimeout()
	if err != nil {
		return err
	}
	ctx, stop := login.Interruptible()
	defer stop()
	if err := a.use(cfg, name); err != nil {
		return err
	}
	shell.Announce(a.environ, name)
	a.printUsing(name, cfg)
	if errors.Is(a.loginRunner(timeout).Ensure(ctx, cfg, name), login.ErrCancelled) {
		return errInterrupted
	}
	return nil
}

// runContext is 'vctx <name> [vault args...]'.
func (a *app) runContext(name string, args []string) error {
	cfg, err := a.loadConfig()
	if err != nil {
		if s := suggest(name, a.commandNames()); s != "" {
			return usageError(fmt.Sprintf("unknown command %q, did you mean %q?", name, s))
		}
		return err
	}
	if _, ok := cfg.Contexts[name]; !ok {
		if s := suggest(name, append(slices.Sorted(maps.Keys(cfg.Contexts)), a.commandNames()...)); s != "" {
			return usageError(fmt.Sprintf("unknown command or context %q, did you mean %q?", name, s))
		}
		return usageError(fmt.Sprintf("unknown command or context %q, see 'vctx help'", name))
	}
	return a.execWith(cfg, name, append([]string{a.vaultBin()}, args...))
}
