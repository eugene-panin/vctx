# vctx

I work with several Vault instances: a few clients, each with its own Vault,
some of them reachable only over Tailscale or WireGuard. The Vault CLI knows
about one server at a time: `VAULT_ADDR`, `VAULT_NAMESPACE`, a CA file, and a
single token in `~/.vault-token`. Switching between instances meant re-exporting
variables and logging in again, and once in a while running a command against
the wrong server with the wrong token. vctx fixes that.

Each Vault instance is a named context: a set of environment variables in one
config file. `vctx use prod` switches the current terminal to it, and plain
`vault` works from then on. Every context keeps its own token, bound to the
address it was issued for. When there is no token yet or it has expired, vctx
runs `vault login` for you.

```
$ vctx check
client   vault.client.example:443     unreachable: timed out
dev      vault.dev.example.com:8200   ok 1.20.4 active 41ms
prod     vault.example.com:8200       ok 1.20.4 active 38ms
vctx: 1 of 3 contexts not usable
```

## Install

With Homebrew (macOS and Linux):

```bash
brew install eugene-panin/tap/vctx
```

With Go 1.26 or newer:

```bash
go install github.com/eugene-panin/vctx@latest
```

The binary ends up in `$(go env GOPATH)/bin`, usually `~/go/bin`.

vctx runs the `vault` binary it finds on `PATH` (or `$VCTX_VAULT_BIN`). It
does not replace or bundle it.

## Set up

Describe your instances in `~/.config/vctx/config.yaml`:

```yaml
defaults:                  # applied to every context
  VAULT_FORMAT: table

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
```

Any environment variable is allowed, `VAULT_ADDR` is required. `login` is
optional: these are the arguments for `vault login`. Without it vctx asks for
the method the first time and remembers the answer once the login works. The
file must not be writable by other users.

Then hook vctx into your shell once:

```bash
vctx init
```

It adds one line to the rc file of your shell (zsh, bash or fish). Open a new
terminal after that.

## Use

```bash
vctx use prod        # this terminal now talks to prod, logging in if needed
vault kv get secret/app
vctx use dev
vault token lookup
```

`vctx use` also makes the context the default: new terminals start in it.
Other terminals keep the context they have.

`vctx` with no arguments opens a small UI with the status of every instance:
pick one with enter to switch the terminal to it, `l` logs in, `s` opens a
shell in that context, `x` forgets its token, `r` probes again.

To run a single command against another instance without switching:

```bash
vctx prod kv get secret/app          # vault kv get ... against prod
vctx exec prod -- terraform plan     # any command with prod's variables
```

`vctx help` lists all commands and settings.

## How it works

Before applying a context vctx drops every inherited `VAULT_*` variable, so an
address or token of one instance never leaks into another. Variables of your
own that a context overrides, `HTTPS_PROXY` say, get their values back when you
switch away.

vctx registers itself as the Vault [token helper] through a generated
`VAULT_CONFIG_PATH`. `vault login` hands it the new token, and vctx stores it
under the context's name together with the address. A token is never given to
a different address, even if you change `VAULT_ADDR` by hand. Tokens live in
the macOS Keychain, or on Linux in `0600` files under
`~/.local/state/vctx/tokens`. Set `VCTX_TOKEN_STORE=file` to use files on macOS
too. Neither hides tokens from other programs running as you.

vctx keeps no passwords. `vault login` asks for them itself, or opens the
browser for OIDC. Contexts that set `VAULT_TOKEN` or use a Vault agent are left
alone.

Before running a command vctx calls the unauthenticated `sys/health` endpoint
with the same TLS and proxy settings as the Vault CLI. A VPN that is down or an
ingress that rejects your IP shows up in seconds instead of as a hanging
command. `VCTX_CHECK_TIMEOUT` sets the timeout (3s by default), and `0` turns
the check off.

vctx refuses `vault -address` and `-agent-address`: the token helper cannot see
these flags and would hand the context's token to that other server.

[token helper]: https://developer.hashicorp.com/vault/docs/commands/token-helper

## Without the shell hook

The hook only defines a `vctx` shell function so that `vctx use` can change
variables of the terminal it runs in. Without it:

```bash
eval "$(vctx env prod)"     # switch this shell
eval "$(vctx env --clear)"  # undo
```

`vctx env ... --shell fish` prints the same for fish.

## License

MIT
