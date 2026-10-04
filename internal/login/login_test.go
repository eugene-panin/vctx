package login

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eugene-panin/vctx/internal/config"
	"github.com/eugene-panin/vctx/internal/token"
	"github.com/eugene-panin/vctx/internal/vaulttest"
)

func TestVaultError(t *testing.T) {
	out := "Error looking up token: Error making API request.\n\nURL: GET http://v/v1/auth/token/lookup-self\nCode: 503. Errors:\n\n* Vault is sealed\n"
	if got := vaultError(out); got != "Code: 503. Vault is sealed" {
		t.Errorf("got %q", got)
	}
	nested := "Code: 403. Errors:\n\n* 2 errors occurred:\n\t* permission denied\n\t* invalid token\n"
	if got := vaultError(nested); got != "Code: 403. permission denied" {
		t.Errorf("nested: %q", got)
	}
}

// newRunner returns a Runner on a terminal with nothing typed, running
// vaultBin and keeping tokens in files.
func newRunner(t *testing.T, vaultBin string) (*Runner, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	var out bytes.Buffer
	return &Runner{
		Environ:     []string{"PATH=" + os.Getenv("PATH")},
		Home:        "/home/u",
		StateDir:    dir,
		Self:        "/usr/local/bin/vctx",
		VaultBin:    vaultBin,
		Tokens:      func() (token.Store, error) { return token.Open(dir, "file", nil) },
		In:          strings.NewReader(""),
		Out:         &out,
		Interactive: true,
	}, &out
}

func loadConfig(t *testing.T, yaml string) *config.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// activeContext is a config with context x at a Vault that answers as active.
func activeContext(t *testing.T) *config.Config {
	return loadConfig(t, "contexts:\n  x:\n    VAULT_ADDR: "+vaulttest.Serve(t, vaulttest.Handler(200, vaulttest.ActiveBody))+"\n")
}

// fakeVault writes a vault stand-in that logs its arguments, answers
// `token lookup` as lookup says (ok, denied or down), and fails `login`
// when lookup is "loginfails".
func fakeVault(t *testing.T, lookup string) (bin, log string) {
	t.Helper()
	return fakeVaultPrinting(t, lookup, "")
}

// fakeVaultPrinting is fakeVault whose `vault print token` prints printed.
func fakeVaultPrinting(t *testing.T, lookup, printed string) (bin, log string) {
	t.Helper()
	dir := t.TempDir()
	bin, log = filepath.Join(dir, "vault"), filepath.Join(dir, "calls")
	script := `#!/bin/sh
echo "$*" >> "` + log + `"
if [ "$1 $2" = "token lookup" ]; then
  case "` + lookup + `" in
    ok) exit 0 ;;
    denied) printf 'Code: 403. Errors:\n* 2 errors occurred:\n\t* permission denied\n\t* invalid token\n'; exit 2 ;;
    nolookup) printf 'Code: 403. Errors:\n* 1 error occurred:\n\t* permission denied\n'; exit 2 ;;
    *) echo "Error looking up token: dial tcp: connection refused"; exit 2 ;;
  esac
fi
if [ "$1" = login ] && [ "` + lookup + `" = loginfails ]; then exit 2; fi
if [ "$1 $2" = "print token" ]; then echo "` + printed + `"; fi
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, log
}

func calls(t *testing.T, log string) string {
	t.Helper()
	b, _ := os.ReadFile(log)
	return string(b)
}

func TestEnsure(t *testing.T) {
	devAddr := vaulttest.Serve(t, vaulttest.Handler(200, vaulttest.ActiveBody))
	cfg := loadConfig(t, "contexts:\n  dev:\n    VAULT_ADDR: "+devAddr+"\n    login: -method=userpass username=me\n  bare:\n    VAULT_ADDR: "+vaulttest.Serve(t, vaulttest.Handler(200, vaulttest.ActiveBody))+"\n")
	tests := []struct {
		name, context, lookup string
		stored, tty           bool
		answers               string
		wantLogin, wantInErr  string
		wantRemembered        bool
	}{
		{"no token", "dev", "ok", false, true, "", "login -no-print -method=userpass username=me", "", false},
		{"working token", "dev", "ok", true, true, "", "", "", false},
		{"expired token", "dev", "denied", true, true, "", "login -no-print -method=userpass username=me", "", false},
		{"vault cannot tell", "dev", "down", true, true, "", "", "check token", false},
		{"token without lookup right works", "dev", "nolookup", true, true, "", "", "", false},
		{"asks the method", "bare", "ok", false, true, "1\n\nwoodman\n", "login -no-print -method=userpass username=woodman", "", true},
		{"asks oidc with a path", "bare", "ok", false, true, "3\nsso\n\n", "login -no-print -method=oidc -path=sso", "", true},
		{"failed login not remembered", "bare", "loginfails", false, true, "2\n\nme\n", "login -no-print -method=ldap username=me", "login failed", false},
		{"script", "dev", "ok", false, false, "", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bin, log := fakeVault(t, tc.lookup)
			r, out := newRunner(t, bin)
			if tc.stored {
				s, _ := r.Tokens()
				if err := s.Set("dev", "tok", config.NormalizeAddr(devAddr)); err != nil {
					t.Fatal(err)
				}
			}
			r.Interactive = tc.tty
			r.In = strings.NewReader(tc.answers)
			r.Ensure(context.Background(), cfg, tc.context)

			gotLogin := ""
			for _, line := range strings.Split(strings.TrimSpace(calls(t, log)), "\n") {
				if strings.HasPrefix(line, "login") {
					gotLogin = line
				}
			}
			if gotLogin != tc.wantLogin {
				t.Errorf("login call %q, want %q", gotLogin, tc.wantLogin)
			}
			if tc.wantInErr != "" && !strings.Contains(out.String(), tc.wantInErr) {
				t.Errorf("output %q, want %q", out.String(), tc.wantInErr)
			}
			_, err := os.Stat(r.rememberedPath(tc.context))
			if remembered := err == nil; remembered != tc.wantRemembered {
				t.Errorf("remembered = %v, want %v", remembered, tc.wantRemembered)
			}
		})
	}
}

func TestMethod(t *testing.T) {
	r, _ := newRunner(t, "vault")
	cfg := loadConfig(t, "contexts:\n  dev:\n    VAULT_ADDR: http://v\n    login: -method=oidc -path=sso\n  ops:\n    VAULT_ADDR: http://o\n")
	if got := r.Method(cfg, "dev"); !slices.Equal(got, []string{"-method=oidc", "-path=sso"}) {
		t.Errorf("from the config: %q", got)
	}
	if got := r.Method(cfg, "ops"); got != nil {
		t.Errorf("nothing known: %q", got)
	}
	if err := r.remember("ops", []string{"-method=ldap", "username=me"}); err != nil {
		t.Fatal(err)
	}
	if got := r.Method(cfg, "ops"); !slices.Equal(got, []string{"-method=ldap", "username=me"}) {
		t.Errorf("remembered: %q", got)
	}
}

func TestRememberedLoginUsedNextTime(t *testing.T) {
	bin, log := fakeVault(t, "denied")
	r, out := newRunner(t, bin)
	if err := r.remember("x", []string{"-method=ldap", "username=me"}); err != nil {
		t.Fatal(err)
	}
	r.Ensure(context.Background(), activeContext(t), "x") // nothing typed: no questions expected
	if got := calls(t, log); !strings.Contains(got, "login -no-print -method=ldap username=me") {
		t.Errorf("calls:\n%s\noutput:\n%s", got, out)
	}
}

func TestCmd(t *testing.T) {
	bin, log := fakeVault(t, "ok")
	r, _ := newRunner(t, bin)
	var out bytes.Buffer
	l := r.Cmd(loadConfig(t, "contexts:\n  dev:\n    VAULT_ADDR: http://127.0.0.1:8201\n"), "dev")
	l.SetStdin(strings.NewReader("4\n"))
	l.SetStdout(&out)
	l.SetStderr(&out)
	if err := l.Run(); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if got := calls(t, log); !strings.Contains(got, "login -no-print -method=token") {
		t.Errorf("calls:\n%s", got)
	}
}

func TestCmdWaitsAfterFailure(t *testing.T) {
	bin, _ := fakeVault(t, "loginfails")
	r, _ := newRunner(t, bin)
	var out bytes.Buffer
	l := r.Cmd(activeContext(t), "x")
	l.SetStdin(strings.NewReader("4\nn\n\n")) // token, no other method, Enter
	l.SetStdout(&out)
	if err := l.Run(); err == nil {
		t.Fatal("failed login reported as success")
	}
	if !strings.Contains(out.String(), "press Enter to return") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestNoLoginAgainstUnusableServer(t *testing.T) {
	bin, log := fakeVault(t, "ok")
	for name, addr := range map[string]string{"sealed": vaulttest.Serve(t, vaulttest.Handler(503, vaulttest.SealedBody)), "down": vaulttest.ClosedURL(t)} {
		r, out := newRunner(t, bin)
		r.Ensure(context.Background(), loadConfig(t, "contexts:\n  x:\n    VAULT_ADDR: "+addr+"\n"), "x")
		if got := calls(t, log); strings.Contains(got, "login") {
			t.Errorf("%s: logged in anyway: %s", name, got)
		}
		if !strings.Contains(out.String(), "not logging in") {
			t.Errorf("%s: output %q", name, out.String())
		}
	}
}

func TestExternalTokenNeverLogsIn(t *testing.T) {
	bin, log := fakeVault(t, "denied")
	r, out := newRunner(t, bin)
	addr := vaulttest.Serve(t, vaulttest.Handler(200, vaulttest.ActiveBody))
	r.Ensure(context.Background(), loadConfig(t, "contexts:\n  x:\n    VAULT_ADDR: "+addr+"\n    VAULT_TOKEN: hvs.fromconfig\n    login: -method=userpass username=me\n"), "x")
	if got := calls(t, log); strings.Contains(got, "login") {
		t.Errorf("logged in although vault uses VAULT_TOKEN: %s", got)
	}
	if !strings.Contains(out.String(), "refuses the token") {
		t.Errorf("output %q", out.String())
	}
}

func TestCancelAtPrompt(t *testing.T) {
	bin, log := fakeVault(t, "ok")
	r, _ := newRunner(t, bin)
	pr, pw, err := os.Pipe() // a real file, as the terminal is: Ctrl-C must interrupt the read
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pr.Close(); pw.Close() })
	var out syncBuffer
	r.In, r.Out = pr, &out

	cfg := activeContext(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Ensure(ctx, cfg, "x")
		close(done)
	}()
	for !strings.Contains(out.String(), "method [1]") {
		select {
		case <-done:
			t.Fatalf("no question asked:\n%s", out.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel() // what Ctrl-C does through Interruptible
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the question did not give up on Ctrl-C")
	}
	if !strings.Contains(out.String(), "login cancelled") {
		t.Errorf("output %q", out.String())
	}
	if got := calls(t, log); strings.Contains(got, "login") {
		t.Errorf("logged in after Ctrl-C: %s", got)
	}
}

func TestOwnTokenHelperContext(t *testing.T) {
	addr := vaulttest.Serve(t, vaulttest.Handler(200, vaulttest.ActiveBody))
	cfg := loadConfig(t, "contexts:\n  x:\n    VAULT_ADDR: "+addr+"\n    VAULT_CONFIG_PATH: /etc/vault-cli.hcl\n    login: -method=userpass username=me\n")
	for _, tc := range []struct {
		name, lookup, printed string
		wantLogin             bool
	}{
		{"no token there", "ok", "", true},
		{"working token", "ok", "hvs.x", false},
		{"expired token", "denied", "hvs.x", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin, log := fakeVaultPrinting(t, tc.lookup, tc.printed)
			r, _ := newRunner(t, bin)
			r.Ensure(context.Background(), cfg, "x")
			if got := strings.Contains(calls(t, log), "login -no-print"); got != tc.wantLogin {
				t.Errorf("login = %v, want %v; calls:\n%s", got, tc.wantLogin, calls(t, log))
			}
		})
	}
}

func TestAgentContextNeverLogsIn(t *testing.T) {
	bin, log := fakeVault(t, "denied")
	r, _ := newRunner(t, bin)
	addr := vaulttest.Serve(t, vaulttest.Handler(200, vaulttest.ActiveBody))
	r.Ensure(context.Background(), loadConfig(t, "contexts:\n  x:\n    VAULT_AGENT_ADDR: "+addr+"\n    login: -method=userpass username=me\n"), "x")
	if got := calls(t, log); got != "" {
		t.Errorf("vault called for an agent context: %s", got)
	}
}

func TestFailedLoginOffersAnotherMethod(t *testing.T) {
	bin, log := fakeVault(t, "loginfails")
	r, out := newRunner(t, bin)
	if err := r.remember("x", []string{"-method=ldap", "username=me"}); err != nil {
		t.Fatal(err)
	}
	r.In = strings.NewReader("y\n1\n\nme\nn\n") // pick userpass, then give up
	r.Ensure(context.Background(), activeContext(t), "x")
	got := calls(t, log)
	if !strings.Contains(got, "-method=ldap") || !strings.Contains(got, "-method=userpass") {
		t.Errorf("calls:\n%s\noutput:\n%s", got, out)
	}
	if got := r.remembered("x"); !slices.Equal(got, []string{"-method=ldap", "username=me"}) {
		t.Errorf("remembered after failures = %q, want unchanged", got)
	}
}

// syncBuffer is a bytes.Buffer safe to read while another goroutine writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
