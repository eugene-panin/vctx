package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInitWritesOnce(t *testing.T) {
	a, out, _ := newTestApp(t, "SHELL=/bin/zsh")
	a.home = t.TempDir()
	for range 2 {
		if err := a.run([]string{"init"}); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(filepath.Join(a.home, ".zshrc"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(b), initMarker) != 1 || !strings.Contains(string(b), initLine("zsh")) {
		t.Errorf(".zshrc:\n%s", b)
	}
	if !strings.Contains(out.String(), "already set up") {
		t.Errorf("second run: %q", out)
	}
}

func TestRCFile(t *testing.T) {
	a, _, _ := newTestApp(t, "ZDOTDIR=/zdot", "XDG_CONFIG_HOME=/xdg")
	a.home = "/home/u"
	bash := "/home/u/.bashrc"
	if runtime.GOOS == "darwin" {
		bash = "/home/u/.bash_profile"
	}
	for shell, want := range map[string]string{"zsh": "/zdot/.zshrc", "bash": bash, "fish": "/xdg/fish/conf.d/vctx.fish"} {
		if got, err := a.rcFile(shell); err != nil || got != want {
			t.Errorf("%s: %q, %v", shell, got, err)
		}
	}
	if _, err := a.rcFile("tcsh"); err == nil {
		t.Error("tcsh accepted")
	}
}

func TestInitPrintsScript(t *testing.T) {
	a, out, _ := newTestApp(t)
	if err := a.run([]string{"init", "fish"}); err != nil || !strings.Contains(out.String(), "env --shell fish --default 2>/dev/null | source") {
		t.Errorf("fish: %v\n%s", err, out)
	}
	var uerr usageError
	if err := a.run([]string{"init", "--bogus"}); !errors.As(err, &uerr) {
		t.Errorf("--bogus: %v", err)
	}
}

func TestEnvDefaultIgnoresShellContext(t *testing.T) {
	a, out, _ := newTestApp(t, "VCTX_CONTEXT=prod")
	if err := a.run([]string{"use", "dev"}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := a.run([]string{"env", "--default"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "export VCTX_CONTEXT='dev'") {
		t.Errorf("output:\n%s", out)
	}
}

func TestFishEnv(t *testing.T) {
	a, out, _ := newTestApp(t, "VAULT_TOKEN=x")
	if err := a.run([]string{"env", "prod", "--shell", "fish"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"set -e VAULT_TOKEN\n", "set -gx VAULT_ADDR 'https://vault.example.com'\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if got := fishQuote(`it's \ here`); got != `'it\'s \\ here'` {
		t.Errorf("fishQuote = %s", got)
	}
}

func TestUseUnderIntegrationIsQuiet(t *testing.T) {
	choice := filepath.Join(t.TempDir(), "choice")
	if err := os.WriteFile(choice, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	a, _, _ := newTestApp(t, "VCTX_CONTEXT=prod", "VCTX_CHOICE_FILE="+choice)
	var stderr strings.Builder
	a.stderr = &stderr
	if err := a.run([]string{"use", "dev"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr.String(), "precedence") {
		t.Errorf("override note under the integration: %q", stderr.String())
	}
	if b, _ := os.ReadFile(choice); string(b) != "dev" {
		t.Errorf("choice file = %q, want dev", b)
	}
}

// TestBashIntegration runs the real thing: vctx init, then an interactive bash
// in which `vctx use` switches VAULT_ADDR.
func TestBashIntegration(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil || testing.Short() {
		t.Skip("needs bash and a build")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if out, err := exec.Command("go", "build", "-o", filepath.Join(bin, "vctx"), ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	home := filepath.Join(dir, "home")
	cfg := filepath.Join(dir, "c.yaml")
	// b sets a PATH without vctx in it: the function must still reach vctx.
	if err := os.WriteFile(cfg, []byte("contexts:\n  a:\n    VAULT_ADDR: http://a\n  b:\n    VAULT_ADDR: http://b\n    PATH: /usr/bin:/bin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := []string{
		"HOME=" + home, "SHELL=" + bash, "PATH=" + bin + ":/usr/bin:/bin",
		"VCTX_CONFIG=" + cfg, "VCTX_STATE_DIR=" + filepath.Join(dir, "state"), "VCTX_TOKEN_STORE=file",
	}
	run := func(name string, args ...string) string {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %q: %v\n%s", name, args, err, out)
		}
		return string(out)
	}
	run(filepath.Join(bin, "vctx"), "use", "a")
	run(filepath.Join(bin, "vctx"), "init")
	// rcFile picks .bash_profile on macOS, read by login shells, and .bashrc elsewhere.
	flags := []string{"-i", "-c"}
	if runtime.GOOS == "darwin" {
		flags = append([]string{"-l"}, flags...)
	}
	out := run(bash, append(flags, `echo "start=$VAULT_ADDR"
vctx use b >/dev/null 2>&1; echo "b=$VAULT_ADDR"
vctx use a >/dev/null 2>&1; echo "back=$VAULT_ADDR"
vctx ls >/dev/null 2>&1; vctx >/dev/null 2>&1; echo "unchanged=$VAULT_ADDR"`)...)
	for _, want := range []string{"start=http://a", "b=http://b", "back=http://a", "unchanged=http://a"} {
		if !strings.Contains(out, want) {
			t.Errorf("bash session lacks %q:\n%s", want, out)
		}
	}
	// A non-interactive shell (a script) is left alone.
	if out := run(bash, "-l", "-c", `echo "script=$VAULT_ADDR"`); strings.Contains(out, "script=http") {
		t.Errorf("non-interactive shell got a context: %q", out)
	}
}

func TestInitFindsHandWrittenLine(t *testing.T) {
	a, out, _ := newTestApp(t, "SHELL=/bin/zsh")
	a.home = t.TempDir()
	rc := filepath.Join(a.home, ".zshrc")
	if err := os.WriteFile(rc, []byte(`eval "$(vctx init zsh)"`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.run([]string{"init"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(rc); strings.Contains(string(b), initMarker) || !strings.Contains(out.String(), "already set up") {
		t.Errorf("hand-written line duplicated:\n%s", b)
	}
}

func TestBashProfileOnMacKeepsExistingProfile(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS login shells only")
	}
	a, _, _ := newTestApp(t)
	a.home = t.TempDir()
	profile := filepath.Join(a.home, ".profile")
	if err := os.WriteFile(profile, []byte("export MYPROFILE=loaded\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := a.rcFile("bash"); err != nil || got != profile {
		t.Errorf("rc file = %q, %v; want the existing .profile", got, err)
	}
}
