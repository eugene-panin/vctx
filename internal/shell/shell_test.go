package shell

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallOnce(t *testing.T) {
	s := Setup{Home: t.TempDir()}
	var out bytes.Buffer
	for range 2 {
		if err := s.Install("zsh", &out); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(filepath.Join(s.Home, ".zshrc"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(b), initMarker) != 1 || !strings.Contains(string(b), InitLine("zsh")) {
		t.Errorf(".zshrc:\n%s", b)
	}
	if !strings.Contains(out.String(), "already set up") {
		t.Errorf("second run: %q", out.String())
	}
}

func TestRCFile(t *testing.T) {
	s := Setup{Home: "/home/u", ZDotDir: "/zdot", ConfigHome: "/xdg"}
	bash := "/home/u/.bashrc"
	if runtime.GOOS == "darwin" {
		bash = "/home/u/.bash_profile"
	}
	for shell, want := range map[string]string{"zsh": "/zdot/.zshrc", "bash": bash, "fish": "/xdg/fish/conf.d/vctx.fish"} {
		if got, err := s.RCFile(shell); err != nil || got != want {
			t.Errorf("%s: %q, %v", shell, got, err)
		}
	}
	if _, err := s.RCFile("tcsh"); err == nil {
		t.Error("tcsh accepted")
	}
}

func TestPrintQuotesTheBinary(t *testing.T) {
	s := Setup{Self: "/opt/my tools/vctx"}
	for shell, want := range map[string]string{
		"zsh":  `'/opt/my tools/vctx' env --default`,
		"bash": `'/opt/my tools/vctx' env --default`,
		"fish": `'/opt/my tools/vctx' env --shell fish --default 2>/dev/null | source`,
	} {
		var out bytes.Buffer
		if err := s.Print(shell, &out); err != nil || !strings.Contains(out.String(), want) {
			t.Errorf("%s: %v\n%s", shell, err, out.String())
		}
	}
}

func TestInstallFindsHandWrittenLine(t *testing.T) {
	s := Setup{Home: t.TempDir()}
	rc := filepath.Join(s.Home, ".zshrc")
	if err := os.WriteFile(rc, []byte(`eval "$(vctx init zsh)"`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := s.Install("zsh", &out); err != nil {
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
	s := Setup{Home: t.TempDir()}
	profile := filepath.Join(s.Home, ".profile")
	if err := os.WriteFile(profile, []byte("export MYPROFILE=loaded\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := s.RCFile("bash"); err != nil || got != profile {
		t.Errorf("rc file = %q, %v; want the existing .profile", got, err)
	}
}

// TestShellIntegration runs the real thing: vctx init, then an interactive
// zsh and bash in which `vctx use` switches VAULT_ADDR.
func TestShellIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("builds vctx and starts shells")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if out, err := exec.Command("go", "build", "-o", filepath.Join(bin, "vctx"), "github.com/eugene-panin/vctx").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for _, shell := range []string{"zsh", "bash"} {
		t.Run(shell, func(t *testing.T) {
			path, err := exec.LookPath(shell)
			if err != nil {
				t.Skip(shell + " not installed")
			}
			home := t.TempDir()
			cfg := filepath.Join(home, "c.yaml")
			// b sets a PATH without vctx in it: the function must still reach vctx.
			if err := os.WriteFile(cfg, []byte("contexts:\n  a:\n    VAULT_ADDR: http://a\n  b:\n    VAULT_ADDR: http://b\n    PATH: /usr/bin:/bin\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			env := []string{
				"HOME=" + home, "SHELL=" + path, "PATH=" + bin + ":/usr/bin:/bin", "TMPDIR=" + t.TempDir(),
				"VCTX_CONFIG=" + cfg, "VCTX_STATE_DIR=" + filepath.Join(home, "state"), "VCTX_TOKEN_STORE=file",
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
			if shell == "bash" && runtime.GOOS == "darwin" {
				flags = append([]string{"-l"}, flags...)
			}
			out := run(path, append(flags, `echo "start=$VAULT_ADDR"
vctx use b >/dev/null 2>&1; echo "b=$VAULT_ADDR"
vctx use a >/dev/null 2>&1; echo "back=$VAULT_ADDR"
vctx ls >/dev/null 2>&1; vctx >/dev/null 2>&1; echo "unchanged=$VAULT_ADDR"
vctx nosuch >/dev/null 2>&1; echo "rc=$?"`)...)
			for _, want := range []string{"start=http://a", "b=http://b", "back=http://a", "unchanged=http://a", "rc=2"} {
				if !strings.Contains(out, want) {
					t.Errorf("session lacks %q:\n%s", want, out)
				}
			}
			// A non-interactive shell (a script) is left alone.
			if shell == "bash" {
				if out := run(path, "-l", "-c", `echo "script=$VAULT_ADDR"`); strings.Contains(out, "script=http") {
					t.Errorf("non-interactive shell got a context: %q", out)
				}
			}
		})
	}
}
