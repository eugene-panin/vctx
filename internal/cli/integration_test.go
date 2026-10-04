package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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
			// The rc file is .bash_profile on macOS, read by login shells, and .bashrc elsewhere.
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
