package shell

import (
	"bytes"
	"os"
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
	if strings.Count(string(b), initMarker) != 1 || !strings.Contains(string(b), initLine("zsh")) {
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
