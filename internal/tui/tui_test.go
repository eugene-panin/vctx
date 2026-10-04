package tui

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/eugene-panin/vctx/internal/config"
	"github.com/eugene-panin/vctx/internal/probe"
	"github.com/eugene-panin/vctx/internal/token"
	"github.com/eugene-panin/vctx/internal/vaulttest"
)

// fakeBackend keeps what the UI asks for in memory.
type fakeBackend struct {
	current string
	tokens  map[string]token.State
	logins  map[string][]string
	forgot  []string
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{tokens: map[string]token.State{}, logins: map[string][]string{}}
}

func (f *fakeBackend) Current() string                  { return f.current }
func (f *fakeBackend) Use(name string) error            { f.current = name; return nil }
func (f *fakeBackend) LoginMethod(name string) []string { return f.logins[name] }
func (f *fakeBackend) Getenv(string) string             { return "" }
func (f *fakeBackend) Login(string) tea.ExecCommand     { return nil }

func (f *fakeBackend) TokenStatus(names []string) (map[string]token.State, error) {
	out := make(map[string]token.State, len(names))
	for _, n := range names {
		out[n] = f.tokens[n]
	}
	return out, nil
}

func (f *fakeBackend) Forget(name string) error {
	delete(f.tokens, name)
	f.forgot = append(f.forgot, name)
	return nil
}

func (f *fakeBackend) CommandEnv(map[string]string) ([]string, error) {
	return []string{"PATH=/usr/bin:/bin"}, nil
}

// testConfig has two contexts and a default.
var testConfig = &config.Config{
	Defaults: map[string]string{"VAULT_FORMAT": "json"},
	Contexts: map[string]map[string]string{
		"dev":  {"VAULT_ADDR": "http://127.0.0.1:8201", "VAULT_CACERT": "~/ca.pem"},
		"prod": {"VAULT_ADDR": "https://vault.example.com", "VAULT_NAMESPACE": "admin", "HTTPS_PROXY": "http://proxy:3128"},
	},
}

func prepare(t *testing.T, cfg *config.Config) []probe.Instance {
	t.Helper()
	var out []probe.Instance
	for _, name := range slices.Sorted(maps.Keys(cfg.Contexts)) {
		c, err := probe.Resolve(cfg, name, []string{"PATH=/usr/bin:/bin"}, "/home/u")
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func newModelFor(t *testing.T, cfg *config.Config) (*model, *fakeBackend) {
	t.Helper()
	b := newFakeBackend()
	return newModel(b, prepare(t, cfg), time.Second), b
}

// newTestModel has dev answered as active and prod blocked by an ingress.
func newTestModel(t *testing.T) (*model, *fakeBackend) {
	t.Helper()
	m, b := newModelFor(t, testConfig)
	m.rows[0].Status.Result = probe.Result{Health: &probe.Health{Initialized: true, Version: "1.20.4"}, Latency: 280 * time.Millisecond}
	m.rows[0].probing = false
	blocked, err := probe.TargetFor([]string{"VAULT_ADDR=" + vaulttest.Serve(t, vaulttest.Forbidden())})
	if err != nil {
		t.Fatal(err)
	}
	m.rows[1].Status.Result = probe.Probe(t.Context(), blocked, nil, time.Second)
	m.rows[1].probing = false
	return m, b
}

func TestViewFitsWindow(t *testing.T) {
	m, _ := newTestModel(t)
	sizes := [][2]int{{90, 8}, {109, 30}, {110, 30}, {180, 50}, {200, 6}}
	for w := 30; w <= 120; w++ { // bubbles/help overran some of these widths
		sizes = append(sizes, [2]int{w, 20})
	}
	for _, size := range sizes {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		view := m.render()
		lines := strings.Split(view, "\n")
		if len(lines) > size[1] {
			t.Errorf("%dx%d: %d lines:\n%s", size[0], size[1], len(lines), view)
		}
		for _, l := range lines {
			if w := lipgloss.Width(l); w > size[0] {
				t.Errorf("%dx%d: line is %d wide: %q", size[0], size[1], w, l)
			}
		}
		if !strings.Contains(view, "dev") {
			t.Errorf("%dx%d: context list missing:\n%s", size[0], size[1], view)
		}
	}
}

func TestViewWhileProbing(t *testing.T) {
	m, _ := newModelFor(t, testConfig)
	m.Init() // marks every row as probing; the probes themselves are not run
	for _, w := range []int{60, 150} {
		m.Update(tea.WindowSizeMsg{Width: w, Height: 24})
		// Every row shows the spinner in full, not cut to "check…".
		if view := ansi.Strip(m.render()); strings.Count(view, ansi.Strip(m.spin.View())+" checking") < 1+len(m.rows) {
			t.Errorf("width %d: no spinner while probing:\n%s", w, view)
		}
	}
}

func TestEnterMakesDefault(t *testing.T) {
	m, b := newTestModel(t)
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	_, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.chosen != "prod" {
		t.Fatalf("chosen = %q, want prod", m.chosen)
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("enter did not quit")
	}
	if b.current != "prod" {
		t.Errorf("default = %q, want prod", b.current)
	}
}

func TestForgetToken(t *testing.T) {
	m, b := newTestModel(t)
	b.tokens["dev"] = token.OK
	m.Update(m.loadTokens()()) // as after a login
	_, cmd := m.Update(tea.KeyPressMsg{Code: 'x', Text: "x"})
	if cmd == nil {
		t.Fatal("x did nothing")
	}
	_, cmd = m.Update(cmd())
	m.Update(cmd())
	if m.tokens["dev"] != token.None {
		t.Error("token still shown")
	}
	if !slices.Equal(b.forgot, []string{"dev"}) {
		t.Errorf("forgot = %q", b.forgot)
	}
	if !m.flashOK || !strings.Contains(m.flash, "forgotten") {
		t.Errorf("flash = %q", m.flash)
	}
}

func TestStaleProbeIgnored(t *testing.T) {
	m, _ := newTestModel(t)
	m.probe(0)
	stale := m.rows[0].gen
	m.Update(tea.KeyPressMsg{Code: 'r', Text: "r"})
	m.Update(probeMsg{i: 0, gen: stale, res: probe.Result{Err: errors.New("old")}})
	if !m.rows[0].probing || m.rows[0].Status.Err != nil {
		t.Errorf("stale answer applied: probing=%v err=%v", m.rows[0].probing, m.rows[0].Status.Err)
	}
	m.Update(probeMsg{i: 0, gen: m.rows[0].gen, res: probe.Result{Err: errors.New("new")}})
	if m.rows[0].probing || m.rows[0].Status.Err == nil || m.rows[0].Status.Err.Error() != "new" {
		t.Errorf("current answer not applied: probing=%v err=%v", m.rows[0].probing, m.rows[0].Status.Err)
	}
}

func TestDisplayValue(t *testing.T) {
	tests := []struct{ key, value, want string }{
		{"VAULT_TOKEN", "hvs.secret", "•••"},
		{"DB_PASSWORD", "x", "•••"},
		{"HTTPS_PROXY", "http://user:pass@proxy:3128", "http://user:xxxxx@proxy:3128"},
		{"VAULT_NAMESPACE", "admin", "admin"},
		{"API_KEY", "k", "•••"},
		{"SMTP_PASS", "p", "•••"},
		{"GOOGLE_APPLICATION_CREDENTIALS", "/k.json", "•••"},
	}
	for _, tc := range tests {
		if got := displayValue(tc.key, tc.value); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestDetailShowsDefaults(t *testing.T) {
	m, _ := newTestModel(t)
	m.Update(tea.WindowSizeMsg{Width: 150, Height: 30})
	if view := m.render(); !strings.Contains(view, "VAULT_FORMAT=json") {
		t.Errorf("defaults missing from details:\n%s", view)
	}
}

func TestScrollKeepsCursorVisible(t *testing.T) {
	m, _ := newTestModel(t)
	m.Update(tea.WindowSizeMsg{Width: 60, Height: 7})
	m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	if view := m.render(); !strings.Contains(view, "prod") {
		t.Errorf("selected row scrolled out:\n%s", view)
	}
}

func TestStaleTokenStatusIgnored(t *testing.T) {
	m, b := newTestModel(t)
	b.tokens["dev"] = token.OK
	slow := m.loadTokens()() // started before the token is forgotten, answers after
	m.Update(m.loadTokens()())
	_, cmd := m.Update(tea.KeyPressMsg{Code: 'x', Text: "x"})
	_, cmd = m.Update(cmd())
	m.Update(slow)
	m.Update(cmd())
	if m.tokens["dev"] != token.None {
		t.Error("late token status brought a forgotten token back")
	}
}

func TestRefreshRetriesConfigErrorsFromProbe(t *testing.T) {
	m, _ := newModelFor(t, &config.Config{Contexts: map[string]map[string]string{
		"x": {"VAULT_ADDR": "https://127.0.0.1:1", "VAULT_CACERT": "/nonexistent/ca.pem"},
	}})
	cmd := m.probe(0)
	m.Update(cmd())
	if short, _ := m.rows[0].Status.Short(); short != "config error" {
		t.Fatalf("status = %q", short)
	}
	gen := m.rows[0].gen
	m.Update(tea.KeyPressMsg{Code: 'r', Text: "r"})
	if m.rows[0].gen == gen {
		t.Error("refresh skipped a context whose address is fine")
	}
}

// drain runs cmd the way bubbletea does and feeds the result back, so a panic
// in a command shows up in the test. Spinner ticks are not fed back: they would
// keep the loop going while anything is probing.
func drain(t *testing.T, m *model, cmd tea.Cmd, depth int) {
	t.Helper()
	if cmd == nil || depth > 20 {
		return
	}
	switch msg := cmd().(type) {
	case nil, tea.QuitMsg, spinner.TickMsg:
	case tea.BatchMsg:
		for _, c := range msg {
			drain(t, m, c, depth+1)
		}
	default:
		_, next := m.Update(msg)
		drain(t, m, next, depth+1)
	}
}

func TestEveryKeyOnEveryKindOfContext(t *testing.T) {
	ok := vaulttest.Serve(t, vaulttest.Handler(200, vaulttest.ActiveBody))
	c := &config.Config{Contexts: map[string]map[string]string{
		"ok":      {"VAULT_ADDR": ok},
		"badaddr": {"VAULT_ADDR": "vault.example.com:8200"},
		"down":    {"VAULT_ADDR": vaulttest.ClosedURL(t)},
		"noca":    {"VAULT_ADDR": ok, "VAULT_CACERT": "/nonexistent/ca.pem"},
	}}
	press := func(s string) tea.KeyPressMsg {
		switch s {
		case "down":
			return tea.KeyPressMsg{Code: tea.KeyDown}
		case "up":
			return tea.KeyPressMsg{Code: tea.KeyUp}
		case "enter":
			return tea.KeyPressMsg{Code: tea.KeyEnter}
		}
		return tea.KeyPressMsg{Code: rune(s[0]), Text: s}
	}

	for row := range 4 {
		m, b := newModelFor(t, c)
		for _, name := range slices.Sorted(maps.Keys(c.Contexts)) {
			b.tokens[name] = token.Stale
		}
		m.spin.Spinner.FPS = time.Microsecond
		m.Update(tea.WindowSizeMsg{Width: 120, Height: 24})
		drain(t, m, m.Init(), 0)
		m.cursor = row
		name := m.rows[row].Status.Name
		for _, k := range []string{"r", "l", "s", "x", "down", "up", "enter"} {
			_, cmd := m.Update(press(k))
			drain(t, m, cmd, 0)
			if k == "l" || k == "s" {
				// The command itself does not run in a test; its completion does.
				_, cmd = m.Update(execDoneMsg{i: m.cursor, what: name + " " + k})
				drain(t, m, cmd, 0)
			}
			for _, line := range strings.Split(m.render(), "\n") {
				if lipgloss.Width(line) > 120 {
					t.Errorf("%s after %q: line too wide: %q", name, k, line)
				}
			}
		}
		if want := m.rows[m.cursor].Status.Name; m.chosen != want {
			t.Errorf("%s: enter chose %q, cursor on %q", name, m.chosen, want)
		}
	}
}

func TestMultilineValueInDetails(t *testing.T) {
	m, _ := newModelFor(t, &config.Config{Contexts: map[string]map[string]string{
		"x": {"VAULT_ADDR": "http://v", "VAULT_CACERT_BYTES": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"},
	}})
	m.Update(tea.WindowSizeMsg{Width: 150, Height: 30})
	view := m.render()
	if !strings.Contains(view, "VAULT_CACERT_BYTES=-----BEGIN CERTIFICATE-----…") || strings.Contains(view, "MIIB") {
		t.Errorf("details:\n%s", view)
	}
}

func TestForgetBeforeStatusLoads(t *testing.T) {
	m, b := newTestModel(t)
	b.tokens["dev"] = token.OK
	_, cmd := m.Update(tea.KeyPressMsg{Code: 'x', Text: "x"})
	if cmd == nil {
		t.Fatalf("x refused before token status loaded: %q", m.flash)
	}
	m.Update(cmd())
	if !slices.Equal(b.forgot, []string{"dev"}) {
		t.Errorf("forgot = %q", b.forgot)
	}
}

func TestBadAddressShown(t *testing.T) {
	m, _ := newModelFor(t, &config.Config{Contexts: map[string]map[string]string{
		"noscheme": {"VAULT_ADDR": "vault.example.com:8200"},
	}})
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 20})
	if view := m.render(); !strings.Contains(view, "config error") {
		t.Errorf("UI:\n%s", view)
	}
}

func TestDetailShowsLoginMethod(t *testing.T) {
	b := newFakeBackend()
	b.logins["dev"] = []string{"-method=oidc", "-path=sso"}
	m := newModel(b, prepare(t, testConfig), time.Second)
	m.Update(tea.WindowSizeMsg{Width: 150, Height: 30})
	if view := m.render(); !strings.Contains(view, "-method=oidc -path=sso") {
		t.Errorf("details:\n%s", view)
	}
}

// The detail box keeps its border straight around wrapped error text.
func TestDetailBoxIsRectangular(t *testing.T) {
	m, _ := newTestModel(t)
	m.cursor = 1 // prod, blocked: a long error that wraps
	for _, w := range []int{120, 150} {
		m.Update(tea.WindowSizeMsg{Width: w, Height: 30})
		box := m.detailView(m.layout().detailW, 0)
		lines := strings.Split(box, "\n")
		for _, l := range lines {
			if lipgloss.Width(l) != lipgloss.Width(lines[0]) {
				t.Errorf("width %d: line %q is %d wide, the top %d", w, ansi.Strip(l), lipgloss.Width(l), lipgloss.Width(lines[0]))
			}
		}
	}
}
