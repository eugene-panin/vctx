package main

import (
	"errors"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func TestFitColumns(t *testing.T) {
	cols := []column{
		{header: "", cells: []string{"●"}},
		{header: "CONTEXT", cells: []string{"matchsystems"}, min: 8, shrink: 2},
		{header: "ADDRESS", cells: []string{"vault.matchsystems.tech"}, min: 12, shrink: 1},
		{header: "STATUS", cells: []string{"blocked (HTTP 403)"}, min: 10, shrink: 5},
		{header: "LATENCY", cells: []string{"300ms"}, drop: 4},
		{header: "TOKEN", cells: []string{"✓"}, drop: 3},
	}
	tests := []struct {
		total int
		want  []int
	}{
		{200, []int{1, 12, 23, 18, 7, 5}},
		{70, []int{1, 12, 17, 18, 7, 5}}, // address gives way first
		{62, []int{1, 9, 12, 18, 7, 5}},  // then the name
		{55, []int{1, 8, 12, 18, 7, 0}},  // then the token column goes
		{45, []int{1, 8, 12, 18, 0, 0}},  // then latency
		{40, []int{1, 8, 12, 13, 0, 0}},  // status is truncated last
		{20, []int{1, 8, 12, 10, 0, 0}},  // nothing left to give
	}
	for _, tc := range tests {
		if got := fitColumns(cols, tc.total, 2); !slices.Equal(got, tc.want) {
			t.Errorf("total %d: got %v, want %v", tc.total, got, tc.want)
		}
	}
}

func newTestModel(t *testing.T) (*model, *app) {
	t.Helper()
	a, _, _ := newTestApp(t)
	cfg, err := a.loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	m, err := newModel(a, cfg)
	if err != nil {
		t.Fatal(err)
	}
	m.rows[0].status.probeResult = probeResult{health: &health{Initialized: true, Version: "1.20.4"}, latency: 280 * time.Millisecond}
	m.rows[0].probing = false
	m.rows[1].status.probeResult = probeResult{err: &notVaultError{status: 403, contentType: "text/html"}}
	m.rows[1].probing = false
	return m, a
}

func TestViewFitsWindow(t *testing.T) {
	m, _ := newTestModel(t)
	sizes := [][2]int{{90, 8}, {109, 30}, {110, 30}, {180, 50}, {200, 6}}
	for w := 30; w <= 120; w++ { // bubbles/help overran some of these widths
		sizes = append(sizes, [2]int{w, 20})
	}
	for _, size := range sizes {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		view := m.View()
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
	a, _, _ := newTestApp(t)
	cfg, err := a.loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	m, err := newModel(a, cfg)
	if err != nil {
		t.Fatal(err)
	}
	m.Init() // marks every row as probing; the probes themselves are not run
	for _, w := range []int{60, 150} {
		m.Update(tea.WindowSizeMsg{Width: w, Height: 24})
		if view := m.View(); !strings.Contains(view, m.spin.View()+" checking") {
			t.Errorf("width %d: no spinner while probing:\n%s", w, view)
		}
	}
}

func TestEnterMakesDefault(t *testing.T) {
	m, a := newTestModel(t)
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m.Update(tea.KeyMsg{Type: tea.KeyDown})
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.chosen != "prod" {
		t.Fatalf("chosen = %q, want prod", m.chosen)
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("enter did not quit")
	}
	if name, _ := a.contextName(""); name != "prod" {
		t.Errorf("default = %q, want prod", name)
	}
}

func TestForgetToken(t *testing.T) {
	m, a := newTestModel(t)
	if err := writeFileAtomic(a.tokenPath("dev"), []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	m.Update(m.loadTokens()()) // as after a login
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	if cmd == nil {
		t.Fatal("x did nothing")
	}
	_, cmd = m.Update(cmd())
	m.Update(cmd())
	if m.tokens["dev"] != tokenNone {
		t.Error("token still shown")
	}
	if _, err := os.Stat(a.tokenPath("dev")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("token still present: %v", err)
	}
	if !m.flashOK || !strings.Contains(m.flash, "forgotten") {
		t.Errorf("flash = %q", m.flash)
	}
}

func TestStaleProbeIgnored(t *testing.T) {
	m, _ := newTestModel(t)
	m.probe(0)
	stale := m.rows[0].gen
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	m.Update(probeMsg{i: 0, gen: stale, res: probeResult{err: errors.New("old")}})
	if !m.rows[0].probing || m.rows[0].status.err != nil {
		t.Errorf("stale answer applied: probing=%v err=%v", m.rows[0].probing, m.rows[0].status.err)
	}
	m.Update(probeMsg{i: 0, gen: m.rows[0].gen, res: probeResult{err: errors.New("new")}})
	if m.rows[0].probing || m.rows[0].status.err == nil || m.rows[0].status.err.Error() != "new" {
		t.Errorf("current answer not applied: probing=%v err=%v", m.rows[0].probing, m.rows[0].status.err)
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
	if view := m.View(); !strings.Contains(view, "VAULT_FORMAT=json") {
		t.Errorf("defaults missing from details:\n%s", view)
	}
}

func TestScrollKeepsCursorVisible(t *testing.T) {
	m, _ := newTestModel(t)
	m.Update(tea.WindowSizeMsg{Width: 60, Height: 7})
	m.Update(tea.KeyMsg{Type: tea.KeyDown})
	if view := m.View(); !strings.Contains(view, "prod") {
		t.Errorf("selected row scrolled out:\n%s", view)
	}
}

func TestStaleTokenStatusIgnored(t *testing.T) {
	m, a := newTestModel(t)
	if err := writeFileAtomic(a.tokenPath("dev"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	slow := m.loadTokens()() // started before the token is forgotten, answers after
	m.Update(m.loadTokens()())
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	_, cmd = m.Update(cmd())
	m.Update(slow)
	m.Update(cmd())
	if m.tokens["dev"] != tokenNone {
		t.Error("late token status brought a forgotten token back")
	}
}

func TestRefreshRetriesConfigErrorsFromProbe(t *testing.T) {
	a, _, _ := newTestApp(t)
	cfg := "contexts:\n  x:\n    VAULT_ADDR: https://127.0.0.1:1\n    VAULT_CACERT: /nonexistent/ca.pem\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := a.loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	m, err := newModel(a, c)
	if err != nil {
		t.Fatal(err)
	}
	cmd := m.probe(0)
	m.Update(cmd())
	if short, _ := m.rows[0].status.shortSummary(); short != "config error" {
		t.Fatalf("status = %q", short)
	}
	gen := m.rows[0].gen
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
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
	a, _, _ := newTestApp(t)
	ok := serve(t, vaultHandler(200, activeBody))
	cfg := "contexts:\n" +
		"  ok:\n    VAULT_ADDR: " + ok + "\n" +
		"  badaddr:\n    VAULT_ADDR: vault.example.com:8200\n" +
		"  down:\n    VAULT_ADDR: " + closedURL(t) + "\n" +
		"  noca:\n    VAULT_ADDR: " + ok + "\n    VAULT_CACERT: /nonexistent/ca.pem\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c := loadTestConfig(t, a)
	press := func(s string) tea.KeyMsg {
		switch s {
		case "down":
			return tea.KeyMsg{Type: tea.KeyDown}
		case "up":
			return tea.KeyMsg{Type: tea.KeyUp}
		case "enter":
			return tea.KeyMsg{Type: tea.KeyEnter}
		}
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}

	for row := range 4 {
		for _, name := range slices.Sorted(maps.Keys(c.Contexts)) {
			if err := writeFileAtomic(a.tokenPath(name), []byte("http://x\nt\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		m, err := newModel(a, c)
		if err != nil {
			t.Fatal(err)
		}
		m.spin.Spinner.FPS = time.Microsecond
		m.Update(tea.WindowSizeMsg{Width: 120, Height: 24})
		drain(t, m, m.Init(), 0)
		m.cursor = row
		name := m.rows[row].status.name
		for _, k := range []string{"r", "l", "s", "x", "down", "up", "enter"} {
			_, cmd := m.Update(press(k))
			drain(t, m, cmd, 0)
			if k == "l" || k == "s" {
				// The command itself does not run in a test; its completion does.
				_, cmd = m.Update(execDoneMsg{i: m.cursor, what: name + " " + k})
				drain(t, m, cmd, 0)
			}
			for _, line := range strings.Split(m.View(), "\n") {
				if lipgloss.Width(line) > 120 {
					t.Errorf("%s after %q: line too wide: %q", name, k, line)
				}
			}
		}
		if want := m.rows[m.cursor].status.name; m.chosen != want {
			t.Errorf("%s: enter chose %q, cursor on %q", name, m.chosen, want)
		}
	}
}

func TestMultilineValueInDetails(t *testing.T) {
	a, _, _ := newTestApp(t)
	cfg := "contexts:\n  x:\n    VAULT_ADDR: http://v\n    VAULT_CACERT_BYTES: |\n      -----BEGIN CERTIFICATE-----\n      MIIB\n      -----END CERTIFICATE-----\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := newModel(a, loadTestConfig(t, a))
	if err != nil {
		t.Fatal(err)
	}
	m.Update(tea.WindowSizeMsg{Width: 150, Height: 30})
	view := m.View()
	if !strings.Contains(view, "VAULT_CACERT_BYTES=-----BEGIN CERTIFICATE-----…") || strings.Contains(view, "MIIB") {
		t.Errorf("details:\n%s", view)
	}
}

func TestForgetBeforeStatusLoads(t *testing.T) {
	m, a := newTestModel(t)
	if err := writeFileAtomic(a.tokenPath("dev"), []byte("http://127.0.0.1:8201\nt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	if cmd == nil {
		t.Fatalf("x refused before token status loaded: %q", m.flash)
	}
	m.Update(cmd())
	if _, err := os.Stat(a.tokenPath("dev")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("token not forgotten: %v", err)
	}
}
