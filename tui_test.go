package main

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

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
	init := true
	m.rows[0].status.probeResult = probeResult{health: &health{Initialized: &init, Version: "1.20.4"}, latency: 280 * time.Millisecond}
	m.rows[0].probing = false
	m.rows[1].status.probeResult = probeResult{err: &notVaultError{status: 403, contentType: "text/html"}}
	m.rows[1].probing = false
	return m, a
}

func TestViewFitsWindow(t *testing.T) {
	m, _ := newTestModel(t)
	for _, size := range [][2]int{{40, 12}, {70, 20}, {90, 8}, {109, 30}, {110, 30}, {180, 50}, {200, 6}} {
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
	for _, w := range []int{60, 150} {
		m.Update(tea.WindowSizeMsg{Width: w, Height: 24})
		if view := m.View(); !strings.Contains(view, "checking") {
			t.Errorf("width %d: no checking state:\n%s", w, view)
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
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
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
