package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type keyMap struct {
	Up, Down, Use, Refresh, Login, Shell, Logout, Quit key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Use, k.Refresh, k.Login, k.Shell, k.Logout, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding { return [][]key.Binding{k.ShortHelp()} }

var keys = keyMap{
	Up:      key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down:    key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	Use:     key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "use")),
	Refresh: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
	Login:   key.NewBinding(key.WithKeys("l"), key.WithHelp("l", "login")),
	Shell:   key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "shell")),
	Logout:  key.NewBinding(key.WithKeys("x"), key.WithHelp("x", "forget token")),
	Quit:    key.NewBinding(key.WithKeys("q", "esc", "ctrl+c"), key.WithHelp("q", "quit")),
}

type row struct {
	name    string
	vars    map[string]string
	env     []string
	status  contextStatus
	probing bool
}

type probeMsg struct {
	i   int
	res probeResult
}

type execDoneMsg struct {
	i    int
	what string
	err  error
}

type model struct {
	a       *app
	cfg     *config
	rows    []row
	cursor  int
	offset  int
	current string
	timeout time.Duration
	width   int
	height  int
	spin    spinner.Model
	help    help.Model
	p       palette
	flash   string
	flashOK bool
	chosen  string
}

func newModel(a *app, cfg *config) (*model, error) {
	timeout, err := a.checkTimeout()
	if err != nil {
		return nil, err
	}
	if timeout == 0 {
		timeout = defaultCheckTimeout
	}
	m := &model{
		a:       a,
		cfg:     cfg,
		timeout: timeout,
		spin:    spinner.New(spinner.WithSpinner(spinner.MiniDot)),
		help:    help.New(),
		p:       newPalette(a.stdout),
	}
	m.spin.Style = m.p.accent
	m.current, _ = a.contextName("")
	for _, name := range slices.Sorted(maps.Keys(cfg.Contexts)) {
		vars, err := a.contextVars(cfg, name)
		if err != nil {
			return nil, err
		}
		env := applyEnv(a.environ, vars)
		t, _ := targetFor(env)
		if name == m.current {
			m.cursor = len(m.rows)
		}
		m.rows = append(m.rows, row{
			name:    name,
			vars:    cfg.Contexts[name],
			env:     env,
			status:  contextStatus{name: name, target: t.String(), display: t.display()},
			probing: true,
		})
	}
	return m, nil
}

func (m *model) Init() tea.Cmd {
	cmds := []tea.Cmd{m.spin.Tick}
	for i := range m.rows {
		cmds = append(cmds, m.probe(i))
	}
	return tea.Batch(cmds...)
}

func (m *model) probe(i int) tea.Cmd {
	m.rows[i].probing = true
	env, timeout := m.rows[i].env, m.timeout
	return func() tea.Msg {
		return probeMsg{i: i, res: probe(context.Background(), env, timeout)}
	}
}

func (m *model) probing() bool {
	return slices.ContainsFunc(m.rows, func(r row) bool { return r.probing })
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.help.Width = msg.Width
	case spinner.TickMsg:
		if !m.probing() {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd
	case probeMsg:
		m.rows[msg.i].probing = false
		m.rows[msg.i].status.probeResult = msg.res
	case execDoneMsg:
		m.flashOK = msg.err == nil
		m.flash = msg.what + " finished"
		if msg.err != nil {
			m.flash = fmt.Sprintf("%s: %v", msg.what, msg.err)
		}
		return m, tea.Batch(m.spin.Tick, m.probe(msg.i))
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if len(m.rows) == 0 {
		if key.Matches(msg, keys.Quit) {
			return m, tea.Quit
		}
		return m, nil
	}
	r := &m.rows[m.cursor]
	switch {
	case key.Matches(msg, keys.Quit):
		return m, tea.Quit
	case key.Matches(msg, keys.Up):
		m.cursor = max(m.cursor-1, 0)
	case key.Matches(msg, keys.Down):
		m.cursor = min(m.cursor+1, len(m.rows)-1)
	case key.Matches(msg, keys.Use):
		if err := m.a.use(m.cfg, r.name); err != nil {
			m.flash, m.flashOK = err.Error(), false
			return m, nil
		}
		m.chosen = r.name
		return m, tea.Quit
	case key.Matches(msg, keys.Refresh):
		cmds := []tea.Cmd{m.spin.Tick}
		for i := range m.rows {
			cmds = append(cmds, m.probe(i))
		}
		m.flash = ""
		return m, tea.Batch(cmds...)
	case key.Matches(msg, keys.Login):
		return m, m.run(m.cursor, "login", m.vaultBin(), "login")
	case key.Matches(msg, keys.Shell):
		sh := m.a.getenv("SHELL")
		if sh == "" {
			sh = "/bin/sh"
		}
		return m, m.run(m.cursor, "shell", sh)
	case key.Matches(msg, keys.Logout):
		err := os.Remove(m.a.tokenPath(r.name))
		switch {
		case errors.Is(err, os.ErrNotExist):
			m.flash, m.flashOK = r.name+": no stored token", false
		case err != nil:
			m.flash, m.flashOK = err.Error(), false
		default:
			m.flash, m.flashOK = r.name+": token forgotten", true
		}
	}
	return m, nil
}

func (m *model) vaultBin() string {
	if bin := m.a.getenv("VCTX_VAULT_BIN"); bin != "" {
		return bin
	}
	return "vault"
}

// run suspends the UI and runs a command in the terminal with the context's environment.
func (m *model) run(i int, what, name string, args ...string) tea.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Env = m.rows[i].env
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return execDoneMsg{i: i, what: m.rows[i].name + " " + what, err: err}
	})
}

func (m *model) View() string {
	if m.width == 0 {
		return ""
	}
	header := m.headerView()
	footer := m.footerView()
	bodyH := max(m.height-lipgloss.Height(header)-lipgloss.Height(footer)-2, 1)

	var body string
	switch {
	case len(m.rows) == 0:
		body = m.p.dim.Render("no contexts in " + m.a.configPath)
	case m.width >= 110 && bodyH >= 5:
		detailW := min(max(m.width*2/5, 40), 64)
		tableW := m.width - detailW - 2
		body = lipgloss.JoinHorizontal(lipgloss.Top,
			m.tableView(tableW, bodyH), "  ", m.detailView(detailW, bodyH))
	default:
		detail := m.detailView(m.width, 0)
		tableH := bodyH - lipgloss.Height(detail) - 1
		if tableH >= min(len(m.rows)+1, 4) {
			body = m.tableView(m.width, tableH) + "\n\n" + detail
		} else {
			body = m.tableView(m.width, bodyH)
		}
	}
	// Pin the key help to the bottom of the screen.
	gap := max(m.height-lipgloss.Height(header)-lipgloss.Height(body)-lipgloss.Height(footer)-1, 1)
	return header + "\n\n" + body + strings.Repeat("\n", gap+1) + footer
}

func (m *model) headerView() string {
	badge := lipgloss.NewStyle().Reverse(true).Bold(true).Foreground(lipgloss.Color("5")).Render(" vctx ")
	current := m.p.dim.Render("no default context")
	if m.current != "" {
		current = m.p.dim.Render("default ") + m.p.bold.Render(m.current)
	}
	ok, done := 0, 0
	for _, r := range m.rows {
		if r.probing {
			continue
		}
		done++
		if _, lvl := r.status.shortSummary(); lvl == levelOK {
			ok++
		}
	}
	summary := m.spin.View() + m.p.dim.Render(" checking")
	if done == len(m.rows) {
		summary = m.p.dim.Render(fmt.Sprintf("%d/%d reachable", ok, len(m.rows)))
	}
	left := badge + "  " + current
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(summary)
	if gap < 2 {
		return truncate(left, m.width)
	}
	return left + strings.Repeat(" ", gap) + summary
}

func (m *model) tableView(width, height int) string {
	statuses := make([]contextStatus, len(m.rows))
	for i, r := range m.rows {
		statuses[i] = r.status
	}
	cols, levels := m.a.statusColumns(statuses, m.current)
	for i, r := range m.rows {
		if r.probing {
			cols[3].cells[i] = "checking"
			cols[4].cells[i] = ""
		}
	}
	const gutter = 2
	widths := fitColumns(cols, width-gutter, 2)

	visible := max(height-1, 1)
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+visible {
		m.offset = m.cursor - visible + 1
	}
	m.offset = min(m.offset, max(len(m.rows)-visible, 0))

	line := func(gut string, value func(c int) string, style func(c int) lipgloss.Style) string {
		var parts []string
		for c, col := range cols {
			if widths[c] > 0 {
				parts = append(parts, cell(value(c), widths[c], col.right, style(c)))
			}
		}
		return truncate(gut+strings.Join(parts, "  "), width)
	}
	lines := []string{line("  ", func(c int) string { return cols[c].header }, func(int) lipgloss.Style { return m.p.dim })}
	for i := m.offset; i < min(m.offset+visible, len(m.rows)); i++ {
		selected := i == m.cursor
		gut := "  "
		if selected {
			gut = m.p.accent.Render("▌") + " "
		}
		lines = append(lines, line(gut, func(c int) string {
			if c == 3 && m.rows[i].probing {
				return m.spin.View() + " checking"
			}
			return cols[c].cells[i]
		}, func(c int) lipgloss.Style {
			switch c {
			case 0:
				return m.p.accent
			case 1:
				if selected {
					return m.p.accent
				}
				return m.p.bold
			case 2, 4:
				return m.p.dim
			case 3:
				if m.rows[i].probing {
					return m.p.dim
				}
				return m.p.level(levels[i])
			}
			return m.p.ok
		}))
	}
	return strings.Join(lines, "\n")
}

// detailView renders the selected context, cut to height lines unless height is 0.
func (m *model) detailView(width, height int) string {
	r := m.rows[m.cursor]
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("8")).
		Padding(0, 1).
		Width(width - 2)
	inner := width - 4

	label := func(s string) string { return m.p.dim.Render(fmt.Sprintf("%-8s", s)) }
	wrap := func(s string, indent int) string {
		return lipgloss.NewStyle().Width(max(inner-indent, 10)).Render(s)
	}

	var b strings.Builder
	b.WriteString(m.p.accent.Render(r.name) + "\n")
	b.WriteString(m.p.dim.Render(truncate(r.vars["VAULT_ADDR"], inner)) + "\n\n")

	switch text, lvl := r.status.shortSummary(); {
	case r.probing:
		b.WriteString(label("status") + m.spin.View() + m.p.dim.Render(" checking") + "\n")
	case r.status.err != nil:
		_, long := classify(r.status.err)
		b.WriteString(label("status") + m.p.level(lvl).Render(text) + "\n")
		b.WriteString(indentLines(m.p.dim.Render(wrap(long, 8)), 8) + "\n")
	default:
		b.WriteString(label("status") + m.p.level(lvl).Render(text) + m.p.dim.Render("  "+r.status.latencyText()) + "\n")
	}

	if m.a.hasToken(r.name) {
		b.WriteString(label("token") + m.p.ok.Render("✓ stored") + "\n")
	} else {
		b.WriteString(label("token") + m.p.dim.Render("none, press l to log in") + "\n")
	}

	var extra []string
	for _, k := range slices.Sorted(maps.Keys(r.vars)) {
		if k == "VAULT_ADDR" {
			continue
		}
		v := r.vars[k]
		if k == "VAULT_TOKEN" {
			v = "•••"
		}
		extra = append(extra, truncate(k+"="+v, inner-8))
	}
	if len(extra) > 0 {
		b.WriteString(label("vars") + strings.Join(extra, "\n"+strings.Repeat(" ", 8)) + "\n")
	}

	content := strings.TrimSuffix(b.String(), "\n")
	if lines := strings.Split(content, "\n"); height > 0 && len(lines) > height-2 {
		content = strings.Join(lines[:max(height-2, 1)], "\n")
	}
	return box.Render(content)
}

func (m *model) footerView() string {
	h := m.help.View(keys)
	if m.flash == "" {
		return h
	}
	style := m.p.fail
	if m.flashOK {
		style = m.p.ok
	}
	return truncate(style.Render(m.flash), m.width) + "\n" + h
}

func truncate(s string, w int) string {
	if lipgloss.Width(s) <= w {
		return s
	}
	return cell(s, w, false, lipgloss.NewStyle())
}

func indentLines(s string, n int) string {
	pad := strings.Repeat(" ", n)
	return pad + strings.ReplaceAll(s, "\n", "\n"+pad)
}

// ui runs the full-screen interface; picking a context with enter makes it the default.
func (a *app) ui() error {
	if !isTerminal(a.stdin) || !isTerminal(a.stdout) {
		return errors.New("the interactive UI needs a terminal, see 'vctx help'")
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	m, err := newModel(a, cfg)
	if err != nil {
		return err
	}
	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		return err
	}
	if m.chosen != "" {
		a.printUsing(m.chosen, cfg)
	}
	return nil
}
