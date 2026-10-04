package main

import (
	"fmt"
	"maps"
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
	prepared
	probing bool
	gen     int // bumped per probe so a late answer from an older one is ignored
}

type probeMsg struct {
	i   int
	gen int
	res probeResult
}

type execDoneMsg struct {
	i    int
	what string
	err  error
}

type tokensMsg struct {
	gen    int
	tokens map[string]tokenState
	err    error
}

type forgetMsg struct {
	name string
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
	// Loaded in the background: with the keychain every lookup runs a process.
	tokens       map[string]tokenState
	tokensLoaded bool
	tokenGen     int // bumped per load, and on forget, so a late answer is ignored
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
		tokens:  map[string]tokenState{},
	}
	m.spin.Style = m.p.accent
	m.current, _ = a.contextName("")
	for _, name := range slices.Sorted(maps.Keys(cfg.Contexts)) {
		p, err := a.prepare(cfg, name)
		if err != nil {
			return nil, err
		}
		if name == m.current {
			m.cursor = len(m.rows)
		}
		m.rows = append(m.rows, row{prepared: p})
	}
	return m, nil
}

func (m *model) Init() tea.Cmd {
	return m.refresh()
}

// refresh reloads token status and probes every context whose address could be resolved.
func (m *model) refresh() tea.Cmd {
	cmds := []tea.Cmd{m.spin.Tick, m.loadTokens()}
	for i := range m.rows {
		cmds = append(cmds, m.probe(i))
	}
	return tea.Batch(cmds...)
}

// probe checks row i again; a row whose address does not resolve has nothing to check.
func (m *model) probe(i int) tea.Cmd {
	if m.rows[i].badAddr {
		return nil
	}
	m.rows[i].probing = true
	m.rows[i].gen++
	p, gen, timeout := m.rows[i].prepared, m.rows[i].gen, m.timeout
	return func() tea.Msg {
		return probeMsg{i: i, gen: gen, res: p.probeHealth(timeout)}
	}
}

func (m *model) loadTokens() tea.Cmd {
	names := make([]string, len(m.rows))
	for i, r := range m.rows {
		names[i] = r.status.name
	}
	m.tokenGen++
	a, cfg, gen := m.a, m.cfg, m.tokenGen
	return func() tea.Msg {
		tokens, err := a.tokenStatus(cfg, names)
		return tokensMsg{gen: gen, tokens: tokens, err: err}
	}
}

func (m *model) forget(name string) tea.Cmd {
	a := m.a
	return func() tea.Msg {
		store, err := a.tokens()
		if err == nil {
			err = store.del(name)
		}
		return forgetMsg{name: name, err: err}
	}
}

func (m *model) probing() bool {
	return slices.ContainsFunc(m.rows, func(r row) bool { return r.probing })
}

func (m *model) setFlash(msg string, ok bool) {
	m.flash, m.flashOK = msg, ok
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmd := m.update(msg)
	m.scroll()
	return m, cmd
}

func (m *model) update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.help.Width = msg.Width
	case spinner.TickMsg:
		if !m.probing() {
			return nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return cmd
	case probeMsg:
		if r := &m.rows[msg.i]; msg.gen == r.gen {
			r.probing = false
			r.status.probeResult = msg.res
		}
	case tokensMsg:
		if msg.gen != m.tokenGen {
			return nil
		}
		m.tokens, m.tokensLoaded = msg.tokens, true
		if msg.err != nil {
			m.setFlash("token status: "+msg.err.Error(), false)
		}
	case forgetMsg:
		if msg.err != nil {
			m.setFlash(msg.err.Error(), false)
		} else {
			m.setFlash(msg.name+": token forgotten", true)
		}
		return m.loadTokens()
	case execDoneMsg:
		if msg.err != nil {
			m.setFlash(fmt.Sprintf("%s: %v", msg.what, msg.err), false)
		} else {
			m.setFlash(msg.what+" finished", true)
		}
		return tea.Batch(m.spin.Tick, m.probe(msg.i), m.loadTokens())
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return nil
}

func (m *model) handleKey(msg tea.KeyMsg) tea.Cmd {
	if key.Matches(msg, keys.Quit) {
		return tea.Quit
	}
	r := &m.rows[m.cursor]
	switch {
	case key.Matches(msg, keys.Up):
		m.cursor = max(m.cursor-1, 0)
	case key.Matches(msg, keys.Down):
		m.cursor = min(m.cursor+1, len(m.rows)-1)
	case key.Matches(msg, keys.Use):
		if err := m.a.use(m.cfg, r.status.name); err != nil {
			m.setFlash(err.Error(), false)
			return nil
		}
		m.chosen = r.status.name
		return tea.Quit
	case key.Matches(msg, keys.Refresh):
		m.flash = ""
		return m.refresh()
	case key.Matches(msg, keys.Login):
		return m.run(m.cursor, "login", m.a.vaultBin(), "login")
	case key.Matches(msg, keys.Shell):
		sh := m.a.getenv("SHELL")
		if sh == "" {
			sh = "/bin/sh"
		}
		return m.run(m.cursor, "shell", sh)
	case key.Matches(msg, keys.Logout):
		if m.tokensLoaded && m.tokens[r.status.name] == tokenNone {
			m.setFlash(r.status.name+": no stored token", false)
			return nil
		}
		m.tokenGen++ // a load already under way would bring the token back
		return m.forget(r.status.name)
	}
	return nil
}

// run suspends the UI and runs a command in the terminal with the context's
// environment, vctx registered as the token helper.
func (m *model) run(i int, what, name string, args ...string) tea.Cmd {
	vars := maps.Clone(m.rows[i].vars)
	if err := m.a.registerHelper(vars); err != nil {
		m.setFlash(err.Error(), false)
		return nil
	}
	env := applyEnv(m.a.environ, vars)
	bin, err := lookPath(name, env)
	if err != nil {
		m.setFlash(err.Error(), false)
		return nil
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	label := m.rows[i].status.name + " " + what
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return execDoneMsg{i: i, what: label, err: err}
	})
}

type layout struct {
	wide           bool // table and details side by side
	detail         bool // details under the table
	tableW, tableH int
	detailW        int
}

func (m *model) layout() layout {
	// One line of header, a blank line after it and one before the footer.
	bodyH := max(m.height-1-lipgloss.Height(m.footerView())-2, 1)
	if m.width >= 110 && bodyH >= 5 {
		detailW := min(max(m.width*2/5, 40), 64)
		return layout{wide: true, tableW: m.width - detailW - 2, tableH: bodyH, detailW: detailW}
	}
	l := layout{tableW: m.width, tableH: bodyH}
	if tableH := bodyH - lipgloss.Height(m.detailView(m.width, 0)) - 1; tableH >= min(len(m.rows)+1, 4) {
		l.tableH, l.detail = tableH, true
	}
	return l
}

// scroll keeps the cursor row inside the visible part of the table.
func (m *model) scroll() {
	if m.width == 0 {
		return
	}
	visible := max(m.layout().tableH-1, 1)
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+visible {
		m.offset = m.cursor - visible + 1
	}
	m.offset = min(m.offset, max(len(m.rows)-visible, 0))
}

func (m *model) View() string {
	if m.width == 0 {
		return ""
	}
	header := m.headerView()
	footer := m.footerView()
	l := m.layout()

	var body string
	switch {
	case l.wide:
		body = lipgloss.JoinHorizontal(lipgloss.Top,
			m.tableView(l.tableW, l.tableH), "  ", m.detailView(l.detailW, l.tableH))
	case l.detail:
		body = m.tableView(l.tableW, l.tableH) + "\n\n" + m.detailView(m.width, 0)
	default:
		body = m.tableView(l.tableW, l.tableH)
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
	if shell := m.a.getenv(envContext); shell != "" {
		current = m.p.dim.Render("this shell ") + m.p.warn.Render(shell) + m.p.dim.Render(" ($"+envContext+")")
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
	cols, levels := statusColumns(statuses, m.current, m.tokens)
	for i, r := range m.rows {
		if r.probing {
			cols[colStatus].cells[i] = "checking"
			cols[colLatency].cells[i] = ""
		}
	}
	const gutter = 2
	widths := fitColumns(cols, width-gutter, 2)
	visible := max(height-1, 1)

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
			if c == colStatus && m.rows[i].probing {
				return m.spin.View() + " checking"
			}
			return cols[c].cells[i]
		}, func(c int) lipgloss.Style {
			return m.p.column(c, levels[i], m.tokens[m.rows[i].status.name], selected, m.rows[i].probing)
		}))
	}
	return strings.Join(lines, "\n")
}

// displayValue hides secrets in a variable shown on screen: values of
// variables named like credentials, and credentials inside URLs.
func displayValue(key, value string) string {
	k := strings.ToUpper(key)
	for _, word := range []string{"TOKEN", "SECRET", "PASS", "CREDENTIAL", "KEY"} {
		if strings.Contains(k, word) {
			return "•••"
		}
	}
	if strings.Contains(value, "://") {
		return redactAddr(value)
	}
	return value
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

	addr, addrKey := addrFrom(func(k string) string { return r.vars[k] })
	var b strings.Builder
	b.WriteString(m.p.accent.Render(r.status.name) + "\n")
	b.WriteString(m.p.dim.Render(truncate(redactAddr(addr), inner)) + "\n\n")

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

	switch m.tokens[r.status.name] {
	case tokenOK:
		b.WriteString(label("token") + m.p.ok.Render("✓ stored") + "\n")
	case tokenStale:
		b.WriteString(label("token") + m.p.warn.Render("for another address, press l to log in") + "\n")
	default:
		b.WriteString(label("token") + m.p.dim.Render("none, press l to log in") + "\n")
	}

	var extra []string
	for _, k := range slices.Sorted(maps.Keys(r.vars)) {
		if k != addrKey && !strings.HasPrefix(k, "VCTX_") {
			v, rest, multiline := strings.Cut(displayValue(k, r.vars[k]), "\n")
			if multiline && rest != "" {
				v += "…"
			}
			extra = append(extra, truncate(k+"="+v, inner-8))
		}
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
	// bubbles/help can overrun its width when the ellipsis does not fit.
	h := truncate(m.help.View(keys), m.width)
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
	if !a.stdinTTY || !a.stdoutTTY {
		return usageError("the interactive UI needs a terminal; use 'vctx use <context>' to set the default")
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	m, err := newModel(a, cfg)
	if err != nil {
		return err
	}
	if _, err := tea.NewProgram(m, tea.WithAltScreen(), tea.WithInput(a.stdin), tea.WithOutput(a.stdout)).Run(); err != nil {
		return err
	}
	if m.chosen != "" {
		a.printUsing(m.chosen, cfg)
	}
	return nil
}
