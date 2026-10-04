// Package tui is vctx's full-screen interface to switch contexts and log in.
package tui

import (
	"fmt"
	"io"
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
	"github.com/eugene-panin/vctx/internal/config"
	"github.com/eugene-panin/vctx/internal/environ"
	"github.com/eugene-panin/vctx/internal/probe"
	"github.com/eugene-panin/vctx/internal/style"
	"github.com/eugene-panin/vctx/internal/table"
	"github.com/eugene-panin/vctx/internal/token"
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
	probe.Instance
	login   []string // the login method, from the config or remembered
	probing bool
	gen     int // bumped per probe so a late answer from an older one is ignored
}

type probeMsg struct {
	i   int
	gen int
	res probe.Result
}

type execDoneMsg struct {
	i    int
	what string
	err  error
}

type tokensMsg struct {
	gen    int
	tokens map[string]token.State
	err    error
}

type forgetMsg struct {
	name string
	err  error
}

type model struct {
	b       Backend
	rows    []row
	cursor  int
	offset  int
	current string
	timeout time.Duration
	width   int
	height  int
	spin    spinner.Model
	help    help.Model
	p       style.Palette
	flash   string
	flashOK bool
	chosen  string
	// Loaded in the background: with the keychain every lookup runs a process.
	tokens       map[string]token.State
	tokensLoaded bool
	tokenGen     int // bumped per load, and on forget, so a late answer is ignored
}

func newModel(b Backend, contexts []probe.Instance, timeout time.Duration, out io.Writer) *model {
	if timeout == 0 {
		timeout = probe.DefaultTimeout
	}
	m := &model{
		b:       b,
		timeout: timeout,
		spin:    spinner.New(spinner.WithSpinner(spinner.MiniDot)),
		help:    help.New(),
		p:       style.New(out),
		tokens:  map[string]token.State{},
		current: b.Current(),
	}
	m.spin.Style = m.p.Accent
	for _, c := range contexts {
		if c.Status.Name == m.current {
			m.cursor = len(m.rows)
		}
		m.rows = append(m.rows, row{Instance: c, login: b.LoginMethod(c.Status.Name)})
	}
	return m
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
	if m.rows[i].BadAddr {
		return nil
	}
	m.rows[i].probing = true
	m.rows[i].gen++
	p, gen, timeout := m.rows[i].Instance, m.rows[i].gen, m.timeout
	return func() tea.Msg {
		return probeMsg{i: i, gen: gen, res: p.Probe(timeout)}
	}
}

func (m *model) loadTokens() tea.Cmd {
	names := make([]string, len(m.rows))
	for i, r := range m.rows {
		names[i] = r.Status.Name
	}
	m.tokenGen++
	b, gen := m.b, m.tokenGen
	return func() tea.Msg {
		tokens, err := b.TokenStatus(names)
		return tokensMsg{gen: gen, tokens: tokens, err: err}
	}
}

func (m *model) forget(name string) tea.Cmd {
	b := m.b
	return func() tea.Msg {
		return forgetMsg{name: name, err: b.Forget(name)}
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
			r.Status.Result = msg.res
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
		m.current = m.b.Current() // `vctx use` may have run in the shell
		m.rows[msg.i].login = m.b.LoginMethod(m.rows[msg.i].Status.Name)
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
		if err := m.b.Use(r.Status.Name); err != nil {
			m.setFlash(err.Error(), false)
			return nil
		}
		m.chosen = r.Status.Name
		return tea.Quit
	case key.Matches(msg, keys.Refresh):
		m.flash = ""
		return m.refresh()
	case key.Matches(msg, keys.Login):
		i, name := m.cursor, r.Status.Name
		return tea.Exec(m.b.Login(name), func(err error) tea.Msg {
			return execDoneMsg{i: i, what: name + " login", err: err}
		})
	case key.Matches(msg, keys.Shell):
		sh := m.b.Getenv("SHELL")
		if sh == "" {
			sh = "/bin/sh"
		}
		return m.run(m.cursor, "shell", sh)
	case key.Matches(msg, keys.Logout):
		if m.tokensLoaded && m.tokens[r.Status.Name] == token.None {
			m.setFlash(r.Status.Name+": no stored token", false)
			return nil
		}
		m.tokenGen++ // a load already under way would bring the token back
		return m.forget(r.Status.Name)
	}
	return nil
}

// run suspends the UI and runs a command in the terminal with the context's
// environment, vctx registered as the token helper.
func (m *model) run(i int, what, name string, args ...string) tea.Cmd {
	env, err := m.b.CommandEnv(m.rows[i].Vars)
	if err != nil {
		m.setFlash(err.Error(), false)
		return nil
	}
	bin, err := environ.LookPath(name, env)
	if err != nil {
		m.setFlash(err.Error(), false)
		return nil
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	label := m.rows[i].Status.Name + " " + what
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
	current := m.p.Dim.Render("no default context")
	if m.current != "" {
		current = m.p.Dim.Render("default ") + m.p.Bold.Render(m.current)
	}
	if shell := m.b.Getenv(environ.Context); shell != "" {
		current = m.p.Dim.Render("this shell ") + m.p.Warn.Render(shell) + m.p.Dim.Render(" ($"+environ.Context+")")
	}
	ok, done := 0, 0
	for _, r := range m.rows {
		if r.probing {
			continue
		}
		done++
		if _, lvl := r.Status.Short(); lvl == probe.OK {
			ok++
		}
	}
	summary := m.spin.View() + m.p.Dim.Render(" checking")
	if done == len(m.rows) {
		summary = m.p.Dim.Render(fmt.Sprintf("%d/%d reachable", ok, len(m.rows)))
	}
	left := badge + "  " + current
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(summary)
	if gap < 2 {
		return truncate(left, m.width)
	}
	return left + strings.Repeat(" ", gap) + summary
}

func (m *model) tableView(width, height int) string {
	statuses := make([]probe.Status, len(m.rows))
	for i, r := range m.rows {
		statuses[i] = r.Status
	}
	cols, levels := table.Columns(statuses, m.current, m.tokens)
	for i, r := range m.rows {
		if r.probing {
			cols[table.ColStatus].Cells[i] = "checking"
			cols[table.ColLatency].Cells[i] = ""
		}
	}
	const gutter = 2
	widths := table.Fit(cols, width-gutter, 2)
	visible := max(height-1, 1)

	line := func(gut string, value func(c int) string, style func(c int) lipgloss.Style) string {
		var parts []string
		for c, col := range cols {
			if widths[c] > 0 {
				parts = append(parts, table.Cell(value(c), widths[c], col.Right, style(c)))
			}
		}
		return truncate(gut+strings.Join(parts, "  "), width)
	}
	lines := []string{line("  ", func(c int) string { return cols[c].Header }, func(int) lipgloss.Style { return m.p.Dim })}
	for i := m.offset; i < min(m.offset+visible, len(m.rows)); i++ {
		selected := i == m.cursor
		gut := "  "
		if selected {
			gut = m.p.Accent.Render("▌") + " "
		}
		lines = append(lines, line(gut, func(c int) string {
			if c == table.ColStatus && m.rows[i].probing {
				return m.spin.View() + " checking"
			}
			return cols[c].Cells[i]
		}, func(c int) lipgloss.Style {
			return table.CellStyle(m.p, c, levels[i], m.tokens[m.rows[i].Status.Name], selected, m.rows[i].probing)
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
		return config.RedactAddr(value)
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

	label := func(s string) string { return m.p.Dim.Render(fmt.Sprintf("%-8s", s)) }
	wrap := func(s string, indent int) string {
		return lipgloss.NewStyle().Width(max(inner-indent, 10)).Render(s)
	}

	addr, addrKey := config.AddrFrom(func(k string) string { return r.Vars[k] })
	var b strings.Builder
	b.WriteString(m.p.Accent.Render(r.Status.Name) + "\n")
	b.WriteString(m.p.Dim.Render(truncate(config.RedactAddr(addr), inner)) + "\n\n")

	switch text, lvl := r.Status.Short(); {
	case r.probing:
		b.WriteString(label("status") + m.spin.View() + m.p.Dim.Render(" checking") + "\n")
	case r.Status.Err != nil:
		_, long := probe.Classify(r.Status.Err)
		b.WriteString(label("status") + table.LevelStyle(m.p, lvl).Render(text) + "\n")
		b.WriteString(indentLines(m.p.Dim.Render(wrap(long, 8)), 8) + "\n")
	default:
		b.WriteString(label("status") + table.LevelStyle(m.p, lvl).Render(text) + m.p.Dim.Render("  "+r.Status.LatencyText()) + "\n")
	}

	if args := r.login; args != nil {
		b.WriteString(label("login") + m.p.Dim.Render(truncate(strings.Join(args, " "), inner-8)) + "\n")
	}
	switch m.tokens[r.Status.Name] {
	case token.OK:
		b.WriteString(label("token") + m.p.OK.Render("✓ stored") + "\n")
	case token.Stale:
		b.WriteString(label("token") + m.p.Warn.Render("for another address, press l to log in") + "\n")
	default:
		b.WriteString(label("token") + m.p.Dim.Render("none, press l to log in") + "\n")
	}

	var extra []string
	for _, k := range slices.Sorted(maps.Keys(r.Vars)) {
		if k != addrKey && !strings.HasPrefix(k, "VCTX_") {
			v, rest, multiline := strings.Cut(displayValue(k, r.Vars[k]), "\n")
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
	style := m.p.Fail
	if m.flashOK {
		style = m.p.OK
	}
	return truncate(style.Render(m.flash), m.width) + "\n" + h
}

func truncate(s string, w int) string {
	if lipgloss.Width(s) <= w {
		return s
	}
	return table.Cell(s, w, false, lipgloss.NewStyle())
}

func indentLines(s string, n int) string {
	pad := strings.Repeat(" ", n)
	return pad + strings.ReplaceAll(s, "\n", "\n"+pad)
}

// Backend is what the UI needs from the rest of vctx.
type Backend interface {
	// Current is the active context: the shell's, else the default.
	Current() string
	// Use makes name the default context.
	Use(name string) error
	// LoginMethod is the `vault login` arguments name logs in with, nil if unknown.
	LoginMethod(name string) []string
	TokenStatus(names []string) (map[string]token.State, error)
	Forget(name string) error
	// CommandEnv is the environment for a command run in a context with vars,
	// vctx being vault's token helper.
	CommandEnv(vars map[string]string) ([]string, error)
	// Login logs in to name with the terminal handed over.
	Login(name string) tea.ExecCommand
	Getenv(key string) string
}

// Run shows the interface until the user quits or picks a context with
// enter, which it returns after b.Use has made it the default.
func Run(b Backend, contexts []probe.Instance, timeout time.Duration, in io.Reader, out io.Writer) (chosen string, err error) {
	m := newModel(b, contexts, timeout, out)
	if _, err := tea.NewProgram(m, tea.WithAltScreen(), tea.WithInput(in), tea.WithOutput(out)).Run(); err != nil {
		return "", err
	}
	return m.chosen, nil
}
