package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
)

// errSilent ends the program with status 1 but no message: the failure is already on screen.
var errSilent = errors.New("failed")

func isTerminal(f *os.File) bool {
	return term.IsTerminal(f.Fd())
}

func terminalWidth(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok {
		return 0
	}
	width, _, err := term.GetSize(f.Fd())
	if err != nil {
		return 0
	}
	return width
}

type palette struct {
	ok, warn, fail, dim, bold, accent lipgloss.Style
}

// newPalette uses the terminal's own 16 colors, so it follows the user's light or dark theme.
func newPalette(w io.Writer) palette {
	r := lipgloss.NewRenderer(w)
	return palette{
		ok:     r.NewStyle().Foreground(lipgloss.Color("2")),
		warn:   r.NewStyle().Foreground(lipgloss.Color("3")),
		fail:   r.NewStyle().Foreground(lipgloss.Color("1")),
		dim:    r.NewStyle().Foreground(lipgloss.Color("8")),
		bold:   r.NewStyle().Bold(true),
		accent: r.NewStyle().Foreground(lipgloss.Color("5")).Bold(true),
	}
}

func (p palette) level(l level) lipgloss.Style {
	switch l {
	case levelOK:
		return p.ok
	case levelWarn:
		return p.warn
	}
	return p.fail
}

// withSpinner runs fn, animating a spinner on stderr when it is a terminal.
func (a *app) withSpinner(title string, fn func()) {
	f, ok := a.stderr.(*os.File)
	if !ok || !a.stderrTTY {
		fn()
		return
	}
	p := newPalette(f)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		frames := []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
		tick := time.NewTicker(80 * time.Millisecond)
		defer tick.Stop()
		for i := 0; ; i++ {
			fmt.Fprintf(f, "\r%s %s", p.accent.Render(string(frames[i%len(frames)])), p.dim.Render(title))
			select {
			case <-done:
				fmt.Fprint(f, "\r\x1b[2K")
				return
			case <-tick.C:
			}
		}
	})
	fn()
	close(done)
	wg.Wait()
}

// statusColumns lays out contexts as table columns; the first is the current-context marker.
func statusColumns(statuses []contextStatus, current string, tokens map[string]bool) ([]column, []level) {
	cols := []column{
		{header: ""},
		{header: "CONTEXT", min: 8, shrink: 4},
		{header: "ADDRESS", min: 12, shrink: 1},
		{header: "STATUS", min: 10, shrink: 5},
		{header: "LATENCY", right: true, drop: 3},
		{header: "TOKEN", drop: 2},
	}
	levels := make([]level, len(statuses))
	for i, s := range statuses {
		text, lvl := s.shortSummary()
		levels[i] = lvl
		// An empty marker column has zero width and disappears when nothing is current.
		mark, token := "", ""
		if s.name == current {
			mark = "●"
		}
		if tokens[s.name] {
			token = "✓"
		}
		for c, v := range []string{mark, s.name, s.display, text, s.latencyText(), token} {
			cols[c].cells = append(cols[c].cells, v)
		}
	}
	return cols, levels
}

func (a *app) renderStatusTable(statuses []contextStatus, current string) string {
	p := newPalette(a.stdout)
	names := make([]string, len(statuses))
	for i, s := range statuses {
		names[i] = s.name
	}
	tokens, tokenErr := a.tokenStatus(names)
	cols, levels := statusColumns(statuses, current, tokens)
	width := terminalWidth(a.stdout)
	if width <= 0 {
		width = 100
	}
	widths := fitColumns(cols, width, 2)

	var b strings.Builder
	line := func(row int, style func(c int) lipgloss.Style) {
		var parts []string
		for c, col := range cols {
			if widths[c] == 0 {
				continue
			}
			v := col.header
			if row >= 0 {
				v = col.cells[row]
			}
			parts = append(parts, cell(v, widths[c], col.right, style(c)))
		}
		b.WriteString(strings.TrimRight(strings.Join(parts, "  "), " ") + "\n")
	}
	line(-1, func(int) lipgloss.Style { return p.dim })
	for r := range statuses {
		line(r, func(c int) lipgloss.Style {
			switch c {
			case 0:
				return p.accent
			case 1:
				return p.bold
			case 2, 4:
				return p.dim
			case 3:
				return p.level(levels[r])
			}
			return p.ok
		})
	}

	var failed, network, agent bool
	for i, s := range statuses {
		if s.err == nil {
			continue
		}
		if !failed {
			b.WriteString("\n")
			failed = true
		}
		if networkProblem(s.err) {
			network = network || !s.unix
			agent = agent || s.unix
		}
		_, long := classify(s.err)
		text := lipgloss.NewStyle().Width(max(width-2, 20)).Render(s.name + " " + long)
		name, rest, _ := strings.Cut(text, " ")
		fmt.Fprintf(&b, "%s %s %s\n", p.level(levels[i]).Render("✗"), p.bold.Render(name), p.dim.Render(strings.ReplaceAll(rest, "\n", "\n  ")))
	}
	if network {
		b.WriteString(p.dim.Render("  "+networkHint(false)) + "\n")
	}
	if agent {
		b.WriteString(p.dim.Render("  "+networkHint(true)) + "\n")
	}
	if tokenErr != nil {
		fmt.Fprintf(&b, "\n%s %s\n", p.warn.Render("!"), p.dim.Render("token status: "+tokenErr.Error()))
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func (a *app) printUsing(name string, cfg *config) {
	vars, _ := cfg.vars(name, a.home)
	addr := vaultAddr(vars)
	override := a.shellOverride(name)
	if !a.stderrTTY {
		fmt.Fprintf(a.stderr, "using %s (%s)\n", name, addr)
		if override != "" {
			fmt.Fprintf(a.stderr, "note: this shell has %s=%s, it takes precedence\n", envContext, override)
		}
		return
	}
	p := newPalette(a.stderr)
	fmt.Fprintf(a.stderr, "%s %s %s\n", p.accent.Render("●"), p.bold.Render(name), p.dim.Render(addr))
	if override != "" {
		fmt.Fprintln(a.stderr, p.warn.Render(fmt.Sprintf("  this shell has %s=%s, it takes precedence here", envContext, override)))
	}
	// Shown once: the alias is the missing piece for plain `vault` to follow `vctx use`.
	marker := filepath.Join(a.stateDir, "hint-alias")
	if _, err := os.Stat(marker); errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(a.stderr, p.dim.Render("  tip: make plain `vault` follow this choice: alias vault='vctx exec -- vault'"))
		_ = writeFileAtomic(marker, nil, 0o600)
	}
}
