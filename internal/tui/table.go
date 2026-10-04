package tui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
	"github.com/eugene-panin/vctx/internal/probe"
	"github.com/eugene-panin/vctx/internal/status"
	"github.com/eugene-panin/vctx/internal/style"
	"github.com/eugene-panin/vctx/internal/token"
)

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

// Columns of the status table, in the order statusColumns builds them.
const (
	colMark = iota // current context
	colName
	colAddr
	colStatus
	colLatency
	colToken
)

// column styles a cell of the status table built by statusColumns.
func columnStyle(p style.Palette, c int, lvl status.Level, tok token.State, selected, probing bool) lipgloss.Style {
	switch c {
	case colMark:
		return p.Accent
	case colName:
		if selected {
			return p.Accent
		}
		return p.Bold
	case colAddr, colLatency:
		return p.Dim
	case colStatus:
		if probing {
			return p.Dim
		}
		return levelStyle(p, lvl)
	case colToken:
		if tok == token.Stale {
			return p.Warn
		}
	}
	return p.OK
}

func levelStyle(p style.Palette, l status.Level) lipgloss.Style {
	switch l {
	case status.OK:
		return p.OK
	case status.Warn:
		return p.Warn
	}
	return p.Fail
}

// Spin runs fn, animating a spinner on w when it is a terminal.
func Spin(w io.Writer, tty bool, title string, fn func()) {
	f, ok := w.(*os.File)
	if !ok || !tty {
		fn()
		return
	}
	p := style.New(f)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		frames := []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
		tick := time.NewTicker(80 * time.Millisecond)
		defer tick.Stop()
		for i := 0; ; i++ {
			fmt.Fprintf(f, "\r%s %s", p.Accent.Render(string(frames[i%len(frames)])), p.Dim.Render(title))
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
func statusColumns(statuses []status.Status, current string, tokens map[string]token.State) ([]column, []status.Level) {
	cols := []column{
		colMark:    {header: ""},
		colName:    {header: "CONTEXT", min: 8, shrink: 4},
		colAddr:    {header: "ADDRESS", min: 12, shrink: 1},
		colStatus:  {header: "STATUS", min: 10, shrink: 5},
		colLatency: {header: "LATENCY", right: true, drop: 3},
		colToken:   {header: "TOKEN", drop: 2},
	}
	levels := make([]status.Level, len(statuses))
	for i, s := range statuses {
		text, lvl := s.Short()
		levels[i] = lvl
		// An empty marker column has zero width and disappears when nothing is current.
		mark, tok := "", ""
		if s.Name == current {
			mark = "●"
		}
		switch tokens[s.Name] {
		case token.OK:
			tok = "✓"
		case token.Stale:
			tok = "stale"
		}
		for c, v := range []string{mark, s.Name, s.Display, text, s.LatencyText(), tok} {
			cols[c].cells = append(cols[c].cells, v)
		}
	}
	return cols, levels
}

// StatusTable renders statuses for out, fitted to its width: current marks the
// active context, tokens what each has stored, and tokenErr is shown when
// token status could not be read.
func StatusTable(out io.Writer, statuses []status.Status, current string, tokens map[string]token.State, tokenErr error) string {
	p := style.New(out)
	cols, levels := statusColumns(statuses, current, tokens)
	width := terminalWidth(out)
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
	line(-1, func(int) lipgloss.Style { return p.Dim })
	for r := range statuses {
		line(r, func(c int) lipgloss.Style {
			return columnStyle(p, c, levels[r], tokens[statuses[r].Name], false, false)
		})
	}

	var failed, network, agent bool
	for i, s := range statuses {
		if s.Err == nil {
			continue
		}
		if !failed {
			b.WriteString("\n")
			failed = true
		}
		if probe.NetworkProblem(s.Err) {
			network = network || !s.Unix
			agent = agent || s.Unix
		}
		_, long := probe.Classify(s.Err)
		text := lipgloss.NewStyle().Width(max(width-2, 20)).Render(s.Name + " " + long)
		name, rest, _ := strings.Cut(text, " ")
		fmt.Fprintf(&b, "%s %s %s\n", levelStyle(p, levels[i]).Render("✗"), p.Bold.Render(name), p.Dim.Render(strings.ReplaceAll(rest, "\n", "\n  ")))
	}
	if network {
		b.WriteString(p.Dim.Render("  "+probe.NetworkHint(false)) + "\n")
	}
	if agent {
		b.WriteString(p.Dim.Render("  "+probe.NetworkHint(true)) + "\n")
	}
	if tokenErr != nil {
		fmt.Fprintf(&b, "\n%s %s\n", p.Warn.Render("!"), p.Dim.Render("token status: "+tokenErr.Error()))
	}
	return strings.TrimSuffix(b.String(), "\n")
}
