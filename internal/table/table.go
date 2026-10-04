// Package table lays out the status of contexts as a table fitted to the terminal.
package table

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
	"github.com/eugene-panin/vctx/internal/probe"
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

// Columns of the status table, in the order Columns builds them.
const (
	ColMark = iota // current context
	ColName
	ColAddr
	ColStatus
	ColLatency
	ColToken
)

// CellStyle styles a cell of the status table built by Columns.
func CellStyle(p style.Palette, c int, lvl probe.Level, tok token.State, selected, probing bool) lipgloss.Style {
	switch c {
	case ColMark:
		return p.Accent
	case ColName:
		if selected {
			return p.Accent
		}
		return p.Bold
	case ColAddr, ColLatency:
		return p.Dim
	case ColStatus:
		if probing {
			return p.Dim
		}
		return LevelStyle(p, lvl)
	case ColToken:
		if tok == token.Stale {
			return p.Warn
		}
	}
	return p.OK
}

func LevelStyle(p style.Palette, l probe.Level) lipgloss.Style {
	switch l {
	case probe.OK:
		return p.OK
	case probe.Warn:
		return p.Warn
	}
	return p.Fail
}

// Columns lays out contexts as table columns; the first is the current-context marker.
func Columns(statuses []probe.Status, current string, tokens map[string]token.State) ([]Column, []probe.Level) {
	cols := []Column{
		ColMark:    {Header: ""},
		ColName:    {Header: "CONTEXT", Min: 8, Shrink: 4},
		ColAddr:    {Header: "ADDRESS", Min: 12, Shrink: 1},
		ColStatus:  {Header: "STATUS", Min: 10, Shrink: 5},
		ColLatency: {Header: "LATENCY", Right: true, Drop: 3},
		ColToken:   {Header: "TOKEN", Drop: 2},
	}
	levels := make([]probe.Level, len(statuses))
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
			cols[c].Cells = append(cols[c].Cells, v)
		}
	}
	return cols, levels
}

// Render renders statuses for out, fitted to its width: current marks the
// active context, tokens what each has stored, and tokenErr is shown when
// token status could not be read.
func Render(out io.Writer, statuses []probe.Status, current string, tokens map[string]token.State, tokenErr error) string {
	p := style.New(out)
	cols, levels := Columns(statuses, current, tokens)
	width := terminalWidth(out)
	if width <= 0 {
		width = 100
	}
	widths := Fit(cols, width, 2)

	var b strings.Builder
	line := func(row int, style func(c int) lipgloss.Style) {
		var parts []string
		for c, col := range cols {
			if widths[c] == 0 {
				continue
			}
			v := col.Header
			if row >= 0 {
				v = col.Cells[row]
			}
			parts = append(parts, Cell(v, widths[c], col.Right, style(c)))
		}
		b.WriteString(strings.TrimRight(strings.Join(parts, "  "), " ") + "\n")
	}
	line(-1, func(int) lipgloss.Style { return p.Dim })
	for r := range statuses {
		line(r, func(c int) lipgloss.Style {
			return CellStyle(p, c, levels[r], tokens[statuses[r].Name], false, false)
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
		fmt.Fprintf(&b, "%s %s %s\n", LevelStyle(p, levels[i]).Render("✗"), p.Bold.Render(name), p.Dim.Render(strings.ReplaceAll(rest, "\n", "\n  ")))
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
