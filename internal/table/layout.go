package table

import (
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// Column is a table column and its cells, with how it gives up width when
// the table does not fit.
type Column struct {
	Header string
	Cells  []string
	Min    int  // narrowest width the column is truncated to
	Shrink int  // when the column gives up width; 0 never
	Drop   int  // when the column is hidden; 0 never
	Right  bool // right-aligned
}

// Fit returns a width per column so that a row fits into total cells; 0 hides a column.
// Shrinking and hiding share one sequence: the lowest shrink or drop number goes first.
func Fit(cols []Column, total, gap int) []int {
	widths := make([]int, len(cols))
	for i, c := range cols {
		widths[i] = lipgloss.Width(c.Header)
		for _, cell := range c.Cells {
			widths[i] = max(widths[i], lipgloss.Width(cell))
		}
	}
	sum := func() int {
		n, visible := 0, 0
		for _, w := range widths {
			if w > 0 {
				n += w
				visible++
			}
		}
		return n + gap*max(visible-1, 0)
	}

	for over := sum() - total; over > 0; over = sum() - total {
		best, bestOrder, hide := -1, 0, false
		for i, c := range cols {
			if c.Shrink > 0 && widths[i] > c.Min && (best < 0 || c.Shrink < bestOrder) {
				best, bestOrder, hide = i, c.Shrink, false
			}
			if c.Drop > 0 && widths[i] > 0 && (best < 0 || c.Drop < bestOrder) {
				best, bestOrder, hide = i, c.Drop, true
			}
		}
		switch {
		case best < 0:
			return widths
		case hide:
			widths[best] = 0
		default:
			widths[best] = max(cols[best].Min, widths[best]-over)
		}
	}
	return widths
}

// Cell truncates s to width w and pads it, applying style to the text only.
func Cell(s string, w int, right bool, style lipgloss.Style) string {
	s = ansi.Truncate(s, w, "…")
	pad := strings.Repeat(" ", max(w-lipgloss.Width(s), 0))
	if right {
		return pad + style.Render(s)
	}
	return style.Render(s) + pad
}
