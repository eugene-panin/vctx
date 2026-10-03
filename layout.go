package main

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

type column struct {
	header string
	cells  []string
	min    int  // narrowest width the column is truncated to
	shrink int  // when the column gives up width; 0 never
	drop   int  // when the column is hidden; 0 never
	right  bool // right-aligned
}

// fitColumns returns a width per column so that a row fits into total cells; 0 hides a column.
// Shrinking and hiding share one sequence: the lowest shrink or drop number goes first.
func fitColumns(cols []column, total, gap int) []int {
	widths := make([]int, len(cols))
	for i, c := range cols {
		widths[i] = lipgloss.Width(c.header)
		for _, cell := range c.cells {
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
			if c.shrink > 0 && widths[i] > c.min && (best < 0 || c.shrink < bestOrder) {
				best, bestOrder, hide = i, c.shrink, false
			}
			if c.drop > 0 && widths[i] > 0 && (best < 0 || c.drop < bestOrder) {
				best, bestOrder, hide = i, c.drop, true
			}
		}
		switch {
		case best < 0:
			return widths
		case hide:
			widths[best] = 0
		default:
			widths[best] = max(cols[best].min, widths[best]-over)
		}
	}
	return widths
}

// cell truncates s to width w and pads it, applying style to the text only.
func cell(s string, w int, right bool, style lipgloss.Style) string {
	s = ansi.Truncate(s, w, "…")
	pad := strings.Repeat(" ", max(w-lipgloss.Width(s), 0))
	if right {
		return pad + style.Render(s)
	}
	return style.Render(s) + pad
}
