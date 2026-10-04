// Package style holds the colors vctx prints with.
package style

import (
	"io"

	"github.com/charmbracelet/lipgloss"
)

// Palette styles vctx's output.
type Palette struct {
	OK, Warn, Fail, Dim, Bold, Accent lipgloss.Style
}

// New uses the terminal's own 16 colors, so it follows the user's light or dark theme.
func New(w io.Writer) Palette {
	r := lipgloss.NewRenderer(w)
	return Palette{
		OK:     r.NewStyle().Foreground(lipgloss.Color("2")),
		Warn:   r.NewStyle().Foreground(lipgloss.Color("3")),
		Fail:   r.NewStyle().Foreground(lipgloss.Color("1")),
		Dim:    r.NewStyle().Foreground(lipgloss.Color("8")),
		Bold:   r.NewStyle().Bold(true),
		Accent: r.NewStyle().Foreground(lipgloss.Color("5")).Bold(true),
	}
}
