// Package style holds the colors vctx prints with.
package style

import (
	"io"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
)

// Palette styles vctx's output.
type Palette struct {
	OK, Warn, Fail, Dim, Bold, Accent lipgloss.Style
}

// New styles text written to w, with env deciding as the terminal does: no
// styling when w is not a terminal or TERM=dumb, no color with NO_COLOR. The
// colors are the terminal's own 16, so they follow its light or dark theme.
func New(w io.Writer, env []string) Palette {
	profile := colorprofile.Detect(w, env)
	if profile <= colorprofile.NoTTY {
		return Palette{}
	}
	if profile < colorprofile.ANSI {
		return Palette{Bold: lipgloss.NewStyle().Bold(true), Accent: lipgloss.NewStyle().Bold(true)}
	}
	return Full()
}

// Full is the palette for a full-screen program, which downsamples colors
// for the terminal itself.
func Full() Palette {
	color := func(c string) lipgloss.Style { return lipgloss.NewStyle().Foreground(lipgloss.Color(c)) }
	return Palette{
		OK:     color("2"),
		Warn:   color("3"),
		Fail:   color("1"),
		Dim:    color("8"),
		Bold:   lipgloss.NewStyle().Bold(true),
		Accent: color("5").Bold(true),
	}
}
