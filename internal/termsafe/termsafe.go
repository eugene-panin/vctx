// Package termsafe makes text from servers and certificates safe to print.
package termsafe

import (
	"strings"
	"unicode"
)

// String drops control characters from s, which would let it drive the
// terminal (retitle, clear, write the clipboard), and cuts it at limit runes.
func String(s string, limit int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if !unicode.IsPrint(r) {
			continue
		}
		if n == limit {
			b.WriteRune('…')
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
