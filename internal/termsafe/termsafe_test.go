package termsafe

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	tests := []struct{ in, want string }{
		{"1.0\x1b]0;PWNED\x07\x1b[2J", "1.0]0;PWNED[2J"},
		{"line\nbreak\r\ttab", "linebreaktab"},
		{"ключ", "ключ"},
		{strings.Repeat("a", 50), strings.Repeat("a", 40) + "…"},
		{strings.Repeat("a", 40), strings.Repeat("a", 40)},
	}
	for _, tc := range tests {
		if got := String(tc.in, 40); got != tc.want {
			t.Errorf("String(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
