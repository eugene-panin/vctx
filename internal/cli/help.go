package cli

import (
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// helpWins turns a flag error into help when -h or --help is on the line
// (before a "--" that starts a command), so help never loses to a typo.
func helpWins(rawArgs []string) func(*cobra.Command, error) error {
	return func(c *cobra.Command, err error) error {
		for _, arg := range rawArgs {
			if arg == "--" {
				break
			}
			if arg == "-h" || arg == "--help" {
				return pflag.ErrHelp
			}
		}
		return usageError(err.Error() + " (see '" + c.CommandPath() + " -h')")
	}
}

// suggest returns the candidate closest to word, if one is close enough to be a typo.
func suggest(word string, candidates []string) string {
	best, bestDist := "", 3
	if len(word) <= 4 {
		bestDist = 2
	}
	for _, c := range candidates {
		if strings.HasPrefix(c, "-") || slices.Contains([]string{"get", "store", "erase"}, c) {
			continue
		}
		if d := editDistance(word, c); d < bestDist {
			best, bestDist = c, d
		}
	}
	return best
}

// editDistance is the Levenshtein distance between a and b.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
