package table

import (
	"slices"
	"testing"
)

func TestFit(t *testing.T) {
	cols := []Column{
		{Header: "", Cells: []string{"●"}},
		{Header: "CONTEXT", Cells: []string{"matchsystems"}, Min: 8, Shrink: 2},
		{Header: "ADDRESS", Cells: []string{"vault.matchsystems.tech"}, Min: 12, Shrink: 1},
		{Header: "STATUS", Cells: []string{"blocked (HTTP 403)"}, Min: 10, Shrink: 5},
		{Header: "LATENCY", Cells: []string{"300ms"}, Drop: 4},
		{Header: "TOKEN", Cells: []string{"✓"}, Drop: 3},
	}
	tests := []struct {
		total int
		want  []int
	}{
		{200, []int{1, 12, 23, 18, 7, 5}},
		{70, []int{1, 12, 17, 18, 7, 5}}, // address gives way first
		{62, []int{1, 9, 12, 18, 7, 5}},  // then the name
		{55, []int{1, 8, 12, 18, 7, 0}},  // then the token column goes
		{45, []int{1, 8, 12, 18, 0, 0}},  // then latency
		{40, []int{1, 8, 12, 13, 0, 0}},  // status is truncated last
		{20, []int{1, 8, 12, 10, 0, 0}},  // nothing left to give
	}
	for _, tc := range tests {
		if got := Fit(cols, tc.total, 2); !slices.Equal(got, tc.want) {
			t.Errorf("total %d: got %v, want %v", tc.total, got, tc.want)
		}
	}
}
