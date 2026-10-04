package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "new", "f")
	if err := Write(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v, %v", fi, err)
	}
	if err := CheckPrivate(p, fi); err != nil {
		t.Error(err)
	}
	dir, _ := os.Stat(filepath.Dir(p))
	if dir.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v", dir.Mode())
	}
	if entries, _ := os.ReadDir(filepath.Dir(p)); len(entries) != 1 {
		t.Errorf("temporary file left: %v", entries)
	}
}

func TestCheckPrivate(t *testing.T) {
	tests := []struct {
		name string
		fi   fakeInfo
		want string
	}{
		{"group writable", fakeInfo{mode: 0o660}, "writable by group or others"},
		{"other user", fakeInfo{mode: 0o600, sys: &syscall.Stat_t{Uid: uint32(os.Getuid() + 1)}}, "another user"},
	}
	for _, tc := range tests {
		if err := CheckPrivate("cfg", tc.fi); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
	if err := CheckPrivate("cfg", fakeInfo{mode: 0o644}); err != nil {
		t.Errorf("0644: %v", err)
	}
}

type fakeInfo struct {
	mode os.FileMode
	sys  any
}

func (f fakeInfo) Name() string       { return "f" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any           { return f.sys }
