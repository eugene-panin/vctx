// Package safefile writes files atomically and refuses ones others could modify.
package safefile

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// Write writes data to path through a temporary file in the same directory,
// renamed into place, creating the directory with mode 0700 if needed.
func Write(path string, data []byte, perm fs.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(f.Name())
		}
	}()
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// CheckPrivate refuses a file or directory another user could modify, as ssh does:
// the config decides which variables (PATH included) vault runs with, and the
// state directory holds the token helper setting vault executes.
func CheckPrivate(path string, fi fs.FileInfo) error {
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others (mode %04o), fix with: chmod go-w %s", path, perm, path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by another user", path)
	}
	return nil
}
