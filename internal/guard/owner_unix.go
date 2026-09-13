//go:build unix

package guard

import (
	"io/fs"
	"syscall"
)

// fileOwner is the uid and gid that own a file, where the platform says.
//
// UNIX, NOT ONLY LINUX: the guard ships for Linux alone, but syscall.Stat_t
// carries Uid and Gid on every unix, and building it for darwin is what lets the
// owner-naming test run with real numbers on a developer's machine rather than
// only on CI.
func fileOwner(info fs.FileInfo) (uid, gid uint32, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}
