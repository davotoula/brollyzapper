//go:build !unix

package guard

import "io/fs"

// fileOwner reports no owner off unix: there is no uid to name, and
// ownershipAdvice says so rather than inventing one.
func fileOwner(fs.FileInfo) (uid, gid uint32, ok bool) { return 0, 0, false }
