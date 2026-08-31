package guard

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteCredential replaces path with data, atomically.
//
// It writes a temporary file in the SAME directory and renames over the target,
// and it is the only thing in this package that writes to the credential
// volume. Verified on the reference box (§6, §18): a bind-mount source that is
// absent when a container starts makes Docker create a DIRECTORY at the host
// path, the container dies at exit 127, and the path stays a directory until
// someone removes it. rm-then-write opens exactly that window; rename never
// does, because the target either has the old inode or the new one.
func WriteCredential(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	// The temp file must share the directory: a rename across filesystems is
	// not atomic, and /tmp is a different filesystem in every container.
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("creating a temporary file beside %s: %w", path, err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName) // no-op once the rename succeeds

	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("writing %s: %w", tempName, err)
	}
	// The data must be on disk before the rename, or a crash can leave the
	// target pointing at an empty file.
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("syncing %s: %w", tempName, err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tempName, err)
	}
	if err := os.Chmod(tempName, mode); err != nil {
		return fmt.Errorf("securing %s: %w", tempName, err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replacing %s: %w", path, err)
	}
	return nil
}
