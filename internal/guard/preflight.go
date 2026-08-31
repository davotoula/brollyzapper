package guard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrMountIsDirectory means Docker created a directory where a single-file bind
// mount should be — which happens whenever the container is created while the
// source file is absent (§6, box-verified 2026-08-21).
var ErrMountIsDirectory = errors.New("guard: the mount source is a directory, not a file")

// PreflightCredentialsDir asserts the guard can actually write the credential
// volume, and says what to do when it cannot.
//
// This matters more since d46.26 put `data/credentials` in the manifest's
// backupIgnore: a RESTORE therefore arrives without that directory, Docker
// creates the bind-mount source itself, and what Docker creates is owned by
// root — while both containers run as uid 1000. The symptom would be a bake
// that succeeds against the node and then fails to write, which reads like a
// bake failure and is not.
//
// The package ships data/credentials/.gitkeep so a fresh INSTALL has it with
// the right owner; this is for every other way it can go missing.
func PreflightCredentialsDir(dir string) error {
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("guard: the credential volume %s does not exist", dir)
	case err != nil:
		return fmt.Errorf("guard: cannot stat %s: %w", dir, err)
	case !info.IsDir():
		return fmt.Errorf("guard: %s is not a directory", dir)
	}
	// Proved by writing, not by reading a mode: the mode says nothing about
	// whether THIS uid owns it, and ownership is what a restore gets wrong.
	// Through WriteCredential, not os.WriteFile: it is the guard's only writer
	// (§6, arch-enforced), and using it here proves the REAL write path — temp
	// file, rename, mode — rather than merely that the directory is writable.
	probe := filepath.Join(dir, ".write-probe")
	if err := WriteCredential(probe, nil, 0o600); err != nil {
		return fmt.Errorf("guard: cannot write to the credential volume %s: %w.\n"+
			"On Umbrel this is usually ownership: the containers run as uid 1000 and a "+
			"directory docker created itself is owned by root. Fix with "+
			"`sudo chown -R 1000:1000 <APP_DATA_DIR>/data/credentials` and restart", dir, err)
	}
	return os.Remove(probe)
}

// PreflightMounts asserts every path is a regular file before anything else
// runs.
//
// Without this the failure is Docker's: exit 127, "not a directory", and a
// directory left at the host path that has to be removed by hand. The operator
// gets nothing to work with. A named error tells them exactly what to delete.
func PreflightMounts(paths ...string) error {
	for _, path := range paths {
		info, err := os.Stat(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("guard: %s does not exist; the mount from the lightning app is missing", path)
		case err != nil:
			return fmt.Errorf("guard: cannot stat %s: %w", path, err)
		case info.IsDir():
			return fmt.Errorf("guard: %s is a directory; docker created it because the file was "+
				"absent when the container started. Remove it (rm -rf %s), make sure the source "+
				"file exists, and restart: %w", path, path, ErrMountIsDirectory)
		case !info.Mode().IsRegular():
			return fmt.Errorf("guard: %s is not a regular file (mode %s)", path, info.Mode())
		}
	}
	return nil
}
