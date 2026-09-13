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

// PreflightReadable asserts this process can READ every path, and when it
// cannot, says who owns the file and what to set (20i.14).
//
// SEPARATE FROM PreflightMounts BECAUSE IT IS NOT FATAL. A mount that is a
// directory is a container that can do nothing, and exiting with the path to
// remove is the whole help. An unreadable file is a guard that can still answer
// Status, so the admin UI shows what is wrong rather than the tile going dead
// (§11) — the reason the certificate copy was never fatal either.
//
// AT STARTUP, AND FOR THE MACAROON ABOVE ALL. LND writes tls.cert 0644 and
// admin.macaroon 0640, so a guard running as the wrong uid copies the certificate
// without complaint and first meets the macaroon inside a gRPC credential, where
// the error arrives with no owner in it. This is the one place both files are
// opened before anything depends on them.
//
// Opened, not judged from the mode bits: whether THIS uid may read depends on
// its groups too, and the open is the question the later read will ask.
func PreflightReadable(paths ...string) error {
	var errs []error
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("guard: cannot read %s: %w", path, withOwnerAdvice(path, err)))
			continue
		}
		_ = f.Close()
	}
	return errors.Join(errs...)
}

// withOwnerAdvice adds who owns path, and what to set, to a permission error;
// any other error it returns untouched. The result still matches
// fs.ErrPermission.
func withOwnerAdvice(path string, err error) error {
	if !errors.Is(err, fs.ErrPermission) {
		return err
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		return err
	}
	return fmt.Errorf("%w. %s", err, unreadableAdvice(filepath.Base(path), info, os.Getuid(), os.Getgid()))
}

// unreadableAdvice says who owns a file this process was refused, and what to
// set so it is not. uid and gid are this process's, passed in so the branch an
// operator hits — a different owner — is testable without a second user.
func unreadableAdvice(name string, info fs.FileInfo, uid, gid int) string {
	ownerUID, ownerGID, ok := fileOwner(info)
	return ownershipAdvice(name, info.Mode().Perm(), ownerUID, ownerGID, ok, uid, gid)
}

// ownershipAdvice is the sentence itself.
//
// RUN_AS_UID and RUN_AS_GID are the plain-Docker template's names for the
// containers' user, not settings this binary reads; they are named because they
// are what the operator edits. On umbrelOS LND's files and the containers
// normally share 1000:1000, which is why this is a plain-Docker message.
//
// IT READS THE BITS THAT APPLY BEFORE BLAMING OWNERSHIP OR MODE. The kernel
// checks exactly one class — owner if the uid matches, else group if the gid
// does, else other — and a class whose read bit is SET that was still refused
// was refused by something else: SELinux or AppArmor labels, an ACL, the mount.
// Telling that operator to chown or chmod sends them away from the cause.
// Supplementary groups are not considered: `user: uid:gid` in compose gives the
// containers none.
func ownershipAdvice(name string, perm fs.FileMode, ownerUID, ownerGID uint32, ok bool, uid, gid int) string {
	readBit := fs.FileMode(0o004)
	switch {
	case ok && int64(ownerUID) == int64(uid):
		readBit = 0o400
	case ok && int64(ownerGID) == int64(gid):
		readBit = 0o040
	}
	switch {
	case ok && perm&readBit != 0:
		return fmt.Sprintf("%s is owned by uid %d:%d and its mode %s already lets this process (%d:%d) "+
			"read it, so neither ownership nor mode is what refuses it; look at the mount, an ACL, or "+
			"SELinux/AppArmor labels", name, ownerUID, ownerGID, perm, uid, gid)
	case !ok:
		return fmt.Sprintf("%s is not readable by the user this process runs as; set RUN_AS_UID and "+
			"RUN_AS_GID to the file's owner, or make it readable by the group RUN_AS_GID names", name)
	case ownerUID == 0:
		// Never "set RUN_AS_UID=0": the template deliberately does not run the
		// containers as root, and DEPLOYING says to stop if the owner is 0.
		return fmt.Sprintf("%s is owned by root (uid 0:%d) and this process runs as %d:%d; do not run "+
			"the app as root — make the file readable by a group and set RUN_AS_GID to it", name, ownerGID, uid, gid)
	case int64(ownerUID) == int64(uid):
		return fmt.Sprintf("%s is owned by uid %d:%d, which this process runs as, so it is the file's "+
			"mode that refuses it; give its owner read permission", name, ownerUID, ownerGID)
	default:
		return fmt.Sprintf("%s is owned by uid %d:%d and this process runs as %d:%d; set RUN_AS_UID=%d and "+
			"RUN_AS_GID=%d, or make the file readable by the group RUN_AS_GID names",
			name, ownerUID, ownerGID, uid, gid, ownerUID, ownerGID)
	}
}
