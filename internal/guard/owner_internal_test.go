package guard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unreadableFile is a real file this process cannot read, so the owner comes
// off a real stat rather than a value the test made up.
func unreadableFile(t *testing.T) (string, fs.FileInfo) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("SKIPPED: running as root, which reads a mode-0000 file anyway")
	}
	path := filepath.Join(t.TempDir(), "tls.cert")
	if err := os.WriteFile(path, []byte("certificate"), 0o000); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, info
}

// THE ADVICE NAMES THE OWNER AND THE TWO SETTINGS (20i.14). DEPLOYING step 3
// had the operator run stat, read two numbers and type them into .env; the guard
// already knew both numbers at the moment it failed, and said neither.
//
// The owner comes off a real file; only "who this process is" is supplied, so
// the branch where the two differ — the one an operator actually hits — runs
// here without the test needing a second user.
func TestUnreadableAdviceNamesTheOwnerAndTheSettings(t *testing.T) {
	_, info := unreadableFile(t)
	owner, group := os.Getuid(), os.Getgid()
	self := owner + 1

	got := unreadableAdvice("tls.cert", info, self, group+1)

	for _, want := range []string{
		fmt.Sprintf("owned by uid %d:%d", owner, group),
		fmt.Sprintf("runs as %d:%d", self, group+1),
		fmt.Sprintf("RUN_AS_UID=%d", owner),
		fmt.Sprintf("RUN_AS_GID=%d", group),
	} {
		if !strings.Contains(got, want) {
			t.Errorf("advice = %q, want it to contain %q", got, want)
		}
	}
}

// A ROOT-OWNED FILE MUST NOT PRODUCE "set RUN_AS_UID=0". DEPLOYING says "if those
// print 0, stop": the template deliberately never runs the containers as root,
// and a message that typed the root uid into .env for the operator would undo
// that in one copy-paste.
func TestUnreadableAdviceNeverSuggestsRunningAsRoot(t *testing.T) {
	got := ownershipAdvice("admin.macaroon", 0o640, 0, 0, true, 1000, 1000)
	if strings.Contains(got, "RUN_AS_UID=0") {
		t.Errorf("advice = %q, which tells the operator to run the app as root", got)
	}
	for _, want := range []string{"root", "RUN_AS_GID"} {
		if !strings.Contains(got, want) {
			t.Errorf("advice = %q, want it to contain %q", got, want)
		}
	}
}

// The same uid cannot be fixed by RUN_AS_UID, so the advice must not offer it.
func TestUnreadableAdviceForTheProcessesOwnFileBlamesTheMode(t *testing.T) {
	got := ownershipAdvice("tls.cert", 0o000, 1000, 1000, true, 1000, 1000)
	if strings.Contains(got, "RUN_AS_UID=") {
		t.Errorf("advice = %q, but changing RUN_AS_UID cannot help a file this uid already owns", got)
	}
	if !strings.Contains(got, "mode") {
		t.Errorf("advice = %q, want it to point at the file's mode", got)
	}
}

// Where the platform gives no owner, say what is known and invent no numbers.
func TestUnreadableAdviceWithNoOwnerInventsNoNumbers(t *testing.T) {
	got := ownershipAdvice("tls.cert", 0o000, 0, 0, false, 1000, 1000)
	if strings.ContainsAny(got, "0123456789") {
		t.Errorf("advice = %q, which carries numbers the platform never gave", got)
	}
	for _, want := range []string{"RUN_AS_UID", "RUN_AS_GID"} {
		if !strings.Contains(got, want) {
			t.Errorf("advice = %q, want it to contain %q", got, want)
		}
	}
}

// And through the real path: CopyCertificate on a file it cannot read returns
// the permission error, still matchable, carrying the owner. The test owns its
// own file, so this is the same-uid branch; the differing-uid branch is the
// test above.
func TestCopyCertificateNamesTheOwnerOfAnUnreadableCertificate(t *testing.T) {
	path, _ := unreadableFile(t)
	g := &Guard{certSourcePath: path, credentialsDir: t.TempDir()}

	err := g.CopyCertificate()
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("CopyCertificate = %v, want a permission error", err)
	}
	if want := fmt.Sprintf("uid %d:%d", os.Getuid(), os.Getgid()); !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to name the owner %q", err, want)
	}
}

// A REFUSAL THE BITS DO NOT EXPLAIN IS NOT BLAMED ON THE BITS (go-review,
// 20i.14). A file whose applicable read bit is set and was refused anyway was
// refused by a label, an ACL or the mount; chown and chmod advice would send the
// operator away from it. One row per class the kernel can check.
func TestUnreadableAdviceBlamesNeitherOwnershipNorModeWhenTheBitsAllowIt(t *testing.T) {
	for _, tc := range []struct {
		name               string
		perm               fs.FileMode
		ownerUID, ownerGID uint32
	}{
		{"owner class, owner-readable", 0o600, 1000, 1000},
		{"group class, group-readable", 0o640, 998, 1000},
		{"other class, world-readable", 0o644, 998, 998},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ownershipAdvice("admin.macaroon", tc.perm, tc.ownerUID, tc.ownerGID, true, 1000, 1000)
			if strings.Contains(got, "RUN_AS_UID=") || strings.Contains(got, "give its owner read") {
				t.Errorf("advice = %q, which blames ownership or mode for a file the bits let this process read", got)
			}
			if !strings.Contains(got, "SELinux") {
				t.Errorf("advice = %q, want it to point past ownership and mode", got)
			}
		})
	}
}
