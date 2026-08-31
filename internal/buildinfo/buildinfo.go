// Package buildinfo resolves the version string both binaries report. It is
// formatting only — nothing here is security-relevant, which is why the two
// binaries share it despite the §3 container split.
package buildinfo

import "runtime/debug"

// revisionLength is how much of the VCS revision is kept: enough to find the
// commit, short enough to read in a log line.
const revisionLength = 12

// Resolve prefers the version stamped at link time with -X main.version=<tag>
// and falls back to the VCS revision the Go toolchain embeds, so a plain
// go build still identifies what it was built from.
func Resolve(version string) string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			rev := s.Value
			if len(rev) > revisionLength {
				rev = rev[:revisionLength]
			}
			return version + "+" + rev
		}
	}
	return version
}
