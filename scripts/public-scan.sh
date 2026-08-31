#!/usr/bin/env sh
# public-scan: refuse to let private material into the tracked tree.
#
# This repository is public and its working tree is not: internal documents, the
# issue tracker and local notes live beside the code, kept out of git by
# .gitignore. An ignore rule is a default, not a guarantee — `git add -f`, a
# renamed directory, or a pattern that stops matching all put a file back on the
# path to a push. This script is the check that does not depend on remembering.
# It runs in the CI gate and via `make public-scan`, and it fails closed.
#
# It inspects what git TRACKS (`git ls-files`), which is what a commit carries,
# rather than the working tree, which is allowed to hold anything.
#
# TWO HALVES, deliberately. This file carries only GENERIC checks, because it is
# itself public — a scanner that listed the specific names, addresses and keys
# it guards against would publish the very things it exists to suppress. The
# specific patterns live in scripts/public-scan.local, which is ignored,
# forbidden below as a tracked path, and present only where the private material
# is. Public CI runs the generic half alone, which is enough there: the private
# material this guards never exists in a public checkout.
set -eu

fail=0
say() { printf '%s\n' "$*" >&2; }

# ---- 1. Paths that must never be tracked ------------------------------------
forbidden_paths='^(docs/|\.beads/|\.claude/|CLAUDE\.md$|scripts/public-scan\.local$)|(^|/)\.env$'
if git ls-files | grep -E "$forbidden_paths" >/tmp/public-scan.paths 2>/dev/null; then
  say "public-scan: tracked paths that must not be:"
  sed 's/^/  /' /tmp/public-scan.paths >&2
  fail=1
fi

# ---- 2. Compiled binaries ---------------------------------------------------
# A tracked binary carries its build path and machine in its metadata, and the
# build tooling produces its outputs into work directories, never the tree.
for f in $(git ls-files); do
  [ -f "$f" ] || continue
  magic=$(head -c 4 "$f" | od -An -tx1 | tr -d ' \n')
  case "$magic" in
    7f454c46|feedface|feedfacf|cefaedfe|cffaedfe|cafebabe)
      say "public-scan: tracked compiled binary: $f"; fail=1 ;;
  esac
done

# ---- 3. Generic content checks ----------------------------------------------
# Shapes that are private wherever they appear, revealing nothing by being
# listed: a macOS home-directory path, a bech32 private key, key material, and
# leftover merge-conflict markers. /home/<name> is deliberately NOT here:
# container and CI homes (/home/bitcoin in the regtest mounts, /home/runner on
# GitHub) are routine, so the pattern is all false positives — a real Linux
# home path belongs in the local list, where the name can be specific.
generic='/Users/[A-Za-z]+|nsec1[a-z0-9]{58}|BEGIN [A-Z ]*PRIVATE KEY|^<<<<<<< |^>>>>>>> '
scan_files() { git ls-files -z | grep -zvE '^(\.gitignore|scripts/public-scan\.sh)$'; }
if scan_files | xargs -0 grep -nEI "$generic" >/tmp/public-scan.hits 2>/dev/null; then
  say "public-scan: private detail in tracked content:"
  sed 's/^/  /' /tmp/public-scan.hits >&2
  fail=1
fi

# ---- 4. The local pattern list, when present --------------------------------
# One extended-regex pattern per line; lines starting with # are comments. The
# file exists on machines whose working trees hold private material and is the
# other half of this scan there. Its absence is normal in CI and in a fresh
# public checkout, and is announced rather than silent, so "generic-only" is
# never mistaken for "fully scanned" on a machine that should have it.
local_list="scripts/public-scan.local"
if [ -f "$local_list" ]; then
  # POSIX sh (dash on CI) has no process substitution; clean into a temp file.
  grep -v '^#' "$local_list" | grep -v '^$' >/tmp/public-scan.patterns
  if scan_files | xargs -0 grep -nEIf /tmp/public-scan.patterns \
       >/tmp/public-scan.local-hits 2>/dev/null; then
    say "public-scan: local-pattern hit in tracked content:"
    sed 's/^/  /' /tmp/public-scan.local-hits >&2
    fail=1
  fi
  extra=" (+ local patterns)"
else
  extra=" (generic only; no $local_list here)"
fi

if [ "$fail" -ne 0 ]; then
  say "public-scan: FAILED — nothing above may reach a public commit"
  exit 1
fi
echo "public-scan: clean$extra"
