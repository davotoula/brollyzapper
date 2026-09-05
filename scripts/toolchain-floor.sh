#!/usr/bin/env sh
# toolchain-floor: assert go.mod's toolchain equals the Go the pinned base images ship.
#
# THE FLOOR AND THE IMAGE MUST BE THE SAME GO, and until this existed they were
# only kept so by hand. `0vk.35` read `go version` out of the image once, wrote
# the answer into go.mod, and nothing held them together afterwards.
#
# BOTH DIRECTIONS ARE BUGS, and they are different bugs:
#
#   floor ABOVE image — the gate runs govulncheck under a NEWER Go than ships,
#     so it reports clean while the images carry binaries built by the older one
#     and whatever advisories that one had. This is the direction nothing else
#     can see: govulncheck cannot look past the toolchain it is running under.
#     `0vk.35`'s first govulncheck run found 32 reachable stdlib advisories
#     exactly here, because go.mod had no floor at all.
#   floor BELOW image — the gate tests an OLDER Go than ships. Milder, because
#     the shipped binaries are the newer ones, but it means the gate is not
#     testing what is published, which is the whole point of pinning.
#
# GOTOOLCHAIN=local DOES NOT CATCH EITHER, despite an earlier version of the
# Dockerfiles' comment saying so. Under "local" a `toolchain` line is INERT; only
# the `go` directive can refuse. Measured twice during `0vk.35` — `toolchain
# go1.28.0` planted, `--no-cache` build on a base shipping go1.27.1, build
# succeeded silently. That measurement is why this file exists (`0vk.39`).
#
# NO DOCKER DAEMON. The obvious implementation is `docker run <digest> go
# version`, and it would have confined this check to CI, because the local gate
# is daemon-free by design and `make docker` is separate for that reason. The
# official golang images carry their version in the image CONFIG as
# GOLANG_VERSION, and a config blob is readable from the registry over plain
# HTTPS — so this runs in the local gate and in CI as the same check, with no
# asymmetry between them to remember.
#
# IT DOES NEED THE NETWORK, which the gate already does for `make vuln`. Every
# failure to REACH the registry is reported as a failure to run, never as a
# mismatch — see fail_run below. Silence here has to mean "the floor is right",
# never "the check could not tell".
#
# EXPIRY CONDITION: it reads Docker Hub anonymously, which is rate-limited per
# IP. At gate frequency that is far inside the limit. If this ever starts
# failing with 429, the answer is a token, not dropping the check.
set -eu

registry='https://registry-1.docker.io/v2'
accept='application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json'

say() { printf '%s\n' "$*" >&2; }

# fail_run and fail_check are DIFFERENT EXITS on purpose. A network blip and a
# wrong floor must never look alike: one means "come back later", the other
# means "the images and the gate disagree about which Go is being tested".
fail_run() { say "toolchain-floor: COULD NOT CHECK — $*"; exit 2; }
fail_check() { say "toolchain-floor: $*"; exit 1; }

for tool in curl python3; do
  command -v "$tool" >/dev/null 2>&1 || fail_run "$tool is not on PATH"
done

# ---- go.mod's floor ---------------------------------------------------------
floor=$(sed -n 's/^toolchain go\([0-9][0-9.]*\)$/\1/p' go.mod)
[ -n "$floor" ] || fail_check "go.mod has no 'toolchain' line, so the floor is unstated.
  Add 'toolchain go<version>' naming the Go the base images ship."
[ "$(printf '%s\n' "$floor" | wc -l)" -eq 1 ] || fail_run "go.mod has more than one toolchain line"

# THE `go` DIRECTIVE IS CHECKED TOO, and this is what keeps 0vk.39's second
# decision from decaying. Raising it to the toolchain's minor is what makes a
# GOTOOLCHAIN=local image build REFUSE a base older than the language version —
# measured: `go 1.27.0` on a go1.26.8 base fails, `go 1.25.0` on the same base
# builds silently. That guard is the only one covering publish.yml, which builds
# and pushes images WITHOUT running this gate.
#
# Unasserted, it would rot in one step: the next image bump moves the toolchain
# line (this script forces that) and leaves the `go` directive behind, putting
# the build quietly back to where it is today with nothing to say so.
#
# MINOR, not patch. The `go` directive names a language version and has no
# business tracking a patch release; the toolchain line above is what pins the
# patch.
lang=$(sed -n 's/^go \([0-9][0-9.]*\)$/\1/p' go.mod)
[ -n "$lang" ] || fail_run "go.mod has no 'go' directive"
minor() { printf '%s\n' "$1" | cut -d. -f1,2; }

# ---- the images -------------------------------------------------------------
# By DIGEST, never by tag: a tag is a mutable pointer, so a check that read the
# tag would assert against a moving target and stop meaning anything the first
# time upstream republished it. Both Dockerfiles, because they can drift apart.
scanned=0
for file in Dockerfile.server Dockerfile.guard; do
  [ -f "$file" ] || fail_run "$file is missing"
  # Only the golang builder stage ships a Go; the distroless runtime does not.
  pin=$(sed -n 's|^FROM .*golang:[^@]*@\(sha256:[0-9a-f]\{64\}\).*|\1|p' "$file")
  [ -n "$pin" ] || fail_run "no digest-pinned golang base found in $file.
  This check is only meaningful while that FROM line is digest-pinned; if the
  pin was deliberately removed, this script has to change with it."
  [ "$(printf '%s\n' "$pin" | wc -l)" -eq 1 ] || fail_run "$file pins more than one golang base"

  shipped=$(TOKEN_SCOPE=library/golang python3 scripts/image_go_version.py "$pin") \
    || fail_run "could not read the Go version out of $pin (from $file)"
  [ -n "$shipped" ] || fail_run "empty Go version for $pin (from $file)"

  if [ "$(minor "$lang")" != "$(minor "$shipped")" ]; then
    fail_check "go.mod's 'go' directive and $file's base image disagree on the MINOR.
  go.mod  go $lang
  $file  ships go$shipped ($pin)
  The go directive is what makes a GOTOOLCHAIN=local build refuse a base older
  than the language version — the toolchain line cannot, it is inert under
  'local'. It is also the only guard on the publish path, which does not run
  this gate. Raise it with the image, in the same commit."
  fi

  if [ "$shipped" != "$floor" ]; then
    direction="ABOVE the image — the gate would test a newer Go than ships, and
  govulncheck cannot see past that"
    [ "$(printf '%s\n%s\n' "$floor" "$shipped" | sort -V | head -1)" = "$floor" ] &&
      direction="BELOW the image — the gate would test an older Go than ships"
    fail_check "go.mod's toolchain floor and $file's base image disagree.
  go.mod  toolchain go$floor
  $file  ships go$shipped ($pin)
  The floor is $direction.
  Move them together: refresh the digest and the toolchain line in one commit."
  fi
  scanned=$((scanned + 1))
done

# ANTI-VACUITY. A loop that ran zero times reports success, and this check is
# exactly the shape where that would go unnoticed for a long time.
[ "$scanned" -eq 2 ] || fail_run "checked $scanned Dockerfiles, expected 2"

say "toolchain-floor: go.mod (go $lang, toolchain go$floor) matches both pinned base images"
