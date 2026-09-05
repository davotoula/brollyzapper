#!/usr/bin/env python3
"""Assert go.mod's toolchain floor equals the Go the pinned base images ship.

THE FLOOR AND THE IMAGE MUST BE THE SAME GO, and until this existed they were
kept so only by hand: `0vk.35` read `go version` out of the image once, wrote the
answer into go.mod, and nothing held them together afterwards.

The direction that matters is a floor ABOVE the image. `make vuln` then runs
under a newer Go and reports clean, while the images ship binaries built by the
older one carrying whatever advisories it had — the direction govulncheck cannot
see past, because it cannot look beyond the toolchain it runs under. Its first
run found 32 reachable stdlib advisories exactly there. A floor BELOW the image
is milder but still means the gate is not testing what is published, which is the
point of pinning.

GOTOOLCHAIN=local DOES NOT CATCH EITHER, despite an earlier version of the
Dockerfiles' comment saying so. Under "local" a `toolchain` line is INERT; only
the `go` directive can refuse. Measured twice during `0vk.35`. That measurement
is why this file exists (`0vk.39`).

NO DOCKER DAEMON, which is what decided where this lives. `docker run <digest> go
version` is the obvious implementation and would have confined the check to CI,
because the local gate is daemon-free by design and `make docker` is separate for
exactly that reason. The official golang images carry their version in the image
CONFIG as GOLANG_VERSION, and a config blob is readable from the registry over
plain HTTPS — so this runs in the local gate and in CI as one check, with no
asymmetry to remember.

GOLANG_VERSION rather than executing `go version`: it is set by the official
image's own Dockerfile to the version it installed, so it is the same answer,
obtainable without running anything. It is a convention of these images rather
than an OCI guarantee — if they ever stop setting it this fails LOUDLY as a
could-not-check, never quietly with a wrong answer.

WHAT IS DELIBERATELY NOT HERE: the `go` directive's minor must also match the
toolchain line, and that is a pure go.mod-internal invariant needing no network.
It lives in internal/arch (TestTheLanguageVersionTracksTheToolchain) so that it
still runs offline and still runs when the registry is down — it is the sole
guard on the publish path, which builds images without any gate, and a check that
evaporates during a Docker Hub outage is not a guard.
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request

ACCEPT = ",".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
REGISTRY = "https://registry-1.docker.io/v2"
AUTH = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull"
REPO = "library/golang"
TIMEOUT = 30

DOCKERFILES = ("Dockerfile.server", "Dockerfile.guard")
# Only the golang builder stage ships a Go; the distroless runtime does not. By
# DIGEST, never by tag: a tag is a mutable pointer, so a check reading the tag
# would assert against a moving target and stop meaning anything the first time
# upstream republished it.
PIN = re.compile(r"^FROM .*golang:[^@\s]*@(sha256:[0-9a-f]{64})", re.M)
TOOLCHAIN = re.compile(r"^toolchain go([0-9][0-9.]*)$", re.M)


class CannotCheck(Exception):
    """Something stopped the check from running. NOT a floor mismatch.

    The two must never look alike: "come back later" and "the gate is not
    testing what ships" are different news, and they exit 2 and 1 respectively.
    Every failure to reach the registry lands here.
    """


class Mismatch(Exception):
    """The floor and an image disagree."""


def _token():
    with urllib.request.urlopen(AUTH % REPO, timeout=TIMEOUT) as r:
        return json.load(r)["token"]


def _get(url, token, accept=None):
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Bearer " + token)
    if accept:
        req.add_header("Accept", accept)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.load(r)


def shipped_go(digest, cache, state):
    """The Go version the image at this digest ships.

    MEMOISED ON THE DIGEST, and it is not a micro-optimisation: both Dockerfiles
    pin the same base today, so without this the gate asks Docker Hub the same
    question twice — four HTTPS round trips each — and draws twice the anonymous
    rate-limit budget, which is this check's own stated expiry condition.
    """
    if digest in cache:
        return cache[digest]
    if state.get("token") is None:
        state["token"] = _token()
    token = state["token"]

    manifest = _get("%s/%s/manifests/%s" % (REGISTRY, REPO, digest), token, ACCEPT)
    # An index has to be resolved to one platform before there is a config blob
    # to read. Any platform would do — every entry in one index is built from the
    # same source release and ships the same Go — so linux/amd64 is a pick, not a
    # narrowing.
    if "manifests" in manifest:
        chosen = next((e["digest"] for e in manifest["manifests"]
                       if e.get("platform", {}).get("os") == "linux"
                       and e.get("platform", {}).get("architecture") == "amd64"
                       and "variant" not in e.get("platform", {})), None)
        if chosen is None:
            raise CannotCheck("no linux/amd64 manifest in the index for " + digest)
        manifest = _get("%s/%s/manifests/%s" % (REGISTRY, REPO, chosen), token, ACCEPT)

    config = _get("%s/%s/blobs/%s" % (REGISTRY, REPO, manifest["config"]["digest"]), token)
    for entry in config.get("config", {}).get("Env", []):
        if entry.startswith("GOLANG_VERSION="):
            cache[digest] = entry.split("=", 1)[1]
            return cache[digest]
    raise CannotCheck("no GOLANG_VERSION in the image config for " + digest)


def minor(version):
    return ".".join(version.split(".")[:2])


def check():
    floor = TOOLCHAIN.findall(open("go.mod").read())
    if not floor:
        raise Mismatch("go.mod has no 'toolchain' line, so the floor is unstated.\n"
                       "  Add 'toolchain go<version>' naming the Go the base images ship.")
    if len(floor) > 1:
        raise CannotCheck("go.mod has more than one toolchain line")
    floor = floor[0]

    cache, state, scanned = {}, {}, 0
    for name in DOCKERFILES:
        if not os.path.exists(name):
            raise CannotCheck(name + " is missing")
        pins = PIN.findall(open(name).read())
        if not pins:
            raise CannotCheck(
                "no digest-pinned golang base found in %s.\n"
                "  This check is only meaningful while that FROM line is digest-pinned;\n"
                "  if the pin was deliberately removed, this script has to change with it."
                % name)
        if len(set(pins)) > 1:
            raise CannotCheck(name + " pins more than one golang base")

        ships = shipped_go(pins[0], cache, state)
        if ships != floor:
            above = "ABOVE the image — the gate would test a newer Go than ships, and\n" \
                    "  govulncheck cannot see past that"
            below = "BELOW the image — the gate would test an older Go than ships"
            direction = below if _older(floor, ships) else above
            raise Mismatch(
                "go.mod's toolchain floor and %s's base image disagree.\n"
                "  go.mod  toolchain go%s\n"
                "  %s  ships go%s (%s)\n"
                "  The floor is %s.\n"
                "  Move them together: refresh the digest and the toolchain line in one commit."
                % (name, floor, name, ships, pins[0], direction))
        scanned += 1

    # ANTI-VACUITY. A loop that ran zero times reports success, and this check is
    # exactly the shape where that would go unnoticed for a long time.
    if scanned != len(DOCKERFILES):
        raise CannotCheck("checked %d Dockerfiles, expected %d" % (scanned, len(DOCKERFILES)))
    return floor, len(cache)


def _older(a, b):
    key = lambda v: [int(p) for p in v.split(".")]  # noqa: E731
    return key(a) < key(b)


if __name__ == "__main__":
    try:
        got, lookups = check()
        print("toolchain-floor: go.mod's floor (go%s) matches both pinned base images "
              "(%d registry lookup%s)" % (got, lookups, "" if lookups == 1 else "s"))
    except Mismatch as err:
        sys.exit("toolchain-floor: %s" % err)
    except CannotCheck as err:
        print("toolchain-floor: COULD NOT CHECK — %s" % err, file=sys.stderr)
        sys.exit(2)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as err:
        print("toolchain-floor: COULD NOT CHECK — registry unreachable: %s" % err,
              file=sys.stderr)
        sys.exit(2)
