#!/usr/bin/env python3
"""Report the Go version a digest-pinned official golang image ships.

Reads the image CONFIG from the registry over plain HTTPS and returns the
GOLANG_VERSION the image was built with. No Docker daemon, which is what lets
the toolchain-floor check live in the local gate rather than only in CI — see
scripts/toolchain-floor.sh for why that mattered.

GOLANG_VERSION rather than running `go version`: it is set by the official
image's own Dockerfile to the version it installed, so it is the same answer
`go version` would give, obtainable without executing anything. The cost is that
it is a convention of these images rather than a guarantee of the OCI spec — if
the golang images ever stop setting it, this fails loudly (empty result, which
the caller turns into COULD NOT CHECK) rather than quietly returning something
wrong.

The digest may name an index (multi-platform) or a single manifest. Both are
handled: for an index, linux/amd64 is read, because every platform in one index
is built from the same source release and ships the same Go.
"""

import json
import os
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
TIMEOUT = 30


def get(url, token, accept=None):
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Bearer " + token)
    if accept:
        req.add_header("Accept", accept)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.load(r)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: image_go_version.py <sha256:...>")
    digest = sys.argv[1]
    repo = os.environ.get("TOKEN_SCOPE", "library/golang")

    with urllib.request.urlopen(AUTH % repo, timeout=TIMEOUT) as r:
        token = json.load(r)["token"]

    manifest = get("%s/%s/manifests/%s" % (REGISTRY, repo, digest), token, ACCEPT)

    # An index has to be resolved to one platform's manifest before there is a
    # config blob to read at all.
    if "manifests" in manifest:
        chosen = None
        for entry in manifest["manifests"]:
            platform = entry.get("platform", {})
            if (platform.get("os") == "linux"
                    and platform.get("architecture") == "amd64"
                    and "variant" not in platform):
                chosen = entry["digest"]
                break
        if chosen is None:
            sys.exit("no linux/amd64 manifest in the index for " + digest)
        manifest = get("%s/%s/manifests/%s" % (REGISTRY, repo, chosen), token, ACCEPT)

    config = get("%s/%s/blobs/%s" % (REGISTRY, repo, manifest["config"]["digest"]), token)
    for entry in config.get("config", {}).get("Env", []):
        if entry.startswith("GOLANG_VERSION="):
            print(entry.split("=", 1)[1])
            return
    sys.exit("no GOLANG_VERSION in the image config for " + digest)


if __name__ == "__main__":
    try:
        main()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as err:
        # Reaching the registry is a RUN failure, not a floor mismatch. The
        # caller distinguishes the two by exit status and must never report a
        # network problem as "the images and the gate disagree".
        sys.exit("registry unreachable: %s" % err)
