# Umbrel App Store package

`brollyzapper/` is the package as it would be submitted to
[`getumbrel/umbrel-apps`](https://github.com/getumbrel/umbrel-apps): copy the
directory in at the repo root, keeping the name, because the manifest `id` and
the directory must match.

`lint_test.go` is the package's own lint, and it is the **primary** control for
the credential split (§11, §16). The server's runtime preflight is the backstop:
it cannot prove a negative, because a mount at an unexpected path is invisible
to it. Three assertions matter most, and each is verified by planting the
violation:

- the **server service has no `admin.macaroon` mount**, by any path or spelling
- **`PROXY_TRUST_UPSTREAM` appears nowhere** — setting it true makes `app_proxy`
  forward a client-supplied `X-Forwarded-For` verbatim (measured on a real box),
  and it is undocumented in app-proxy's own README
- **`PROXY_AUTH_WHITELIST` equals the public route set** that `internal/api`
  registers — the same equality, expressed in two files

## Before submitting

1. **Publish the images from CI, then pin what the registry actually has.**
   The release procedure opens with "publish from CI,
   never a laptop" — the per-job token is scoped and expires, no credential
   touches a developer machine, and the images that ship are built by the runner
   that gated them.

   ```sh
   gh workflow run publish.yml -f version=<version>
   docker buildx imagetools inspect ghcr.io/<owner>/brollyzapper:<version> \
     --format '{{.Manifest.Digest}}'          # and again for -guard
   ```

   Pin both digests in `docker-compose.yml`, commit, re-tag. A tag build whose
   compose still carries the `sha256:0000…` placeholders fails the `release
   gate` job in `.github/workflows/ci.yml`: an image that cannot be pulled is a
   package that cannot install.

   The `release` Makefile target still exists and still works, but it publishes
   from a developer machine and **is not the path** (BrollyZap-kwm).
2. **Re-check the static IP.** `10.21.21.14` was free across every `exports.sh`
   in the App Store on 2026-08-21, but it is a shared namespace and other
   packages land continuously.
3. **Re-check the manifest port.** `3033` was free across all 391 manifests on
   the same date.
4. `npm run lint:apps -- brollyzapper --check-images` in the app-store repo, then
   install from a local app store and open the UI.
