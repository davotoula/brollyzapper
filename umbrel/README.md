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
2. **Re-check the static IP and the manifest port.** Both live in namespaces the
   whole App Store shares, and packages land continuously. Last verified
   2026-09-01 against `getumbrel/umbrel-apps@e08a7b4` (391 apps): `10.21.21.14`
   free, neighbours `.13`/`.15` free, `3033` free.

   ```sh
   git clone --depth 1 https://github.com/getumbrel/umbrel-apps.git && cd umbrel-apps
   grep -rn '10\.21\.21\.14' .            # the IP: no hits = free
   grep -rn '^port: 3033' */umbrel-app.yml # the port: no hits = free
   grep -rn '"3033:' */docker-compose.yml  # ...and no raw host mapping either
   ```

   The allocated range on that date was `.7-.10, .20, .22-.28, .50, .58, .75,
   .81, .87-.89, .94, .96, .179-.181, .199, .200`.
3. **Check the manifest is in SUBMISSION shape, which is not the same as dev-store
   shape.** `releaseNotes` must be `""` — `umbrel-package-app` requires it for new
   packages, and the Opengist submission (umbrel-apps#5849) shows it done that way.
   `icon:` must be ABSENT; Umbrel hosts the artwork itself, keyed by app id.
   `gallery:` stays `[]` — screenshots go in the PR body, never in the diff.
   `go test ./umbrel/` asserts the icon rule; the other two are on you.
4. **Lint, from inside the app-store repo with the package copied in.**

   ```sh
   npm install
   npm run lint:apps -- brollyzapper --check-images
   git diff --check
   ```

   Expect **exactly two errors, both `manifest.submission`**, and no warnings.
   That pair is not fixable beforehand: `submission:` wants the URL of the PR
   that does not exist yet. Open the PR, then push a commit filling it in —
   Opengist's PR carries five successive `Update umbrel-app.yml` commits doing
   exactly this. Anything else the linter says is a real finding.

   `--check-images` is live, not decorative: it verifies both images are publicly
   pullable and multi-arch. Confirmed by planting a bogus digest, which trips
   `image.pullable` + `image.digest`.
5. **Test through Umbrel, which is stricter than "install it and open the UI".**
   `umbrel-test-app` explicitly refuses `docker compose up`, a successful image
   pull, or `apps.state == ready` as proof. The run needs: install `lightning`
   first, install the app through Umbrel, open it via `app_proxy` (not a raw
   container port), complete a real workflow, verify the `PROXY_AUTH_WHITELIST`
   paths answer anonymously **and** that everything else still demands a login,
   restart through Umbrel, confirm state survived, then read settled logs.

   Record the architecture — the PR template has a checkbox for it, and `arm64`
   coverage is what Raspberry Pi 4/5 users depend on.
6. **Open the PR against the current template.** `.github/PULL_REQUEST_TEMPLATE.md`
   replaced the freeform "App Submission: <name>" body that Opengist and every
   other app merged before ~Aug 2026 used. Title is `Add BrollyZapper`; the body
   is Type / App / Summary / Verification / Notes, with checkboxes for environment
   and architecture. Screenshots and a logo reference go in the body **as
   attachments**; Umbrel creates the final gallery assets before merge, so
   nothing artwork-shaped is committed to the package and `gallery: []` stays
   empty. The logo reference is `assets/icon.svg`, rasterised to 256×256 for
   the attachment because GitHub does not accept SVG uploads. The screenshots
   come from the gallery fixture, not a real box — deterministic, re-generable
   on every UI change, and none of the operator's own npubs or amounts in a
   public listing:

   ```sh
   BROLLY_GALLERY_DIR=/tmp/gallery BROLLY_GALLERY_VERSION=<version> \
     go test ./internal/web/ -run TestTheGalleryFixtureShowsAHealthyInstall
   ```

   That writes six standalone pages; screenshot them at 1440×900 (2× for a
   sharp upload), which is what the gallery hosts today — an observation of the
   current assets, not a stated requirement.

   **The draft body is kept outside the repository**, in the maintainer's local,
   gitignored `docs/` folder as `PR-BODY-umbrel-store-submission.md`. The
   version-independent half is already written there — the credential-posture
   note, and the comparison against the twenty apps that mount `admin.macaroon`
   whole. Fill in the bracketed values.
