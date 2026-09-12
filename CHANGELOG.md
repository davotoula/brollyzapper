# Changelog

This file starts at 0.1.13; this repository's history begins at 0.1.16.

## 0.1.21 — 2026-09-12

The release that makes BrollyZapper deployable on plain Docker beside any LND, not only as an
Umbrel app: a `deploy/` template with its own lint, a DEPLOYING procedure that was walked on a
real node, and the one binary change that path needed — the admin password. Tripped on the
reference box as `0.1.21-rc1` twice on 12 Sep: an in-place Umbrel update where every operator
surface read verbatim as it did on 0.1.20 and a real zap published its receipt to five of five
relays in **999 ms**; and an A/B on a plain-Docker install beside that same Umbrel, where the
only thing swapped between the two readings was the image digests.

### Changed

- **The admin password is now required, and off Umbrel it is yours to change.** Set
  `ADMIN_PASSWORD` (at least 12 characters) before the first start — the server refuses to start
  without it, rather than inventing one and showing it on a page behind the login it would have
  opened. Once you are in, **Settings** offers a password change on any deployment the platform
  does not manage; umbrelOS installs are unaffected in every respect, including the password
  they already have. Existing plain-Docker installs that already set `ADMIN_PASSWORD` need no
  action. *(Breaking for a plain-Docker install that relied on the invented password.)*

### Fixed

- **Two failures a plain-Docker install hits now say what to do.** If LND's certificate does not
  name the address the app dials, the guard says so before it connects and names the exact
  `lnd.conf` edit, instead of a TLS handshake message at the first request. And if your node is
  refusing the credential for the address it sees, the Node page says that — with the address it
  is locked to — instead of reporting a rotation and offering a Re-link button that cannot help.
  umbrelOS installs are unaffected: both conditions need a deployment the platform does not
  produce, and the pages and logs of a healthy install are unchanged.
- **Asking for a second confirmation code now records what happened to the first.** If you ask
  for a code and then ask again before using it, the security trail says the earlier one was
  superseded, instead of simply ending at the request. Nothing about the ceremony itself
  changes: the newest code is still the only one that works.
- **A wallet connection missing half its key pair is refused by name** instead of stored as a
  pairing that could never sign a response. Unreachable from the pages; closes the hand-crafted
  case. Underneath, the payment preimage is typed as a secret from the node to the receipt, so
  it cannot reach a log or an error by accident — no visible change.

### Added

- **`deploy/`: a plain-Docker Compose template** for running beside an existing LND on the same
  host, with an `.env.example` that shows every setting and a lint that keeps the template equal
  to the Umbrel package where it must be and different only where it should be.
- **`DEPLOYING.md` §Running outside Umbrel is a procedure**, walked against a real node: the
  two snags a first start meets (the certificate name, the file ownership) with their fixes, what
  is not supported and why, and how to test beside an Umbrel install without touching its node.

### Documentation

- One root file per reader: `README`, `DEPLOYING`, `OPERATING`, `CONTRIBUTING`. `MANUAL.html`
  is retired; the settings are stated once, in `OPERATING.md`.

### Lint controls

None of these change behaviour. Each is a check that turned out to be satisfiable by prose — a
comment, a folded line, a word in the wrong place — and now reads the thing it checks:

- `umbrel/`: the package lint reads `exports.sh` as assignments rather than text — the
  session-secret and static-IP checks could previously be satisfied by a comment — and ties it
  to the compose that consumes it: the static address is checked at both ends, `exports.sh` must
  export exactly what the compose needs, and the generic-settings contract is derived from
  `internal/config` rather than hand-kept.
- `deploy/`: the env-name lint checks assignments rather than prose, reads both interpolation
  spellings off the parsed compose, and the template says what the spend caps cost and that
  `NETWORK_CIDR` is inert while `SERVER_IP` is set.
- `regtest/`: the lints read the compose they parse rather than its text; the image control
  counts parsed services rather than the word `image:`, and the digest rule requires a real
  digest and a version tag.

### Upgrading

**On umbrelOS, nothing to do.** No migration (schema stays 15), no setting changes, no key baked
or revoked by the update, and the Settings page still says the password is managed by Umbrel.
An in-place update recreates both containers; about 40 s with the app down.

**On plain Docker, `ADMIN_PASSWORD` must be set** (12 characters or more) before the update
starts the new server, or it refuses to start and says so. An install that already set it needs
nothing else.

## 0.1.20 — 2026-09-08

Mostly what an operator sees when a limit change is refused, plus three corrections in the
zap-receipt publish path that were found by review after 0.1.19 shipped. Tripped twice on the
reference box as `0.1.20-rc1` and `0.1.20-rc2`: everything under **Fixed** that touches the
Sending page was confirmed there, and the first real zap through rc2 published its receipt to
five of five relays in **924 ms**, inside the band 0.1.19's relay work predicted.

### Fixed

- **A refused limit change now says which limit to move, on the page.** The per-payment limit
  cannot sit above the 24-hour one, so lowering the 24-hour limit below it, or raising the
  per-payment limit above it, is refused — and the refusal used to reach only the log, while the
  page said a confirmation code was not accepted, for a change that involved no code. The page
  now names the limit to move first: lower the per-payment limit, or raise the 24-hour limit. Any
  other refusal that involved no code says the change was refused and points at the log.
- **A per-payment limit that could never apply is refused before a code is issued**, not after
  you have fetched and typed one.
- **The guard's own refusal names the control you are not editing**, in the log and the audit
  trail, where it used to name the one you had just typed into.
- **A confirmation code you never use is cleared when it expires**, file and record together, at
  the guard's next look. Before, the file stayed on disk indefinitely.
- **A zap receipt is only counted as accepted when a relay says so.** A relay that took the event
  and then dropped the socket used to read as accepted; it is now `no_answer`, and a pending
  receipt's last error names the relay.
- **No relay waits for another when a receipt is published.** Each relay is dialled and sent to on
  its own, so one dead relay no longer delays the live ones by the whole connect budget — the case
  that made a wallet's NWC response miss its window when one paired relay was down.
- **A concurrent subscribe and publish to one relay can no longer leak a socket.** Both now go
  through the app's one dial, so a torn relay-map write, and the unclosable connection it left
  behind, has no path.
- **A Settings save that is missing a field is refused whole**, instead of silently blanking the
  fields it did not carry. Browsers always send the whole form; this closes the hand-crafted case.
- **An unusable log level is refused on save**, with a message, rather than stored and ignored.
- **A refused Settings value is no longer echoed into the log.** The log says which key and why.

### Changed

- **The Sending page names the order the two limits move in**, in the hint above the cap fields.
- The start-up refusal for a per-payment limit above the 24-hour one in the compose environment
  says "24-hour limit", the phrase every other surface uses.
- Dependencies current (pure-Go sqlite 1.58.0, `golang.org/x/crypto` 0.56.0). A large test-only
  hardening of the log-redaction rules ships no behaviour change, and the gate now checks that
  `go.mod`'s toolchain floor matches the Go the pinned base images ship.

### Upgrading

**Nothing to do.** No migration (schema stays 15), no setting changes, no key baked or revoked by
the update. An in-place update recreates both containers; about 40 s with the app down.

## 0.1.19 — 2026-09-03

Three changes, all in the zap-receipt publish path, and all measured on the reference box with
the same six relays: the receipt publish went from **15.0 s to 5.3 s**, and with the dead default
relay gone it is expected under half a second. Nothing about receiving or sending changed.

### Fixed

- **A zap receipt publish no longer waits out a relay that is down.** go-nostr connects to each
  relay under a hardcoded 15-second timeout that no caller can shorten, and waits for every relay
  before returning — so one unreachable relay in the list cost every receipt a flat 15 seconds.
  The app now connects to each relay itself, under a five-second budget, and hands the library
  only relays that are already open. A relay that does not connect in time is one failed result,
  never a longer wait. A relay that has connected and is slow to answer is still waited for, as
  before.
- **`relay.nostr.band` is no longer a default relay.** Measured dead from three networks — TCP
  never completes — and, because it hangs rather than refuses, it consumed the whole connect
  budget on every publish. It was also the third relay every new pairing was prefilled with.
  Nothing replaces it; the defaults are `nos.lol`, `relay.damus.io` and `relay.primal.net`, and
  the Relays setting overrides them.

### Changed

- **The receipt log line says how long the publish took** (`publish_ms`), and when a publish was
  slow or partial, one DEBUG record per relay names its outcome and duration — `accepted`,
  `refused`, `over_budget` (it hung and ate the budget), `not_connected` (it failed fast) — so
  the relay costing the time can be named from a box rather than inferred.
- The `relays chosen for this publish` line now counts every relay the sender named, with a new
  `already_ours` field for the ones this node publishes to anyway; `named` equals `kept` plus
  `dropped` plus `already_ours`.

### Upgrading

**Nothing to do.** No migration, no setting changes. An operator who typed `relay.nostr.band`
into the Relays setting keeps it — the change is to the defaults only.

## 0.1.18 — 2026-09-02

Cut before the App Store submission, on the first fresh-install trip's findings and the first
Dependabot round. Nothing about what the app does changed.

### Fixed

- **A fresh install no longer lands on debug logging.** With no stored log level, the Settings
  page selected nothing, and a browser submits the first option of a select with nothing
  selected — `debug`. Saving the form to set the domain and address name wrote it without the
  operator touching the control. The page now shows the level actually in force, and a stored
  value that matches no option is parsed rather than mistaken for nothing.

### Changed

- **Built with Go 1.27.1.** Both images move to `golang:1.27-alpine`, pinned by digest, and the
  toolchain floor moves with them in the same change — so the gate tests the Go that ships
  rather than one either side of it.
- Dependency bumps proposed by Dependabot and gated before merge: `coder/websocket` 1.8.15,
  `golang.org/x/mod` 0.40.0, `google.golang.org/grpc` 1.83.2, `golang.org/x/net` 0.58.0; the
  base image refreshed to the current `1.27-alpine` build.
- The startup summary's redaction is now asserted on the rendered log record, both secrets,
  and the redaction table can no longer pass an entry whose value held no secret to leak.

### Upgrading

**Nothing to do.** No migration, no setting changes. If a fresh install of 0.1.17 left
`log_level` at `debug`, set it back to `info` on the Settings page once; the fix stops it
happening again but does not rewrite a stored choice.

## 0.1.17 — 2026-09-02

Two small things a reviewer would meet first, fixed before the App Store submission. Nothing
about what the app does changed.

### Fixed

- **A plain payment no longer writes an ERROR line.** An ordinary LNURL payment — and a
  Primal profile zap is one on the wire — settles like any other and owes no zap receipt.
  The obligation to publish one is recorded before that is known, deliberately, and the
  not-a-zap case was left for the retry loop, which reported it at ERROR about 45 seconds
  after every such payment. It is now cleared the moment it is known, at DEBUG.
- **The `sats` unit sits beside its input on the Sending page** instead of dropping onto a
  line of its own under each spending limit.

### Changed

- The images carry an OCI source label pointing at this repository.

### Upgrading

**Nothing to do.** No migration, no setting changes.

## 0.1.16 — 2026-08-31

The app has an icon. Nothing about what it does changed.

### Added

- **A mark.** An upturned umbrella catching zaps, in nostr purple, with `BZ` on the canopy. It
  is the browser-tab favicon, the touch icon, and the header mark beside the wordmark — one
  file for the last two, so the tab and the page cannot drift apart. The letterforms are cut
  from Archivo into path data, so the mark renders the same on a machine that has never heard
  of the font.

### Fixed

- Two things the page previews had been showing wrong for as long as nobody looked: the
  Connections page's budget read `0.000 sats per day` for any pairing with a budget, and the
  Sending page printed "This deployment does not permit sending" directly under "Sending is
  on". Both were preview-fixture defects, not app defects — the running app never showed
  them — but they were what a screenshot would have shown.

### Upgrading

**Nothing to do.** No migration, no setting changes.

## 0.1.15 — 2026-08-30

Outgoing zaps now say who they paid. A paired wallet app can tell this node, when it pays a
zap, who the payee is and what the comment was — and this node checks that claim against the
invoice it actually paid before keeping it. The result shows in the wallet app's history and on
BrollyZapper's own wallet page, where an outgoing zap used to be a bare arrow and an amount.

It reached a real box before it reached this release. The same code shipped first as the test
build `0.1.15-nwc-attribution` and and all three
wire changes below were confirmed against a real Amethyst build on a real phone, in both
directions: a wallet that knows about the feature and one that does not.

### Added

- **NWC-06 metadata on `pay_invoice` is accepted, bounded, verified, stored and echoed.** The
  client's signed zap request travels with the payment; the node binds it to the paid invoice's
  `description_hash`, so a stored label is a fact this node checked rather than a claim the
  client made. It comes back on `list_transactions` in the same `metadata.nostr` shape incoming
  zaps already use, so a client reads both directions with one parser. Bounded at NWC-06's
  4,096 characters. **A label can never cost a payment**: anything that does not verify is
  dropped and logged at INFO with a reason, and the payment settles regardless.
- **The info event advertises `extensions: 05 06`.** `05` is `list_transactions`, which this
  node has served all along and never advertised; `06` is the metadata convention above.
  Clients send metadata only to a wallet that advertises it, so this is the switch — and it
  ships last, after storage, so nothing is ever sent that would be discarded.
- **The admin wallet page names the payee** on an outgoing zap, as a shortened npub with the zap
  comment, and shows no receipt state on it. Nothing is fetched to do this; the node never
  resolves a profile.

### Changed

- **A payment with no memo now omits `description` entirely** instead of sending `""`. A zap
  invoice commits to a hash and carries no memo, so every outgoing zap was arriving with an
  empty string — which a wallet renders as a blank line where a label should be. Absent lets the
  client fall back to its own label. This is the one change every existing pairing sees, and it
  was checked against a wallet build that predates the feature.

### Fixed

- **The regtest stack had been dead for five weeks and nothing said so.** The relay's LMDB was
  on a macOS bind mount, and strfry's subscription threads read new events through a long-lived
  `mmap` that virtiofs never lets observe the write — so the relay accepted everything, stored
  everything, and delivered nothing to a subscription already open, with every visible signal
  healthy. Both relay databases are now named volumes, and a lint in the Go gate fails if one
  goes back.
- **The feature was dead on arrival and every unit test was green.** The six-line adapter
  between the LND decoder and the NWC service dropped `description_hash`, so the binding above
  refused every zap request for lacking a commitment that had never arrived. Found on the first
  regtest run that could reach it. Covered by a seam test, planted.

### Upgrading

**Nothing to do.** Migration 15 adds two nullable columns with `ALTER TABLE ADD COLUMN` — no
table rebuild, no touch on `balance_entries`. Downgrading to 0.1.14 is safe: the older binary
never visits a migration it does not know, and the two columns sit unread.

Attribution only appears for zaps paid *after* the wallet app starts sending metadata, which
for Amethyst means a build carrying its side of NWC-06. Zaps paid before that keep the rows they
have.

## 0.1.14 — 2026-08-28

One fix on top of 0.1.13: zaps sent from Primal web now arrive. Nothing else changed.

It reached a real box before it reached this release. The same code shipped first as the test
build `0.1.13-primal-patch` and and the fix was
confirmed against live Primal web traffic there rather than in a test alone. That is why this is
a patch release and not a candidate.

### Fixed

- **Zaps from Primal web are accepted.** Primal web percent-encodes the `nostr` parameter twice,
  so the zap request reached the callback as encoded text rather than JSON and was refused — every
  Primal web zap to this node failed. Rule 3 of the zap-request validation now attempts one further
  decode, and only when the parse has already failed and the bytes begin `%7B` or `%22`. The
  signature and id checks still run afterwards and are unchanged, so the fallback cannot make a
  request valid that was not: the worst an over-eager decode can do is reach the same refusal a
  rule later.

  It is a **workaround with an expiry**. The guard logs one INFO line per process when it fires;
  when that line stops appearing, the code goes. Review 2026-10-01. The upstream report is
  filed with Primal.

- The zap receipt's `description` tag is now taken from the verified request rather than from the
  bytes handed to the parser. The two were the same until the fallback above made them able to
  differ, and the tag must be the bytes whose signature was checked or a client discards the
  receipt after the invoice has been paid.

## 0.1.13 — 2026-08-27

The release that makes sending reachable again. 0.1.11 and 0.1.12 shipped with the spend gate
switchable only by editing a file umbrelOS overwrites on every app update, while the app's own
Sending page told the operator to change "this app's settings" — a place that did not exist. This
release replaces that with a route an operator can actually walk, and one that a compromised app
still cannot walk on its own.

### Added

- **Turning sending on is now an operator ceremony, not a config edit.** Ask for it on the Sending
  page and the guard writes a short-lived, single-use confirmation code into a file only you can
  read — on Umbrel, `Files → Apps → brollyzapper → data → guard → authorisation.txt`. Type the code
  back in and sending is enabled. No SSH, no compose edit, no restart.
- **The file says what it is authorising, in the guard's own words.** The guard composes that
  sentence, and the part of the app that faces the network cannot write it. So a confirmation
  cannot be quietly repurposed: a code issued to raise a limit to 50,000 sats cannot be redeemed
  for five million.
- **Spending limits are settable by the operator.** Both the 24-hour ceiling and the per-payment
  ceiling now live on the Sending page. **Lowering either takes one click. Raising either needs the
  same confirmation code**, because a limit the network-facing app could raise on its own would not
  be a limit.
- **The header shows which build is running**, so answering "which version is this?" no longer
  means reading container logs — which is not available to someone standing at the box with a
  phone.

### Changed

- **`GUARD_ALLOW_SENDING` has a different meaning, and its default is now `true`.** It is no longer
  the operator's gate; it is a *deployment ceiling* — "may sending ever be enabled here at all" —
  for a deployment that wants a hard "never". The operator's gate is now a latch stored in the
  guard's own directory, off on a fresh install, and that is what keeps BrollyZapper receive-only
  until you say otherwise. **A fresh install still cannot send until you perform the ceremony.**
- **`GUARD_MAX_SPEND_MSAT` and `GUARD_MAX_PAYMENT_MSAT` are initial values, not ceilings.** They
  seed the guard's stored limits on first start; afterwards the operator owns them. Treating them
  as ceilings would recreate the bug this release fixes — an unmovable limit set by package content
  nobody can reach.
- Turning sending **off** still takes one click and no code, and every route that ends sending now
  drops the latch — including a revocation you make at the node yourself. Re-enabling afterwards
  needs a fresh ceremony, deliberately: the app must never restore spending authority you removed.

### Fixed

- **Lightning address endpoints answer browsers.** Both LNURL legs returned `200` with no
  `Access-Control-Allow-Origin`, and `OPTIONS` returned `405`, so web clients such as Primal web
  could not zap this node at all. Native and mobile clients were unaffected, which is why it went
  unnoticed. The header is scoped to the two public endpoints and nothing else — the
  session-authenticated pages remain unreadable cross-origin.
- **Three kinds of security event were recorded nowhere.** `nwc.panic`, `connection.pause` and
  `connection.resume` were declared but never added to the audit vocabulary, and the auditor
  rejects an unknown event *before* writing its log line — so the containment added in 0.1.12 wrote
  neither a durable row nor a log entry, while every test passed. They now appear in the Security
  page's trail. The vocabulary is read from the source instead of hand-mirrored, so the same class
  of gap cannot reappear silently.
- A refused over-limit payment no longer costs a synchronous disk write, on a path a compromised
  app could drive at will.

### Diagnostics

- The inbound NWC log line now names **which encryption scheme a client asked for** — `absent`,
  `nip04`, `nip44_v2` or `unsupported` — which was previously unanswerable: the line said only that
  an encryption tag was present. `unsupported` is reported as that word rather than the client's own
  string, so nothing a client chose the contents of reaches the log. DEBUG, as that line already is.

### Upgrading

**Nothing to do.** If sending was enabled before the upgrade, it stays enabled: the guard reads a
live spend macaroon as your prior consent and sets the latch on. If it was off, it stays off.

Two things worth knowing if you are changing settings around the upgrade:

- A restart must **recreate** containers, not merely restart them — a container's environment is
  fixed at creation. On Umbrel, restarting the app from the desktop does this; `docker restart` does
  not.
- `LOG_LEVEL` set in the environment loses to the level stored in the app's settings, which is
  applied afterwards. Change it in the admin UI.
