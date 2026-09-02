# Changelog

This file starts at 0.1.13; this repository's history begins at 0.1.16.

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
