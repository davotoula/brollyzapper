# regtest — the off-Umbrel stack

Bitcoin regtest, two LND nodes, a nostr relay, and BrollyZapper, in plain Docker
Compose. No Umbrel, no OrbStack.

It exists for two reasons. The first is that spec §13's integration tests need a
node that can be paid and a relay that can be read: `o34.7` (end-to-end zap),
`d46.22` (the guard's rotation-exit path, untestable on a live box because
rotating `macaroons.db` takes every other app's credentials with it) and `d24.7`
(the spend macaroon's `ipaddr` caveat) all wait on it.

The second is the one worth leading with: **this is the off-Umbrel deployment
§19 has promised since the spec was approved, exercised.** The app runs here on
generic `LND_ADDRESS`/cert/macaroon settings and nothing else. `lint_test.go`
asserts that mechanically, so the promise cannot quietly decay.

## Up

```bash
docker compose up -d
```

One command. It mines 101 blocks, funds a second node, opens and confirms a
channel, and refuses to start the guard until LND's credentials actually exist
on disk. Nothing else is required — if a step is manual, that is a bug in
`scripts/init.sh`, not an instruction for you.

Watch it land:

```bash
docker compose logs -f init      # "ready — LND synced, channel open, credentials present"
curl -s localhost:8080/health    # ok
```

The admin UI is on <http://localhost:8080>, password `regtest-admin`
(`ADMIN_PASSWORD` in `.env` to change it).

## Prove it

```bash
./smoke.sh
```

Mints an invoice through the LNURL callback with a signed kind-9734, pays it
from the second node, asserts the wallet credited exactly once, and reads the
kind-9735 receipt back off the relay, checking its description hashes to the
invoice's `description_hash`.

This is `o34.7`'s skeleton. The rest of that bead is `e2e.sh`:

```bash
./e2e.sh              # criteria 1-9
./e2e.sh 7 8          # just those
```

Nine criteria, each a numbered section that exits non-zero on failure: the
replay, the `settle_index` resume across a restart, the profile / event /
addressable zap shapes, the LUD-12 comment round trip, the settle-time
`created_at`, relay-down-then-up with and without a server restart, and the
sender-named relay's socket being closed again. It is self-contained — run it
without `smoke.sh` if you like — and it puts the stack back on the way out even
when an assertion fires, because several criteria deliberately stop the relay or
the server.

Criteria run in a deliberate order and the last one rewinds the resume point, so
a partial run is fine but a re-ordered one may not be.

### The client check

```bash
go install github.com/fiatjaf/nak@latest
./client-check.sh
```

Criterion 10 is a real client accepting a receipt, and it is manual by nature —
"does it render as a zap" needs eyes. What this scripts is everything a client
does *before* it renders: subscribe with an ordinary `kind:9735 #e` filter,
re-derive the id, check the signature, check `sha256(description)` against the
invoice's `description_hash` (NIP-57 Appendix F), and resolve the tags into the
npubs and nevent a UI would show.

`nak` is the third client the criterion names and the right one to script — Damus
and Amethyst are phone apps — and it is independent where it counts: different
author, different codebase, and **upstream** go-nostr rather than this repo's
pinned fork. It also flips one signature byte and confirms `nak` *rejects* that,
because "nak said nothing" and "nak was not checking" look identical otherwise.

## Down

```bash
docker compose down -v      # containers, network and volumes
rm -rf data                 # the chain and both wallets
```

Nothing here is precious. `data/` is gitignored and every wallet in it is a
regtest wallet holding regtest coins.

## Running the working tree instead of the release

The canonical `docker-compose.yml` pins published images **by digest**, so the
stack is reproducible. To run what is currently checked out:

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

The canonical file now pins the **0.1.16** images by digest, and `smoke.sh` passes against them
as-is — verified 2026-08-31 on a stack brought up from empty volumes: both containers reporting
`version 0.1.16`, clean chain, mint, pay, credit once, receipt read back off the relay. It read
0.1.5 when that was the first release publishing zap receipts, then 0.1.10 (verified by the PM on
2026-08-22 the same way). **Every bump is re-proved by that run rather than assumed** — a pin
nobody has exercised is a pin that documents a version instead of testing one. The build override
exists to run the *working tree* instead, for changes that have not been released yet.

Everything else is pinned by digest too — LND, bitcoind and both relays — and
`stack_lint_test.go` fails if any image goes back to a bare tag.

## Things that bit, and are now handled

Eight of these cost real time. They are recorded because the next person will
otherwise meet them in the same order.

- **No sender-named relay can be dialled in this stack, and that is correct.**
  `z9k` resolves every relay a zap request names and refuses it unless *every*
  resolved address is public. Every address inside a compose network is private,
  so a relay named by the request is always refused here — `relay2.zap.test`
  included, and no subnet trick fixes it: every documentation and test range is
  (correctly) in the allow-list table, and squatting on allocated space costs the
  host a route to it while the stack is up. Since `vz1.4` the check also runs at
  DIAL time, on the address actually resolved — so a name that passes the filter
  and then resolves onto the compose network is refused at the socket. The
  operator-configured relay is exempt on both, which is what makes `relay`
  keep working: every green `e2e.sh` run is that exemption being exercised
  against a legitimately private address. Criterion 9 used to assert the
  opposite — that a sender-named relay's socket was opened, used and closed —
  and was rewritten (`vz1.1`) to assert the refusal instead, which is the thing
  this stack can actually prove. Socket **eviction** is asserted in
  `internal/nostr`'s lifecycle tests against a real websocket fleet, where a held
  publish makes the count exact. Relays the OPERATOR configures are exempt from
  the resolution check, which is why `relay` keeps working.

- **The credential volume must be a named volume, not a host bind.** The guard
  `chmod`s its unix socket; `chmod` on a socket inside a macOS bind mount
  (virtiofs) fails with `EINVAL`, and the guard crash-loops on
  `securing /credentials/guard.sock`. On Umbrel the host is Linux and a bind
  mount is fine. LND's directory *does* stay a host bind, because the guard
  mounts `tls.cert` and `admin.macaroon` out of it as single files and you
  cannot bind-mount a file out of a named volume.

- **The relay databases must be named volumes too, and for a nastier reason.**
  Same macOS filesystem, different victim: strfry's writer commits into LMDB and
  its `reqMonitor` threads read new events back through a long-lived `mmap`,
  which across virtiofs never observes the write. The relay then accepts the
  subscription, answers `EOSE`, accepts every published event with `OK true`,
  stores it, and returns it to a *fresh* query — while pushing **nothing** to the
  subscription already open. There is no error, no rejection and no log line;
  every visible signal says the relay is healthy. `nwc.sh` died 20 seconds into
  section 1 on a `get_balance` the app had never been handed, and stayed dead for
  five weeks with no commit to blame (`BrollyZap-qnz`). Measured across six filter
  shapes: strfry 1.1.0, 1.1.1 and 1.1.2 all deliver on a named volume and all fail
  on a bind mount, NIP-42 on or off — the version is irrelevant, the storage is
  the whole variable. `stack_lint_test.go` fails if either relay goes back to a
  bind mount. The credential entry above is the same lesson one layer up: a macOS
  bind mount is not a filesystem, and anything doing more than reading and
  writing whole files will find out.

- **A zap request cannot name this relay.** `internal/lnurl`'s `isLocalHost`
  treats any single-label hostname as local — which every compose service name
  is — and refuses to dial it. That guard is correct and should not be relaxed
  for a test: a zap request is anonymous input. So `smoke.sh` has the request
  advertise a dotted host that never resolves, and the receipt reaches the local
  relay through the operator-configured default set, which is the path an
  operator actually relies on.

- **strfry's shipped config is a pubkey whitelist.** `dockurr/strfry` sets
  `writePolicy.plugin = /app/write-policy.py`, which rejects the app's receipt
  with `blocked: pubkey … not in whitelist`. The app handles it correctly —
  logs `no relay accepted a zap receipt; queued for retry` and backs off — so
  from outside it looks like nothing was published. `strfry.conf` disables the
  plugin and changes nothing else.

- **LND does not re-peer after a restart, so the channel goes inactive.**
  `scripts/init.sh` connects the payer to the receiver once at stack-up and
  never runs again. Anything that restarts `lnd` — `rotation.sh` does, by design
  — leaves `listpeers` empty and the channel `active=false`, and the next
  payment times out. That reads exactly like the app failing to recover and is
  not. `rotation.sh` re-peers and waits for the channel before it pays.

- **The server image has no shell.** It is distroless/static on purpose — it is
  all the attack surface, so it carries no tools. Anything that needs to look at
  the database goes through `tools/sqlite`, a throwaway container on the same
  named volume, and anything that needs to see the server's sockets joins its
  network namespace from a sidecar (`docker run --net=container:<server>`)
  rather than exec'ing in.

- **Payment hashes are truncated to eight characters in the logs** by §12's
  redaction, so a script grepping the logs for a full hash finds nothing and
  reads it as "the thing never happened". `e2e.sh` matches on the first eight.

- **`lncli` in the init container defaults to `127.0.0.1:10009`,** which is the
  init container itself. Both nodes need an explicit `--rpcserver`, and LND
  needs `--tlsextradomain=<service>` or dialling it by service name fails TLS
  verification in a way that reads exactly like a macaroon problem.

## Layout

| | |
|---|---|
| `docker-compose.yml` | the stack; images pinned by digest |
| `docker-compose.build.yml` | override to build the working tree |
| `scripts/init.sh` | mine, fund, open the channel, verify credentials exist |
| `smoke.sh` | the happy path end to end |
| `e2e.sh` | `o34.7` criteria 1-9 |
| `client-check.sh` | `o34.7` criterion 10, as far as a script can take it |
| `rotation.sh` | `d46.22` — rotate the node's macaroons and assert every step of §6 |
| `ipaddr.sh` | `d24.7` — what LND's `ipaddr` and `iprange` caveats actually bind to, both directions. **Bakes macaroons: regtest only** |
| `spend.sh` | `d24.1` — the guard mints the right to spend and takes it back. Ends on the P3 epic's **release criterion**: a copy of `spend.macaroon` kept before `RevokeSpend` is refused by LND afterwards. **Bakes macaroons and revokes root keys: regtest only** |
| `cap.sh` | `tna.3` — **P4's two exit criteria**, on a live node: a payment over the guard's rolling 24 h cap is refused with every server-side check bypassed, and killing the guard makes LND reject the spend macaroon outright. Every call goes **straight to LND with the credential**, from inside the server's network namespace, so §5's ceiling, §8's ladder and §11's Tier-2 rows are out of the path by construction rather than by mocking — which is the compromised-server model §6 is written against. Stops the guard and puts it back from an `EXIT` trap. **Bakes macaroons and revokes root keys: regtest only** |
| `authorise.sh` | `06v` — the **operator's ceremony**, and the one assertion no unit test can make: `docker inspect` says the server container has **no mount for `data/guard`**, so a code written there is out of reach of the container the design defends against. Drives the whole sequence in the operator's own steps — the server alone gets nowhere, the guard writes the file, three wrong codes spend the grant, the operator's code works once, a spent code cannot re-mint after a revoke, and a cap lowers freely but raises only with a code bound to that exact value. **Bakes macaroons and revokes root keys: regtest only** |
| `tools/guardctl/` | drives the guard's socket (`status`, `bake-spend`, `revoke-spend`, and `06v`'s `authorise`/`apply`), which has no CLI. Goes through `guard.SocketClient` — the **server's own** side of the wire — so the format, the operation vocabulary and the audit relay under test are production's. One command, `read-code`, is the **operator's** step rather than the server's, and it needs the guard's own volume mounted: the split between `guardctl` and `guardctl_op` in the scripts is the security property written out. Main module, cross-compiled by the scripts because it runs inside a container: the socket lives in the credential volume |
| `nwc.sh` | `d24.3` — §8's wallet service over a real relay: authorized request answered, foreign pubkey ignored without decryption, replay returns the identical response, out-of-window request refused and not cached, `pay_invoice` absent, `9xg`'s field half (a zap publish leaves the subscription connected), and a connection on `relay2` — **not** in `default_relays` — answered on its own relay and nowhere else. **Seeds connections directly in the database** (the admin UI is `d24.5`) and **deletes them on the way out**: a live NWC subscription is a socket the app holds, and one left on `relay2` fails `e2e.sh` §9 in a later run with a message about zap receipts |
| `tools/nwctool/` | a NIP-47 client. A **separate module**, like `zaptool`: it needs go-nostr's `nip04`/`nip44` directly, and main-module tooling is kept dependency-free by an arch rule. It speaks the protocol rather than calling our codec — two halves sharing an implementation prove they agree with each other, not with NIP-47. `-save`/`-resend` replay one event VERBATIM, which is what a relay redelivery actually is, and `-genkey` mints the keypairs `nwc.sh` seeds a connection with — here rather than in a main-module tool, which would have needed a private-key accessor on `internal/nostr.Identity` that exists for nothing else |
| `tools/mactool/` | adds the one caveat `lncli` cannot (`iprange`), and reads a macaroon back three ways — `-caveats`, `-require <name>`, `-value <name>`. In the **main module**, deliberately: every mode goes through `internal/lnd`'s own functions, the ones the guard bakes and verifies real credentials with, so a defect in production's path is a defect this finds. An arch rule keeps main-module tooling free of third-party imports, which is what makes that safe; `zaptool` needs them and so has its own module |
| `tools/zaptool/` | signs a kind-9734 (`-e`, `-a`, `-k`) and reads receipts back; a **separate Go module**, so it cannot disturb the repo's `go.mod` |
| `tools/sqlite/` | `sqlite3` against the server's data volume — the server image is distroless and has no shell |
| `strfry.conf` | vendor default, two changes, both explained in its header |
| `lint_test.go` | §19's promise, asserted |
| `stack_lint_test.go` | the stack's reproducibility, asserted: both relay databases on named volumes rather than macOS bind mounts, and every image pinned by digest (`BrollyZap-qnz`) |

### The second relay

`relay2` is a relay the operator has **not** configured, reachable at the dotted
alias `relay2.zap.test`. It exists so `e2e.sh` criterion 9 can fail: with only
`relay` in the stack, a zap request cannot name a relay at all — every compose
service name is single-label and refused — so no transient socket is ever opened
and "the count returned to the configured size" is true having tested nothing.
A dotted name is the one shape the filter passes, because hostnames are
deliberately not resolved on the callback path.

## Knobs

`.env`, all optional:

```
APP_PORT=8080          # host port AND container port — see the note below
RELAY_PORT=7777
RELAY2_PORT=7778
CHANNEL_SAT=5000000
ADMIN_PASSWORD=regtest-admin
```

`APP_PORT` is published on the *same* number the app listens on, deliberately.
The lightning address is `http://localhost:8080`, and that has to resolve to the
app both from your shell and from inside the container, because the app
self-probes its own address. Map it to a different host port and the self-probe
starts failing while everything else looks fine.
