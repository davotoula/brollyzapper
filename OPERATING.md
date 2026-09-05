# Operating BrollyZapper

The reference. [`README.md`](README.md) gets a lightning address working and publishes
it through Cloudflare; this covers everything you touch afterwards — every setting, what
happens when you get one wrong, backups, credential rotation, and the hazards of adapting
the package for a deployment it was not written for.

Read the README first. This assumes the app is installed and answering.

---

## Contents

- [Settings you can reach in the app](#settings-you-can-reach-in-the-app)
- [Sending, and the two caps](#sending-and-the-two-caps)
- [Deployment settings, which no page shows](#deployment-settings-which-no-page-shows)
- [When a change takes effect](#when-a-change-takes-effect)
- [Backups, and the one directory left out](#backups-and-the-one-directory-left-out)
- [Rotating the node's macaroons](#rotating-the-nodes-macaroons)
- [Uninstalling does not revoke anything](#uninstalling-does-not-revoke-anything)
- [Running outside Umbrel](#running-outside-umbrel)
- [Storage](#storage)

---

## Settings you can reach in the app

Everything here lives on **Settings** and is stored in the database. All of it takes effect
within about two seconds — see [When a change takes effect](#when-a-change-takes-effect) for
the ones that do not.

### Public domain

The host your lightning address lives on, entered bare: `zap.example.com`. A pasted
`https://` is stripped and the scheme remembered beside it, so Settings shows which one
wallets will be handed. Changing the host on its own returns to `https`.

**Default:** empty. Nostr Wallet Connect works without a domain; a lightning address does not.

**Get it wrong** and the app advertises a callback nobody can reach, or — worse — one that
reaches a *different* LNURL server that resolves and responds. The Security page's
reachability check exists for exactly that: it fetches your own address over the public
internet and verifies the response carries this instance's nostr pubkey and a per-boot header
only it emits. A domain that points somewhere else fails it. Fix that before anything else.

### Address name

The part before the `@`. `test` gives `test@zap.example.com`.

**Default:** empty. **Get it wrong** and requests for the old name return a plain 404 with no
hint that another name exists — deliberate, so a stranger cannot enumerate what you host.

### Trusted proxies (CIDR list)

Which upstream addresses may be believed when they claim a client's real IP. Empty trusts
nothing, which is the safe default: without it, every request behind a proxy arrives from the
proxy's own address.

**Default:** empty here; the deployment's `TRUSTED_PROXIES` is used when this is unset. **The
setting wins when you set one.**

**Get it wrong in the trusting direction** — naming a range you do not control — and anyone
who can reach the app through it can claim any client IP they like, which makes the
per-sender rate limits meaningless. **Get it wrong in the other direction** and every
anonymous request shares one bucket, so one busy zapper exhausts the limit for everyone. On
Umbrel the `app_proxy` sits in front and the package handles this; off Umbrel, see
[Running outside Umbrel](#running-outside-umbrel).

### Relays

Where zap receipts are published, one per line. Empty means the built-in default set.
Receipts also go to whatever relays each zap request names, so this is an addition to those,
not a replacement.

**Default:** empty (the built-in set). **Get it wrong** — unreachable or private-address
relays — and receipts are published to fewer places than you think. The relays a zap request
names are filtered too: literal private addresses, non-websocket schemes, duplicates and
anything past the cap are dropped. Turn `log_level` to `debug` and the parse logs what it
dropped and why.

### Public rate limit, per minute and per hour

The ceiling on **total anonymous traffic** to the public callback. It governs the public
routes only.

**Defaults:** 60 a minute, 600 an hour. **These are a backstop on the whole box, not a
per-sender limit** — that is separate and fixed at 10 a minute and 100 an hour per verified
sender, and is not operator-adjustable.

**Get it wrong** by setting it too low and legitimate zaps bounce during a burst; too high
and you widen what a stranger can make your node do. It does **not** affect the admin login
limit, which is a constant 30 a minute and deliberately not a setting: an operator has no
legitimate reason to raise their own brute-force ceiling. Those used to be one unlabelled
pair, and raising it until zaps stopped bouncing silently raised the login ceiling by the
same amount.

If you publish through Cloudflare, this is the **inner** of three layers. The edge rate-limit
rule is required, not optional — README §"Rate limiting at the edge".

### Fee reserve, ppm and floor

How much of a payment's value is held back to cover routing fees, as parts-per-million with a
floor in msat. The larger of the two applies.

**Defaults:** 10,000 ppm (1%) and 10,000 msat (10 sat). **Get it too low** and payments fail
to route, or the reserve does not cover the actual fee; **too high** and each payment reserves
more of the ceiling than it needs, so fewer payments fit in the window.

### Log level

`debug`, `info`, `warn` or `error`, applied without a restart.

**Default:** `info`. **This setting overrides the `LOG_LEVEL` environment variable** — the
stored value is applied after the environment on boot, so if the two disagree, this one wins.

**It sets the server's level only.** The guard is a separate container with its own logging, and
it reads its level from its own `LOG_LEVEL` environment variable — nothing on this page changes
it. If you are turning `debug` on to diagnose something the guard does — baking or revoking a
spend macaroon, or a refused operator change — set `LOG_LEVEL` on the guard container too.

`debug` is worth turning on when diagnosing delivery: the relay filter and the double-encoding
rescue both log there. It is safe to leave on briefly and noisy to leave on forever; nothing
secret is logged at any level.

### Incoming payments raise the spending ceiling

A checkbox. When on, sats you receive increase the amount the app may spend.

**Default:** on — the wallet you zap out of is the wallet zaps land in.

**Turn it off** and the ceiling only ever moves when you move it, so received zaps accumulate
without becoming spendable by the app. This has a real financial consequence in both
directions and one line of label; if you are unsure, the conservative reading is that "on"
means money arriving quietly raises what a compromised app could spend, bounded still by the
guard's own caps, which this cannot touch.

### Nostr identity

**This is the app's own key, not yours.** It is minted on first run and you do not normally
touch it.

It signs zap receipts and is announced as `nostrPubkey` in the lightning address response, so
senders' clients use it to recognise receipts as genuinely from this address. You are
identified as the *recipient* by the zap request's `p` tag — a different thing entirely.

The import field exists for **continuity**: restoring a backup that lost the database, moving
to a new box, or rebuilding an install whose address is already published. Import the key that
install used, and previously published receipts stay verifiable.

**Do not paste a personal nostr identity key here.** It would put a key that can post, DM and
delete as you into the server container — the part of the app that faces the network — and it
would gain you nothing, because a receipt-signing key is worthless to an attacker and being
"you" is not what a zap receipt claims.

Replacing the key means receipts already published stay signed by the old one.

### Admin password

Changeable in the app only when the deployment has not set one. On Umbrel the password is
derived per-install and managed by umbrelOS, so the field is absent; off Umbrel, set
`ADMIN_PASSWORD` (minimum 8 characters) or change it here.

Changing it bumps a session counter that is part of every cookie's signature, so **every
existing session is invalidated** — including a copy taken from a browser no longer under your
control. That is the point: restarting the app alone would not do it.

---

## Sending, and the two caps

Sending is off on a fresh install and turning it on is deliberately not one click.

**The latch** is your own gate, on the **Sending** page. Turning it on asks the guard for an
authorisation: the guard writes a single-use code into a file only you can read, states in its
own words what is being authorised, and you type the code back. The app that asked cannot read
that file, which is what makes the confirmation mean something — the part of the app facing the
network cannot forge it.

The page tells you where the file is and how long the code has left. Codes are single-use and
expire; asking again gives you a new one. Turning sending *off* takes one click and no
code — the ceremony is the price of the safe direction being free.

**The two caps** are the guard's, and it enforces them inside your node's request path rather
than in the app:

| Cap | Default | What it bounds |
|---|---|---|
| 24-hour limit | 100,000 sats | Everything spent in any rolling 24 hours |
| Per-payment limit | 25,000 sats | One payment |

**Lowering either takes one click. Raising one needs a confirmation code.** That asymmetry is
the whole design: a compromised app can only ever tighten its own limits.

**A cap of zero refuses every payment.** It does not mean "no cap" — an operator who types 0
into a field called "maximum spend" means *do not spend*, and that is what it does. The
per-payment limit must also stay at or below the 24-hour one, or the guard refuses the change:
a per-payment limit above the window could never be reached.

---

## Deployment settings, which no page shows

These are environment variables, fixed when the container is created. Nothing in the app can
change them, and **changing one needs a restart that recreates the container** — see below.

| Variable | Default | What it does, and what going wrong looks like |
|---|---|---|
| `GUARD_ALLOW_SENDING` | `true` | The deployment's ceiling on sending. `false` is a hard never that nothing inside the app can lift — the Sending page will say so rather than offering a control that cannot work. It is **not** the same as the latch: both must be on. |
| `GUARD_MAX_SPEND_MSAT` | `100000000` (100k sat) | The 24-hour cap's starting value. Zero refuses everything. |
| `GUARD_MAX_PAYMENT_MSAT` | `25000000` (25k sat) | The per-payment cap's starting value. Must be at or below the 24-hour cap. |
| `GUARD_AUTHORISATION_LOCATION` | empty | A sentence telling *your* operator where to find the authorisation file, shown on the Sending page. Free text, deliberately unvalidated — only the deployment knows its own file paths. Leave it empty off Umbrel and the page simply says less. |
| `LND_ADDRESS` | — | Your node's gRPC address. |
| `LND_CERT_FILE`, `LND_ADMIN_MACAROON` | — | Paths to the two files mounted from the node. See [the mount hazard](#running-outside-umbrel). |
| `CREDENTIALS_DIR`, `DATA_DIR` | — | The credential volume and the app's own data. |
| `GUARD_SOCKET` | inside `CREDENTIALS_DIR` | Where the guard listens. |
| `LISTEN_ADDR` | `0.0.0.0:8080` | The admin and public HTTP listener. |
| `TRUSTED_PROXIES` | empty | Fallback for the setting of the same name. The stored setting wins when set. |
| `LOG_LEVEL` | `info` | Fallback for the stored log level, which wins when set. |
| `ADMIN_PASSWORD` | empty | Minimum 8 characters. Set means the deployment manages it and the in-app change form disappears. |
| `SESSION_SECRET` | empty | Minimum 16 characters. Empty means one is generated and persisted, which is what an off-Umbrel deployment wants. |

---

## When a change takes effect

Three categories, and the third is the one that surprises people.

1. **Settings in the app: within about two seconds.** They are database rows read through a
   short-lived cache. No restart, no reconnect.
2. **The sending latch and the caps: immediately**, on the next payment the guard sees.
3. **Environment variables: only when the container is RECREATED.** A container's environment
   is fixed at creation. On umbrelOS that means restarting the app from the dashboard (`apps.restart.mutate`),
   which recreates;
   `docker restart` does **not**, and will leave you editing a compose file and wondering why
   nothing changed.

And the precedence trap worth stating twice: for `LOG_LEVEL` and `TRUSTED_PROXIES`, the
**stored setting wins over the environment variable**, because the stored value is applied
after the environment on boot. Changing the compose file while a setting is present changes
nothing.

---

## Backups, and the one directory left out

The Umbrel package excludes exactly one path from backups:

```yaml
backupIgnore:
  - data/credentials
```

**Why it is excluded.** That directory holds `recv.macaroon`. In a stolen backup it would
stream every invoice on your node over LND's Tor-published gRPC — to anyone holding the file,
from anywhere.

**Nothing is lost by excluding it.** The guard bakes a fresh, correctly caveated credential on
its own start, so a restore recovers unattended — and with a *better* credential than a stale
one whose time-before may have passed. The guard's own state lives in `data/guard`, which
**is** backed up, so the recorded root key ids survive and revocation still works afterwards.

**The database is backed up and must be.** It holds the only zap-receipt signing key. Lose it
and the `nostrPubkey` your lightning address advertises changes, which means receipts signed by
the new key no longer match what senders' clients were told to expect. If you are restoring
onto a rebuilt box and the database is gone, this is what the Nostr identity import field is
for.

---

## Rotating the node's macaroons

Rotating `macaroons.db` is the only way to revoke a credential LND has already issued. It
invalidates **every** macaroon on the node, so every app that talks to it must be stopped and
re-linked afterwards — BrollyZapper among them.

Roughly:

1. Stop every app that holds a macaroon for the node, BrollyZapper included.
2. Rotate the node's macaroons by your node software's own procedure.
3. Start the apps and re-link each one.

BrollyZapper recovers on its own: the guard holds `admin.macaroon` and re-bakes what it needs
on start. If sending was on, the spend macaroon is re-baked through the same ceremony-gated
path — the latch survives, because it is the operator's stored intent, not a credential.

**Re-link or rotate.** Re-linking replaces what *this app* holds. Rotating is what makes an old
copy stop working anywhere. If a credential may have leaked, re-linking is not enough.

---

## Uninstalling does not revoke anything

Uninstalling deletes `app-data`, which deletes the app's copy of `recv.macaroon`. **It does not
revoke it.** The credential remains valid against your node until the node's macaroons are
rotated, and there is no revoke-on-uninstall for the receive credential.

"I uninstalled it" is not "I revoked it", and the distinction matters enough to state plainly.

What that credential can do, exactly — it is baked to five operations and no others:

```
AddInvoice   ChannelBalance   GetInfo   LookupInvoice   SubscribeInvoices
```

So it can **mint invoices and read node information. It cannot spend.** No copy leaves the box
unless you copy it — and the backup exclusion above is there so that "copy it" does not happen
by accident.

If you want it genuinely dead, rotate ([above](#rotating-the-nodes-macaroons)).

---

## Running outside Umbrel

The app itself takes generic settings — an LND address, a cert, a macaroon — so it runs
against any LND. The published images are
`ghcr.io/davotoula/brollyzapper` and `ghcr.io/davotoula/brollyzapper-guard`, and
`regtest/docker-compose.yml` is a working reference stack: the two BrollyZapper services in
it are the whole deployment; the rest is a test node and relay. The Umbrel-specific wiring
lives only in the package. Two things need care.

### The single-file mount hazard

The package mounts two individual **files** from the node's data directory, read-only:

```yaml
- ${APP_LIGHTNING_NODE_DATA_DIR}/tls.cert:/lnd/tls.cert:ro
- ${APP_LIGHTNING_NODE_DATA_DIR}/data/chain/bitcoin/${NETWORK}/admin.macaroon:/lnd/admin.macaroon:ro
```

**Never mount the directory instead.** Adapting this for a plain-Docker deployment, the
convenient-looking change is to mount the parent and let the paths fall out of it. That
directory also contains `wallet.db`, `macaroons.db` and `channel.backup` — and with a default
wallet password, `wallet.db` is the seed. Mounting individual files is the whole reason a
compromise of this app is not a compromise of the node.

The same applies to which container gets what: `admin.macaroon` is mounted into the **guard**
only, never the server. The server has no mount for it and cannot read it.

### Trusted proxies

With no `app_proxy` in front, decide deliberately:

- **Nothing in front** — the app is reached directly. Leave `TRUSTED_PROXIES` empty. Client
  addresses are already real.
- **A reverse proxy you run** — set the range the proxy connects *from*, not the range clients
  come from. On a single-host Docker setup that is the Docker bridge network, typically a
  `/16` such as `172.17.0.0/16`; check your own network rather than copying that.
- **A CDN or tunnel** — the connecting address is the tunnel daemon's, usually loopback or a
  container address. Name that.

Name the narrowest range that covers the hop you actually control. Anything wider is a range
someone else can arrive from, and the per-sender limits stop meaning anything.

Verify rather than assume: README §"Verify before trusting it" has the procedure, including a
negative control.

---

## Storage

Every admitted callback costs an fsync — the app commits before answering, so it cannot mint
an invoice it failed to record.

**Measured on the reference box** (a SATA SSD over USB): ~2.35 ms per commit, about 3.5% of a
66 ms callback. The dominant cost is the round trip to LND, not the disk barrier. At the
default 60/min backstop, a hostile stranger can demand about 141 ms of fsync a minute — a
quarter of one percent of it.

**On an SD card this has not been measured**, and the honest statement is that it would be
worse rather than by how much. Flash cards also wear under sustained small synchronous writes.
If `app-data` is on an SD card and you are exposing a public lightning address, moving it to an
SSD is the cheap precaution; the numbers above do not transfer.
