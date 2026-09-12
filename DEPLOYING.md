# Deploying BrollyZapper

For the operator putting the lightning address on the internet, or running the app somewhere
other than umbrelOS. [`README.md`](README.md) gets it installed and answering; this is the next
step, and it is where the hard-won parts live. [`OPERATING.md`](OPERATING.md) is the reference
for every setting once it is running.

## Contents

- [What is exposed](#what-is-exposed)
- [Putting the address on the internet: Cloudflare Tunnel](#putting-the-address-on-the-internet-cloudflare-tunnel)
- [Running outside Umbrel](#running-outside-umbrel)

---

## What is exposed

Exactly three paths are public (each also answers CORS preflight). Everything else — the whole admin UI — sits
behind authentication, and unknown paths are private by default rather than
public by accident.

| Route | Purpose |
|---|---|
| `GET /.well-known/lnurlp/{name}` | The LUD-16 pay document. Static, cacheable, unlimited. |
| `GET /lnurlp/{name}/callback` | Mints an invoice. Takes `amount` (msat), optional `nostr` (a signed kind-9734) and optional `comment`. Never cached. |
| `/health` | `200 ok` or `503`. Nothing else — no version, no balance, no node state. |

---

## Putting the address on the internet: Cloudflare Tunnel

A tunnel is the recommended way to put the address on the internet: no port
forwarding, no inbound firewall hole, and TLS terminates at Cloudflare.


### 1. The tunnel

In **Zero Trust → Networks → Tunnels**, add a public hostname to your tunnel:

```
Subdomain:  zap
Domain:     example.com
Path:       (leave empty)
Service:    HTTP  ->  <box-ip>:3033
```

**HTTP, not HTTPS.** TLS terminates at Cloudflare and the connector speaks plain
HTTP to the box, which is what the app expects behind its auth proxy. Pointing
it at HTTPS makes the connector attempt TLS against a listener that does not
speak it.

**Leave Path empty.** The app needs both `/.well-known/lnurlp/*` and
`/lnurlp/*`; scoping the hostname to one path breaks the other.

### 2. Do not put the public paths behind Access

If any Cloudflare Access policy matches the hostname — a wildcard across the
zone will — anonymous LNURL clients receive a sign-in page instead of JSON and
**zaps fail with no visible error**. Check **Zero Trust → Access → Applications**
for anything whose domain pattern covers the new hostname.

`/.well-known/lnurlp/*` and `/lnurlp/*` must be reachable with nothing in front
of them. The admin UI needs no such exception: it is already behind the app's own
login and, on Umbrel, the platform's auth proxy as well.

### 3. Never set `PROXY_TRUST_UPSTREAM`

It makes the auth proxy forward a client-supplied `X-Forwarded-For` verbatim,
handing any caller a spoofed source address. The compose lint forbids it.

### 4. Verify before trusting it

From a device **outside** your LAN — a phone on cellular, not the box:

```
https://<hostname>/nonexistent
    A 404 or auth bounce from your deployment.
    NOT a Cloudflare error page (1033 = the connector is not connected),
    and NOT some other service on the same host.

https://<hostname>/.well-known/lnurlp/<name>
    200, JSON, "allowsNostr": true, a 64-hex "nostrPubkey".

https://<hostname>/
    An auth bounce or a 404 — never the app's own login page.
```

The first check matters more than it looks. Without it, "the hostname answers"
and "the tunnel is answering for something else on that host" are
indistinguishable.

### 5. Rate limiting at the edge — required, not optional

**On a tunnel, the app cannot see who is calling.** Every internet client
arrives at the origin as the same address (the container bridge gateway), so
per-client limiting is impossible there — which is why the app's public limiter
is a single *global* ceiling rather than per-IP. Cloudflare's edge is the only
place a real client address still exists, so per-client fairness has to live
there.

In **Security → Security rules → Rate limiting rules**:

```
Match:      URI Path  starts with  /lnurlp/
Rate:       5 requests per 10 seconds     (free plan window)
Counting:   by IP
Action:     Block
```

- **Match `/lnurlp/` only.** Do **not** include `/.well-known/lnurlp/`. That
  document mints nothing, costs nothing, and is fetched by the app's own
  self-probe — rate limiting it lets a stranger starve the probe until the
  Security page reports your own address unreachable.
- **The action must be Block, never a Challenge.** A challenge returns an HTML
  interstitial for a browser to solve. The callers here are wallets and nostr
  clients; they would receive HTML where they expect JSON and the zap would fail
  with nothing useful to show the payer.
- **Why 5-per-10s.** The edge rule only earns its place by being tighter *per
  client* than the app's global ceiling of 60/min. At 10-per-10s a single
  address could sustain exactly 60/min and consume the entire global budget
  alone. At 5, it is stopped with the shared budget still half free.
- On a paid plan, prefer a per-minute window and set 30/min per IP.

> **A 10-second window bounds bursts, not patience.** A caller pacing at 4
> requests per 10 seconds never trips the rule yet consumes a large share of the
> global budget indefinitely. The free tier cannot express "30 per minute". That
> is a real limitation of this configuration, not an oversight.

### 6. Confirm the rule actually fires

A deployed rule is not a working rule. Send more than the threshold from one
address in one window and check what comes back:

```bash
seq 1 20 | xargs -P 20 -I{} curl -s -o /dev/null -w '%{http_code}\n' \
  'https://zap.example.com/lnurlp/<name>/callback?amount=1000' | sort | uniq -c
```

- **Cloudflare's HTML block page** — the rule is working.
- **`{"status":"ERROR","reason":"this address is receiving more requests…"}`** —
  that is the *app's* limiter. The request reached the origin, so the rule did
  not match.
- **`{"status":"ERROR","reason":"this address has too many unpaid invoices open…"}`**
  — the open-invoice cap. Also the app. Wait for them to expire (ten minutes)
  before testing again, or every response will be this regardless of the rule.
- **All 200** — the rule is not in effect at all.

Then confirm the exemption still holds: the document must stay reachable and the
Security page green *while* the callback is being blocked.

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://zap.example.com/.well-known/lnurlp/<name>
```


**If nothing blocks:**

- Check the rule is **deployed and enabled**, not saved as a draft. Editing an
  expression does not deploy it.
- Free zones allow a limited number of rate limiting rules. Extra rules sit
  inactive with no warning.
- Inspect the generated expression, not the form. A stray leading space in the
  path value produces `starts_with(http.request.uri.path, " /lnurlp/")`, which
  can never match, and the form gives no hint.
- **Security → Events** logs every rate-limit match. No events during a burst
  means the rule never evaluated — which separates "not deployed" from
  "deployed but not matching" without guesswork.

### The layers, and what each one is for

| Layer | Bounds | Where |
|---|---|---|
| Edge rate limit | one abusive client | Cloudflare |
| Global backstop (60/min default) | total anonymous traffic | the app |
| Open-invoice cap (100) | invoices held in LND | the app |

The open-invoice cap is the real resource bound: it protects the node's invoice
database and clears itself as invoices expire — an unpaid LNURL invoice in 600 seconds, so a flood
through the public callback costs the node ten minutes at the ceiling; NWC-minted invoices
share the cap and expire in an hour. The other two
shape traffic; this one is what actually limits what a stranger can consume.

---

## Running outside Umbrel

This is for an LND **you already run on this host** — in Docker beside the app, or on the host
itself — with BrollyZapper in plain Docker Compose next to it. umbrelOS operators need none of
it: install from the App Store and the platform supplies every value below.

The supported template is [`deploy/`](deploy/), and this section is the procedure for it.
`regtest/docker-compose.yml` is the integration suite's stack — the two services surrounded by
bitcoind, a test node, a payer, two relays and a setup job — and is not a deployment.

**Steps 1 to 5 are the install**, done once and in order. Steps 6 to 10 are what you will want
afterwards. The headings without a number are background rather than steps, placed where the
decision they inform gets made.

### 1. Before you start

- **Docker with the compose plugin.** `docker compose version` has to answer; the old
  `docker-compose` script will not do.
- **An LND on this host that you control**, synced, with its wallet unlocked. The app runs no
  node of its own and will not create one.
- **A window to restart LND, and to regenerate its TLS certificate**, unless it already answers
  on a Docker-reachable address with a certificate naming it. Step 4 needs both, and any other
  client that holds a copy of `tls.cert` — a mobile wallet, RTL, your own `lncli` — needs the new
  one afterwards. If you cannot do this, stop now rather than at step 4: nothing here works
  without it.
- **A non-root user in the `docker` group**, so `docker compose` needs no `sudo`. The containers
  do not run as root either — that is `RUN_AS_UID`, at step 3.
- **A Linux host.** Docker Desktop on macOS cannot run this template as shipped: its shared
  filesystem refuses the `chmod` the guard puts on its socket, so the guard exits and restarts
  for ever. The regtest stack works around it with a named volume; this template does not,
  because a node worth pairing with is not on a laptop.

Find LND's data directory — `/home/lnd/.lnd` for a systemd install, `~/.lnd` for a user-run node,
or whatever host path sits behind its container's `/root/.lnd` — and note which chain directory
it uses, `mainnet`, `testnet` or `regtest`. Both go into `.env` at step 3.

Two **files** come out of that directory, read-only, and only two: `tls.cert`, and
`data/chain/bitcoin/<network>/admin.macaroon`. Why it is files and not the directory is
immediately below. That block is quoted from the Umbrel package, so the variable names in it
are not this template's — here the two paths come from `LND_DIR` and `LND_NETWORK`. The rule
and the reason are the same wherever the paths come from, which is the point of it.

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

### 2. Get `deploy/`

```bash
git clone https://github.com/davotoula/brollyzapper.git
cd brollyzapper/deploy
```

Only `docker-compose.yml` and `.env.example` matter — fetching those two on their own does just
as well, from `raw.githubusercontent.com/davotoula/brollyzapper/main/deploy/`. `lint_test.go`
beside them is this repository's own test and is no part of a deployment.

**Nothing is built here.** Both `image:` lines name a published image on GHCR pinned by digest,
and `docker compose up` pulls them.

### 3. Fill `.env`

```bash
cp .env.example .env
chmod 600 .env
$EDITOR .env
```

Four values sit above the line in that file, and its own comment on each says more than this
list does:

- **`LND_DIR`** — the directory you found at step 1.
- **`LND_ADDRESS`** — host and port **as the container will dial it**, which is not how you
  reach LND from a shell on the host. Its comment gives the two shapes; step 4 is what a host
  LND needs before either of them answers.
- **`LND_NETWORK`** — the chain directory from step 1, so the macaroon path resolves.
- **`ADMIN_PASSWORD`** — **set one before the first start; the server refuses to start
  without it.** At least **12 characters**. Nothing invents a password for you and nothing
  displays one, so this is the only copy until you sign in — and **editing this value after
  the first start does not change the password**, because the stored hash wins once it exists.
  Change it from **Settings** instead, once you are in.

Two below the line are worth setting now rather than after the first start:

- **`DATA_DIR`** — make it an **absolute** path, outside this checkout. The Sending page prints
  it verbatim as the home of the sending confirmation code, and a relative
  `./data/guard/authorisation.txt` means "wherever you last ran `docker compose`", which is no
  help months later.
- **`TRUSTED_PROXIES`** — leave it commented out unless you are putting a reverse proxy or a
  tunnel in front of the app. If you are, read [§Trusted proxies](#trusted-proxies) below now,
  so you set it once rather than after a restart.

**Then pick the uid, and let the two files decide it.** The containers must be able to *read*
what step 1 named, and LND usually writes those `0600` to its own user. A guard that cannot
read them does not crash — it stays up, answers the admin UI, and logs `could not copy tls.cert
into the credential volume` and `could not bake the receive macaroon yet`, with the node tile
never going ready. Getting the uid right now is cheaper than reading that back later:

```bash
# the same values you just put in .env, so the two commands below can use them.
# Do not `source .env` for this: it is a compose file, not a shell script, and
# ADMIN_PASSWORD is in it.
LND_DIR=/home/lnd/.lnd
LND_NETWORK=mainnet
DATA_DIR=/home/YOU/brollyzapper/data     # absolute, and somewhere you own

ls -l "$LND_DIR/tls.cert" "$LND_DIR/data/chain/bitcoin/$LND_NETWORK/admin.macaroon"
```

This is also the check that both paths exist at all: a missing bind-mount source is not an
error to Docker, it is a root-owned **directory** it creates at that path for you. The guard
refuses to start on that and names the path to remove, but not finding out is quicker.

Whatever `uid:gid` owns those two files is what `RUN_AS_UID`/`RUN_AS_GID` should say —
`RUN_AS_UID`'s comment in `.env.example` has the other way out, a group both can read through.
Read both numbers off `admin.macaroon` — the file the guard actually has to open, and the one
LND writes `0600` — create the directories, and **`chown` only if they do not already have that
owner**. Same shell as the block above, which set `$LND_DIR`, `$LND_NETWORK` and `$DATA_DIR`:

```bash
MAC="$LND_DIR/data/chain/bitcoin/$LND_NETWORK/admin.macaroon"
read -r RUN_AS_UID RUN_AS_GID <<<"$(stat -c '%u %g' "$MAC")"

mkdir -p "$DATA_DIR"/guard "$DATA_DIR"/credentials "$DATA_DIR"/server || \
  sudo mkdir -p "$DATA_DIR"/guard "$DATA_DIR"/credentials "$DATA_DIR"/server

for d in "$DATA_DIR"/guard "$DATA_DIR"/credentials "$DATA_DIR"/server; do
  [ "$(stat -c '%u %g' "$d")" = "$RUN_AS_UID $RUN_AS_GID" ] ||
    sudo chown -R "$RUN_AS_UID:$RUN_AS_GID" "$d"
done

echo "RUN_AS_UID=$RUN_AS_UID"    # put both of these
echo "RUN_AS_GID=$RUN_AS_GID"    # into .env
```

**If those print `0`, stop and pick a different uid.** An LND running as root in Docker owns its
files `0:0`, and this template deliberately does not run the containers as root — see
`RUN_AS_UID` in `.env.example` for the other way out, a group both can read through, which is
the answer whenever the owning uid is one you do not want the app to be.

**The `chown` is conditional because on many hosts it is both unnecessary and impossible.** If
LND's files belong to the uid you are logged in as — the case on umbrelOS, where they are
`1000:1000` and so are you — `mkdir` has already produced the right ownership and there is
nothing to change. And `sudo` may not be reachable at all: where it prompts for a password, a
non-interactive SSH session cannot answer, so an unconditional `sudo` is a step that **stalls**
rather than one that fails. Measured on the September 2026 field trip, where the unconditional
form would have blocked a trip that needed no `chown` at all.

**It tests each of the three directories, and both numbers.** One test on the parent would miss
the case that actually happens: a first `up` that failed leaves Docker's own root-owned
directories underneath a `$DATA_DIR` whose ownership is fine. And a gid-only mismatch is exactly
the state the group route above produces.

`stat -c` is GNU coreutils — this section already assumes a Linux host, which step 1 says.

**If you regenerate `tls.cert` at step 4, check these numbers again**: LND writes the new file
itself, and nothing guarantees the owner is the one you just read.

### 4. The two `lnd.conf` edits a host LND needs

**If LND runs in Docker on this project's network**, you dial it by service name and this step
is nearly free — but the certificate rule still applies to that name, so read the
`tlsextradomain=` bullet below and skip the rest. Everything else here is for an LND on the
host, which answers on neither the right interface nor the right name until `lnd.conf` says so.

**Create the network before you touch `lnd.conf`.** The address you are about to bind LND to is
the bridge's gateway, and the bridge does not exist until compose makes it — bind a listener to
an address the host does not have and LND does not start at all. This makes the network, and
the containers, without starting anything:

```bash
docker compose create
```

Now both edits, then one restart:

```ini
rpclisten=10.61.7.1:10009
tlsextraip=10.61.7.1
```

`10.61.7.1` is the gateway of the template's default `brolly` subnet. Confirm it — and learn
the network's real name, which comes from the directory, so `deploy_brolly` if you followed
step 2 — with:

```bash
docker network inspect deploy_brolly --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}'
```

> **`docker compose down` deletes that bridge**, and while it is gone an LND restart fails: the
> address in `rpclisten` is no longer one the host has. Use `docker compose stop` for routine
> stops, and after a `down` run `docker compose create` again before restarting LND. If you
> would rather not couple LND's startup to Docker at all, `rpclisten=0.0.0.0:10009` is the
> escape — it answers on every interface, which is why it is not the first suggestion.

- **`rpclisten=`** — LND's gRPC listens on `localhost` only by default, so it never answers the
  bridge at all. Name the bridge gateway, which is the address you put in `LND_ADDRESS`.
  `rpclisten=0.0.0.0:10009` answers on every interface and is the blunter option; reach for the
  gateway first.
- **`tlsextraip=` / `tlsextradomain=`** — LND's certificate has to *name* whatever `LND_ADDRESS`
  says: `tlsextraip=` for an address, `tlsextradomain=` for a name. LND fills the certificate in
  with the interfaces that existed **when it generated it**, so a Docker bridge created later
  is not in it however long the node has been running, and the callout above is why you cannot
  count on it being there next time either. The `lnd.conf` line is what makes it certain.

The certificate is only rewritten if it is gone, so delete both halves and restart once:

```bash
sudo rm "$LND_DIR"/tls.cert "$LND_DIR"/tls.key
```

Then restart LND however you run it — `sudo systemctl restart lnd`, or
`docker restart <container>`. **Anything else holding the old certificate needs the new one:**
your own `lncli`, a mobile wallet, a web UI. They will fail verification exactly as the guard
does below until they have it.

**If the stack is already up, restart the guard as well:**

```bash
docker compose restart guard
```

The guard tries to bake at startup and then **once an hour** — there is no fast retry — so a
`lnd.conf` fix made while it is running otherwise looks like it did nothing for up to an hour.

**What each one looks like when it is missing.** Both arrive in `docker compose logs guard`, on
the guard's `could not bake the receive macaroon yet; the server will ask again` line. The logs
are JSON; what follows is the value of that line's `error` field, which is the part worth
reading. Reproduced against this repository's regtest node, with the guard on a Docker bridge
the node's certificate predates:

*The certificate does not name the address* — here the guard dialled `10.61.7.2`, and the
certificate had been generated before that bridge existed:

```
transport: authentication handshake failed: tls: failed to verify certificate:
x509: certificate is valid for 127.0.0.1, ::1, 10.30.0.3, not 10.61.7.2
```

The list is what the certificate *does* name. If the address you chose is not in it, that is
`tlsextraip=`/`tlsextradomain=` missing — or added without deleting `tls.cert` and `tls.key`,
so the old certificate is still on disk.

**From `0.1.21` the guard says this itself, and names the edit.** It checks the certificate
against the address before it dials, so the line you actually get is:

```
lnd: the node's certificate does not name 10.61.7.2; it names localhost, lnd, 127.0.0.1,
10.30.0.3. Add tlsextraip=10.61.7.2 to lnd.conf, delete tls.cert and tls.key so LND
regenerates them, restart LND, then restart the guard
```

The handshake text above is what an earlier image shows — and what any *other* client dialling
the same address will still show you, since the check is this app's and not the node's.

*`rpclisten` is still on loopback* — the same node, dialled this time by a name its certificate
*does* carry, with LND's gRPC bound to `127.0.0.1`:

```
transport: Error while dialing: dial tcp 10.61.7.2:10009: connect: connection refused
```

Refused rather than timed out means the route is fine and nothing is listening on that
interface. A **timeout** instead points at a firewall between the bridge and the host.

**If you cannot restart LND, this is the step 1 prerequisite biting**, and there is nothing to
do but wait for a window — the guard's first act is to dial the node. There is no
skip-verification setting to reach for in the meantime: the app has none, and one would make
the certificate check decorative — which is the check that stops the app handing an admin
macaroon to whatever answered on that address.

### 5. Start, and what "up" looks like

First let compose check what it can. Only `LND_DIR` and `LND_NETWORK` carry the template's
`:?` guard — they are the two with no safe default, and this is what makes an unset one fail
with a sentence rather than mounting the filesystem root:

```bash
docker compose config -q && echo ok
```

`ok` means those two are set and the file parses. It says nothing about `LND_ADDRESS` or
`ADMIN_PASSWORD`, which have no such guard — an empty either passes this, and the container
then refuses to start and says which one. Then:

```bash
docker compose up -d
```

Give it a minute, then look for the three signs rather than watching the stream — the server
reconnects on a widening backoff while it waits for the guard, so a failure loop and a slow
success look alike while they scroll:

```bash
docker compose logs guard server | grep -E 'macaroon baked|"msg":"listening"|"error"'
```

Both containers log **JSON**, one object per line, so match the quoted field names — a `grep`
for `error=` finds nothing here however many errors there are.

Three signs, in the order they arrive:

1. **The guard baked a credential.** From the guard:

   ```json
   {"level":"INFO","msg":"receive macaroon baked","audit":"macaroon.bake",
    "caveats":"time-before 2026-09-16T20:07:42Z, ipaddr 10.61.7.20","permissions":"5"}
   ```

   Do not read `baking the receive macaroon` as this: that line is logged *before* the attempt
   and appears in a failed loop just as it does in a good one. `receive macaroon baked` is the
   one that means it worked, and the `ipaddr` caveat in it is the server's fixed address.

2. **The server is listening.** `{"msg":"listening","addr":"[::]:8080"}` from the server —
   that is the port *inside* the container, always 8080. From the host it is the port you set
   as `HTTP_PORT`:

   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/health   # or your HTTP_PORT
   ```

   `200`. Substitute the port by hand: nothing has put `HTTP_PORT` in this shell, and the
   template's default is 8080.

3. **You can sign in** at `http://<host>:${HTTP_PORT}/` with the password you set at step 3.
   If you left `ADMIN_PASSWORD` empty **on `0.1.21` or later** the server will not have started
   at all, and its log says so in one line naming the variable and the minimum — fix `.env` and
   `docker compose up -d` again. Nothing has been written yet, so there is nothing to undo.
   **On the `0.1.20` images this template still pins it comes up and locks you out instead**,
   and the way back is destructive: see the interim note at step 3.

   Once in, **Settings** offers a password change. It does not on umbrelOS, where the platform
   supplies the password and displays it itself; here it is yours.

**While it settles.** `depends_on` orders **startup**, not readiness, so the server can come up
before the guard has baked anything. While that lasts the server logs

```json
{"level":"WARN","msg":"invoice stream dropped; reconnecting",
 "error":"lnd: node credentials are not present yet","attempt":1,"state":"not_linked"}
```

with a widening gap — a second, then two, four, eight, capped at a minute. They stop of their
own accord once `receive macaroon baked` appears in the guard's log and the stream connects.
The **guard** has no equivalent retry — it bakes at startup and then hourly — so if its log
shows a failure rather than a bake, fix the cause and `docker compose restart guard` rather
than waiting it out.

Then work through **First run** in [`README.md`](README.md#first-run): the public domain and
address name are settings, not deployment values, and they live in the app.

The Security page's self-probe fetches your own lightning address **over the public internet**,
so it stays red until the hostname exists and reaches this container.
[§Putting the address on the internet](#putting-the-address-on-the-internet-cloudflare-tunnel)
above is the procedure, and all of it applies. Two things differ here:

- the tunnel's service points at `<host>:${HTTP_PORT}` — this deployment publishes that port
  directly, with no `app_proxy` in front of it;
- `TRUSTED_PROXIES` becomes your decision rather than the platform's, which is the next
  subsection.

### Trusted proxies

With no `app_proxy` in front, decide deliberately:

- **Nothing in front** — the app is reached directly on `HTTP_PORT`. Leave `TRUSTED_PROXIES`
  empty, which is the template's default. Client addresses are already real.
- **A reverse proxy you run** — set the range the proxy connects *from*, not the range clients
  come from. If the proxy is a container on the template's own network, that is its subnet —
  the value is in `.env.example`, commented out.
- **A CDN or tunnel** — the connecting address is the tunnel daemon's, usually loopback or a
  container address. Name that.

Name the narrowest range that covers the hop you actually control. Anything wider is a range
someone else can arrive from, and the per-sender limits stop meaning anything.

Verify rather than assume: [§Verify before trusting it](#4-verify-before-trusting-it) above has the
procedure, including a negative control.

### 6. Where the confirmation code lives

Sending is gated by a one-time code the guard writes to a file the server has no mount for —
see [`OPERATING.md` §Sending](OPERATING.md#sending-and-the-two-caps). There is no Files app
here, so it is a path on the host:

```
${DATA_DIR}/guard/authorisation.txt
```

The Sending page prints that path for you, from `GUARD_AUTHORISATION_LOCATION` in the compose
file, which is built out of `DATA_DIR` verbatim — which is why step 3 asks for an absolute one.

### 7. Updating

Each GitHub [release](https://github.com/davotoula/brollyzapper/releases) lists the tag and the
two image digests. Edit the two `image:` lines in `docker-compose.yml` to match — both of them,
and the digest as well as the tag — then:

```bash
grep image: docker-compose.yml       # both lines, to check against the release page
docker compose pull && docker compose up -d
```

The settling lines from step 5 reappear for a few seconds, and are as harmless here as on a
first install.

### 8. Backups

Same two directories as everywhere else, and the same exclusion: see
[`OPERATING.md` §Backups](OPERATING.md#backups-and-the-one-directory-left-out). Under this
template they are `${DATA_DIR}/server` and `${DATA_DIR}/guard`, and `${DATA_DIR}/credentials`
is the one left out. There is no umbrelOS here to run the backup for you, so it is a job you
schedule.

### 9. Not supported: LND on another machine

BrollyZapper must sit on the same host as the node. Both credentials the guard bakes carry an
`ipaddr` caveat, and LND checks it against the **source address of the gRPC connection**. Within
one host that address is this container's, which is why the template pins it. Across hosts it is
the Docker host's egress address instead — so the caveat would no longer name this container but
every process on the machine, and a credential stolen from the app would be honoured from
anything else running beside it. Degrading the lock quietly to make the deployment work is not
something this app does.

If you need it, open an issue — nothing is tracked for it yet, because making it safe is a
design change to how credentials are scoped rather than a setting to expose.

### 10. Testing beside an existing Umbrel install

**`lncli` is not on umbrelOS's PATH.** It lives in the Lightning Node app's container, so every
`lncli` in this section is really `docker exec <the lightning app's container> lncli
--network=mainnet …`. Shorten it once and the rest of the section reads as written:

```bash
lncli() { docker exec <the lightning app's container> lncli --network=mainnet "$@"; }
```

**Record the node's root key ids before you start anything.** The put-back below is a diff
against this list, and it cannot be taken afterwards:

```bash
lncli listmacaroonids > ~/macaroonids.before
```

Then stop **only** the BrollyZapper Umbrel app; leave the Lightning Node app running, since it
is the node under test. Choose a fixed address in Umbrel's app network that nothing has
allocated —

```bash
docker network inspect <umbrel's app network> \
  --format '{{range .Containers}}{{.IPv4Address}}{{"\n"}}{{end}}' | sort -t. -k3,3n -k4,4n
```

Pick something well above the highest. **The list is running containers only**, so the
BrollyZapper app you just stopped is not in it and its address will look free — leave a gap
rather than taking the first number that appears unused.

— and join that network from a local override file, which you write yourself and which is not
shipped:

```yaml
# docker-compose.override.yml — local, never committed
services:
  guard:
    environment:
      SERVER_IP: 10.21.21.90
      NETWORK_CIDR: 10.21.0.0/16
    networks:
      brolly: {}
      umbrel: {}
  server:
    networks:
      brolly: {}
      umbrel:
        ipv4_address: 10.21.21.90
networks:
  umbrel:
    external: true
    name: <umbrel's app network>
```

`NETWORK_CIDR` matches umbrelOS's own app network, which is a `/16` — the platform's package
sets `${NETWORK_IP}/16` for the same reason. **It is not read while `SERVER_IP` is set** —
`docker-compose.yml`'s comment on it says why — so getting it right buys nothing here beyond
not contradicting the network you just joined, which is why it is worth thirty seconds and no
more.

`LND_ADDRESS` stays in `.env` as usual — the base template already feeds it to both services —
and it names the Lightning app. The certificate still has to name whatever it says, exactly as
at step 4.

**Both** services join the network, not just the server: the guard is the one that dials the
node, and the server dials it too. Only the server takes a fixed address there, and `SERVER_IP`
must equal it, for the reason at §Not supported above.

**This override leaves the server dual-homed.** The container keeps the template's own `brolly`
network *and* gains Umbrel's, so it has two addresses — and LND sees whichever one the route to
the node came out of, while the `ipaddr` caveat names only the one in `SERVER_IP`. Set
`SERVER_IP` to the address on the network the node is reached over, which here is Umbrel's. A
bake that succeeds followed by every call failing for the address is this, and nothing else
looks like it. Measured on the reference Pi on 12 Sep 2026: with `SERVER_IP` set to the
address on Umbrel's network, the route to the node leaves by that interface and the locked
macaroon minted invoices — the dual-homing is benign once `SERVER_IP` names the right side.

#### Putting it back

In this order, and the first two are the ones that are irreversible if you get them wrong.

**1. Point any repointed hostname back, and confirm it answers.** A Cloudflare tunnel moved from
the app's port to this stack's has to go back *before* the teardown: the moment
`docker compose down` runs, the public address answers 502 from a connector pointing at nothing.

> **Never leave a public lightning address pointing at a stack you are about to destroy.** While
> it does, anything received lands on disposable infrastructure — step 3 below deletes the
> database and with it the receipt-signing key — and clients that fetched the pay document may
> have cached that instance's `nostrPubkey`, so receipts signed by the real install afterwards no
> longer match what they were told to expect. The September 2026 field trip opened exactly this
> window; nothing arrived in it, which is luck rather than design.

**2. Read the root key ids while the guard's own record still exists.** Step 3 deletes it, and
it is the only list that names *this* guard's keys rather than every key the node holds:

```bash
DATA_DIR=<the same absolute path you put in .env>    # this is a fresh shell
grep -oE '"(receive|spend)_root_key_id":[0-9]+|"pending_root_key_ids":\[[^]]*\]' \
  "$DATA_DIR/guard/guard-state.json"
```

`grep` rather than `cat`: the same file holds any outstanding sending authorisation **and its
one-time code**, and there is no reason to put that in your scrollback.

**3. Stop the stack and delete its data.** The directories are bind mounts, so `down -v` alone
does not reach them — and `$DATA_DIR` must be set, from the line above, or the `rm` below is
pointed at the filesystem root:

```bash
: "${DATA_DIR:?set DATA_DIR before running this}"
docker compose down
rm -rf "$DATA_DIR"/guard "$DATA_DIR"/credentials "$DATA_DIR"/server
```

**4. Revoke the root keys this guard minted at the node.** The Umbrel app's guard cannot see
them — a guard only ever revokes keys it recorded itself — so anything left behind stays live
and revocable by nobody:

```bash
diff ~/macaroonids.before <(lncli listmacaroonids)
lncli deletemacaroonid <id>    # every id that appeared in between
```

Use step 2's ids where you have them — they name *this* guard's keys and nothing else. The
`diff` is the fallback if you skipped step 2: it still works after the teardown, because it asks
the node rather than the deleted file, but it also lists anything else that baked in the window,
so read it rather than piping it.

**5. Start the BrollyZapper app again.**
