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
`regtest/docker-compose.yml` is the integration suite's stack — the two services surrounded by a
test node, a payer and two relays — and is not a deployment.

### 1. Before you start

- **Docker with the compose plugin.** `docker compose version` has to answer; the old
  `docker-compose` script will not do.
- **An LND on this host that you control**, synced, with its wallet unlocked. The app runs no
  node of its own and will not create one.
- **A non-root user in the `docker` group**, so `docker compose` needs no `sudo`. The containers
  do not run as root either — that is `RUN_AS_UID`, at step 3.

Find LND's data directory: `/home/lnd/.lnd` for a systemd install, `~/.lnd` for a user-run node,
or whatever host path sits behind its container's `/root/.lnd`. Exactly two **files** are mounted
out of it, both read-only:

| | |
|---|---|
| `tls.cert` | the certificate the app verifies the node's gRPC against |
| `data/chain/bitcoin/<network>/admin.macaroon` | the credential the **guard** holds, and nothing else does |

Note which `<network>` — `mainnet`, `testnet` or `regtest` — you need it at step 3. Before you
adapt either path, read the hazard immediately below.

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

Two files are needed — `docker-compose.yml` and `.env.example`. `lint_test.go` beside them is
this repository's own test and is no part of a deployment.

```bash
git clone https://github.com/davotoula/brollyzapper.git
cd brollyzapper/deploy
```

Downloading the two files on their own does just as well. **Nothing is built here.** Both
`image:` lines name a published image on GHCR pinned by digest, and `docker compose up` pulls
them.

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
- **`LND_NETWORK`** — the `<network>` from step 1, so the macaroon path resolves.
- **`ADMIN_PASSWORD`** — **set one here, before the first start.** Left empty, the server
  invents a password on its first run and shows it on `/setup` — which is behind the login, so
  off Umbrel there is no way to read it and no way in. On umbrelOS the platform supplies the
  password and displays it itself, which is why leaving it empty is right there and wrong here.
  Two consequences worth knowing before you choose the value: a later start does **not**
  re-seed, so filling this in afterwards will not rescue an install that was first started
  empty; and because the app reads "a password was supplied" as "the platform manages it",
  **Settings will not offer a password change** — this file stays the password's only home, so
  keep it `0600` and change the password by editing it here and restarting.

Then create the data directories and give them to the uid the containers will run as:

```bash
mkdir -p data/guard data/credentials data/server
sudo chown -R 1000:1000 data
```

**1000 is the default, not a fact about your host.** What decides it is whether that uid can
*read* the two files from step 1: LND usually writes them `0600` to its own user, and a guard
that cannot read them dies at first start. `RUN_AS_UID`'s comment in `.env.example` has the `ls`
that shows the ownership and the two ways out — and whichever you take, the `chown` above uses
the same uid, because it is one decision rather than two.

Set `DATA_DIR` to an **absolute** path while you are in the file; step 6 says what that buys.

### 4. The two `lnd.conf` edits a host LND needs

An LND running on the host rather than in this compose project answers on neither the right
interface nor the right name until `lnd.conf` says so. Both edits together, then one restart:

```ini
rpclisten=10.61.7.1:10009
tlsextraip=10.61.7.1
```

- **`rpclisten=`** — LND's gRPC listens on `localhost` only by default, so it never answers the
  bridge at all. Name the bridge gateway, which is the address you put in `LND_ADDRESS`.
  `rpclisten=0.0.0.0:10009` answers on every interface and is the blunter option; reach for the
  gateway first.
- **`tlsextraip=` / `tlsextradomain=`** — LND's certificate has to *name* whatever `LND_ADDRESS`
  says: `tlsextraip=` for an address, `tlsextradomain=` for a name. LND fills the certificate in
  with the interfaces that existed **when it generated it**, so a Docker bridge created later is
  not in it however long the node has been running — and since `docker compose down` takes the
  bridge away again, whether the address happens to be there is a matter of what order things
  last restarted in. The `lnd.conf` line is what makes it certain.

The certificate is only rewritten if it is gone, so delete both halves and restart once:

```bash
sudo rm /home/lnd/.lnd/tls.cert /home/lnd/.lnd/tls.key
sudo systemctl restart lnd
```

**What each one looks like when it is missing.** Both arrive in `docker compose logs guard`, on
the guard's `could not bake the receive macaroon yet; the server will ask again` line, in its
`error` field. Reproduced against this repository's regtest node, with the guard on a Docker
bridge the node's certificate predates:

*The certificate does not name the address* — here the guard dialled `10.61.7.2`, and the
certificate had been generated before that bridge existed:

```
transport: authentication handshake failed: tls: failed to verify certificate:
x509: certificate is valid for 127.0.0.1, ::1, 10.30.0.3, not 10.61.7.2
```

The list is what the certificate *does* name. If the address you chose is not in it, that is
`tlsextraip=`/`tlsextradomain=` missing — or added without deleting `tls.cert` and `tls.key`,
so the old certificate is still on disk.

*`rpclisten` is still on loopback* — the same node, dialled this time by a name its certificate
*does* carry, with LND's gRPC bound to `127.0.0.1`:

```
transport: Error while dialing: dial tcp 10.61.7.2:10009: connect: connection refused
```

Refused rather than timed out means the route is fine and nothing is listening on that
interface. A **timeout** instead points at a firewall between the bridge and the host.

**If you cannot restart LND right now, stop here.** Nothing further in this procedure works
until you can, because the guard's first act is to dial the node. There is no
skip-verification setting to reach for in the meantime: the app has none, and one would make
the certificate check decorative — which is the check that stops the app handing an admin
macaroon to whatever answered on that address.

### 5. Start, and what "up" looks like

```bash
docker compose up -d
docker compose logs -f guard server
```

Three signs, in the order they arrive:

1. **The guard baked a credential.** From the guard:

   ```
   receive macaroon baked  audit=macaroon.bake
     caveats="time-before 2026-09-16T20:07:42Z, ipaddr 10.61.7.20"  permissions=5
   ```

   Do not read `baking the receive macaroon` as this: that line is logged *before* the attempt
   and appears in a failed loop just as it does in a good one. `receive macaroon baked` is the
   one that means it worked, and the `ipaddr` caveat in it is the server's fixed address.

2. **The server is listening.** `listening addr=[::]:8080` from the server, and from the host:

   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/health
   ```

   `200`, on whatever `HTTP_PORT` you set.

3. **You can sign in** at `http://<host>:8080/` with the password you set at step 3. If you
   left `ADMIN_PASSWORD` empty, this is where you find out: the login form appears, and the
   password that would open it is on a page behind it. The way out is to stop the stack, set
   `ADMIN_PASSWORD`, delete `${DATA_DIR}/server` and start again — which discards the nostr
   identity the first start generated, so do it now rather than after the address is published.

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
  `.env.example` carries the value, commented out, because uncommenting it is a decision and
  not a restore.
- **A CDN or tunnel** — the connecting address is the tunnel daemon's, usually loopback or a
  container address. Name that.

Name the narrowest range that covers the hop you actually control. Anything wider is a range
someone else can arrive from, and the per-sender limits stop meaning anything.

Verify rather than assume: [§Verify before trusting it](#4-verify-before-trusting-it) above has the
procedure, including a negative control.

### 6. Where the confirmation code lives

Enabling sending needs a one-time code the guard writes where only the host's operator can read
it. There is no Files app here, so it is a path on the host:

```
${DATA_DIR}/guard/authorisation.txt
```

The Sending page prints that path for you, from `GUARD_AUTHORISATION_LOCATION` in the compose
file — which is built out of `DATA_DIR` verbatim. Leave `DATA_DIR` at its `./data` default and
the page says `./data/guard/authorisation.txt`, which is relative to wherever you ran
`docker compose` from and is not much help months later. An absolute `DATA_DIR`, as step 3
suggests, makes that sentence something you can paste into a shell.

### 7. Updating

Each GitHub [release](https://github.com/davotoula/brollyzapper/releases) lists the tag and the
two image digests. Edit the two `image:` lines in `docker-compose.yml` to match — both of them,
and the digest as well as the tag — then:

```bash
docker compose pull && docker compose up -d
```

`depends_on` in the template orders **startup**, not readiness: the server may come up before
the guard has baked anything. That is normal, it clears itself, and while it lasts the server
logs

```
invoice stream dropped; reconnecting  error="lnd: node credentials are not present yet"
  attempt=1  state=not_linked
```

with a widening gap — a second, then two, four, eight, capped at a minute. They stop of their
own accord once `receive macaroon baked` appears in the guard's log and the stream connects.
The same lines on a *first* install are the same thing and equally harmless.

### 8. Backups

Same two directories as everywhere else, and the same exclusion: see
[`OPERATING.md` §Backups](OPERATING.md#backups-and-the-one-directory-left-out). Under this
template they are `${DATA_DIR}/server` and `${DATA_DIR}/guard`, and `${DATA_DIR}/credentials`
is the one left out. There is no umbrelOS here to run the backup for you, so it is a job you
schedule — and the database in `${DATA_DIR}/server` holds the only copy of the zap-receipt
signing key.

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

A footnote for one case: trying this template on a box that already runs the app under umbrelOS.

Stop **only** the BrollyZapper Umbrel app; leave the Lightning Node app running, since it is
the node under test. Then join Umbrel's app network from a local override file — write it
yourself, it is not shipped — and take a fixed address in that network that nothing has
allocated:

```yaml
# docker-compose.override.yml — local, never committed
services:
  guard:
    environment:
      SERVER_IP: 10.21.21.90
      NETWORK_CIDR: 10.21.21.0/24
      LND_ADDRESS: <the lightning app's address>:10009
    networks:
      brolly: {}
      umbrel: {}
  server:
    environment:
      LND_ADDRESS: <the lightning app's address>:10009
    networks:
      brolly: {}
      umbrel:
        ipv4_address: 10.21.21.90
networks:
  umbrel:
    external: true
    name: <umbrel's app network>
```

**Both** services join that network, not just the server: the guard is the one that dials the
node, and the server dials it too. Only the server takes a fixed address there, and `SERVER_IP`
must equal it — the guard bakes the first into the `ipaddr` caveat and LND checks the source
address it actually sees, which on a container with two networks is the one it routed out of.
The certificate still has to name whatever `LND_ADDRESS` says, exactly as at step 4.

**The put-back matters more than the test.** Stop the stack and remove its volumes, then
**revoke the root keys this guard minted at the node** — the Umbrel app's guard cannot see them,
because a guard only ever revokes keys it recorded itself, so anything left behind stays live
and revocable by nobody:

```bash
lncli listmacaroonids          # before you start, and again afterwards
lncli deletemacaroonid <id>    # every id that appeared in between
```

Then start the BrollyZapper app again.
