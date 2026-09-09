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

Verify rather than assume: [§Verify before trusting it](#4-verify-before-trusting-it) above has the
procedure, including a negative control.
