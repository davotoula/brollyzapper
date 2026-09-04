# BrollyZapper

[![CI](https://github.com/davotoula/brollyzapper/actions/workflows/ci.yml/badge.svg)](https://github.com/davotoula/brollyzapper/actions/workflows/ci.yml)

Nostr zap receiving (NIP-57) and Nostr Wallet Connect (NIP-47) for an **existing**
LND node, packaged as an Umbrel app. Safety over features.

## Install on umbrelOS

Until the [official App Store listing](https://github.com/getumbrel/umbrel-apps/pull/6049) is
merged, install from the community store:

1. In the umbrelOS **App Store**, click the three dots (top right) → **Community App Stores**.
2. Paste `https://github.com/davotoula/brollyzapper-umbrel-store` and click **Add**.
3. Open the new store and install **BrollyZapper**.
4. Open the app from your dashboard and set your domain, address name and relays on the
   Settings page.

You need the **Lightning Node** app installed and synced — BrollyZapper reads that node's
certificate and admin macaroon through Umbrel's own app exports and runs no node of its own —
and a domain that reaches your box over HTTPS for the Lightning address. A fresh install is
**receive-only**: sending stays off until you complete the authorisation step the app walks you
through, which bakes a second, separately revocable credential with a spending ceiling you
choose. Updates arrive through the store like any other app; the same app id is what the
official listing will carry, so your data and settings are the same app.

The architecture — the guard/server split and the rules it enforces — is described where it is enforced: [`internal/arch/arch_test.go`](internal/arch/arch_test.go) holds the structural rules as tests, and each package's doc comment says what it may and may not touch. (Read the file rather than reaching for `go doc`: `internal/arch` is test-only, so it has no buildable package for `go doc` to open.)

## Layout

Two static binaries, two containers:

- `cmd/brollyzapper` — the server. All the attack surface: HTTP, nostr relays, sqlite.
- `cmd/brollyguard` — the guard. Credential broker; no listeners, and the sole
  holder of `admin.macaroon`.

`internal/` follows the package layout; `internal/arch` asserts that it still does.

## Build and test

Requires Go **1.25+** (set by `google.golang.org/grpc`; Go's toolchain switching
will fetch it automatically on an older install).

The same gate runs in CI on every push and pull request — `.github/workflows/ci.yml`
mirrors it exactly, and names any difference in a comment. (The badge above renders once
the repository is public.)

```bash
make check     # go build ./... && go vet ./... && go test ./...
make cross     # both binaries, linux/amd64 + linux/arm64, CGO_ENABLED=0
make docker    # multi-arch distroless images (needs a docker daemon + buildx)
```

## Regenerating the LND stubs

`internal/lnd/lnrpc` is generated from the vendored protos in `proto/` and is
committed. The `lnd` Go module itself is deliberately not imported: it drags in cgo,
and `CGO_ENABLED=0` is what keeps cross-compilation free and `distroless/static`
viable — the same reason the sqlite driver is pure Go.

```bash
make proto     # installs pinned buf/protoc-gen-go/protoc-gen-go-grpc, regenerates
```

## Receiving zaps

BrollyZapper serves its own lightning address. Nothing external is required —
no Alby, no LNURL host, no static file to keep in sync.

### What you need

- An LND node BrollyZapper can reach. On Umbrel that is the Lightning app; the
  package wires it up for you.
- A public hostname, if you want a lightning address. Nostr Wallet Connect works
  without one.

### Settings

Open the app and go to **Settings**. These are the five you touch at setup;
[`MANUAL.html`](MANUAL.html) is every setting on one collapsible page;
[`OPERATING.md`](OPERATING.md) is the full
reference — every setting, what each default is and why, and what going wrong
looks like.

| Field | What it is |
|---|---|
| **Public domain** | The host your lightning address lives on. Enter it bare — `zap.example.com`. A pasted `https://` is stripped and the scheme remembered separately. |
| **Address name** | The part before the `@`. `test` gives `test@zap.example.com`. |
| **Relays** | Where receipts are published, one per line. Empty means the built-in default set. Receipts also go to whatever relays each zap request names. |
| **Incoming payments raise the ceiling** | Leave on to have received sats increase the spending authorisation. |
| **Public rate limit** | The global ceiling on anonymous traffic to your address. It governs the public callback only; see *Rate limiting* below before changing it. |

Everything else — trusted proxies, the fee reserve, log level, the nostr identity,
the sending latch and its two caps — is in the
[operator reference](OPERATING.md), along with backups, macaroon
rotation, and what running this outside Umbrel needs.

Save. The app immediately probes its own address over the public internet and
the **Security** page reports the result:

> Your lightning address reaches this instance — **pass**

That check fetches `https://<domain>/.well-known/lnurlp/<name>` and verifies the
response carries this instance's own nostr pubkey **and** a per-boot header only
it emits. It is deliberately not a DNS check: behind a tunnel or a CDN the name
resolves to someone else's anycast, so resolution proves nothing about whether
*your* app is what answers. A domain that points at some other LNURL server
resolves, responds, and is silently broken — that is the failure this catches.

If it fails, the page shows the reason verbatim. Fix that before going further:
an address that does not reach you cannot receive.

The domain is stored as a bare host and the scheme beside it, so Settings shows
which one wallets will be handed — `https://zap.example.com`, under the field.
Paste a scheme to change it; changing the host on its own returns to `https`.

### What is exposed

Exactly three paths are public (each also answers CORS preflight). Everything else — the whole admin UI — sits
behind authentication, and unknown paths are private by default rather than
public by accident.

| Route | Purpose |
|---|---|
| `GET /.well-known/lnurlp/{name}` | The LUD-16 pay document. Static, cacheable, unlimited. |
| `GET /lnurlp/{name}/callback` | Mints an invoice. Takes `amount` (msat), optional `nostr` (a signed kind-9734) and optional `comment`. Never cached. |
| `/health` | `200 ok` or `503`. Nothing else — no version, no balance, no node state. |

### Checking it by hand

```bash
curl -s https://zap.example.com/.well-known/lnurlp/test | jq -r '.callback, .metadata, .nostrPubkey'
```

Expect a callback on your own domain, an identifier of `test@zap.example.com`,
and a 64-character hex pubkey. A name that is not configured returns a plain 404.

---

## Publishing it: Cloudflare Tunnel

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

## Licence

MIT — see [LICENSE](LICENSE).

Every input is permissive, so nothing forced the choice: lnd's vendored protos are MIT,
gRPC and protobuf are Apache-2.0, `x/crypto` and `modernc.org/sqlite` are BSD-3. MIT
matches the ecosystem this ships into — Bitcoin Core, lnd, BTCPay and LNbits are all MIT.

AGPL was considered and rejected: it defends against someone running a modified version
as a hosted service, and BrollyZapper is single-operator software bound to the operator's
own LND node, so there is no hosted business to defend against.

`proto/lnrpc/LICENSE.lnd` stays where it is. Vendored MIT code keeps its own notice
regardless of what this project chooses.
