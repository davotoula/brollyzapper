# AGENTS.md — orientation for AI coding agents

BrollyZapper adds Nostr zap receiving (NIP-57) and Nostr Wallet Connect (NIP-47) to an
**existing** LND node. Safety over features. Read `README.md` for what it is,
`OPERATING.md` for what every setting does, and this file for how to work on it.

## The one design fact that explains everything else

Two containers: **server** (all attack surface — HTTP, relays, sqlite) and **guard**
(credential broker, no listeners, sole holder of `admin.macaroon`, reachable only over a
unix socket with a small fixed API). A compromise of the server must never become a
compromise of the node. Most rules below are this fact restated.

## The gate — run all of it, not just the package you touched

```sh
go build ./... && go vet ./... && go test ./... && go test -race ./...
make cross          # both binaries, linux/amd64 + linux/arm64
gofmt -l . | grep -v '^internal/lnd/lnrpc/'   # generated code is not ours to format
go mod tidy -diff
make vuln           # govulncheck, pinned in the Makefile
make fuzz           # re-exercises the fuzz corpus, ~10s
make public-scan    # see "Privacy" below
```

`-race` is not optional: it has caught bugs in code whose own tests were green.
`.github/workflows/ci.yml` mirrors this exactly; if you add a check locally, add it there.

## Non-negotiables

- **All amounts are msat, stored as INTEGER.** Never floats for money.
- **`CGO_ENABLED=0` is a standing constraint**, not a build flag: it is what makes
  cross-compilation free and `distroless/static` viable. The sqlite driver is pure Go for
  this reason; a dependency needing cgo breaks the build on purpose.
- **Only the guard mints credentials, and only URI-scoped** — never `entity:action`.
- **Only `wallet.Spender` touches the balance**; `balance_entries` is append-only.
- **`log/slog` only.** Every secret-bearing type implements `slog.LogValuer`. Never log
  macaroons, nostr private keys, pairing secrets, preimages, or connection URIs.
- **Audit events go through the `Auditor`** — the log line and the durable row together.
  Hand-building an `audit=` attribute elsewhere is an architecture violation.
- **Consumers declare the interfaces they need.** Do not export a concrete type to make a
  caller's life easier; unexported types are how one capability cannot hand you another.

## How rules are enforced, and how to add one

`internal/arch/arch_test.go` turns the architecture into build failures: layer rules,
balance access, redaction, the guard's isolation, single-call-site pins. When you add a
structural rule, **verify it by planting a violation** — write the forbidden thing, watch
the test fail with the right message, remove it. A rule that has only ever passed has been
written, not tested.

Two testing habits this codebase relies on:

- **Test the seam, not just the two sides.** Two well-tested components with an untested
  wire between them is invisible to per-package coverage, and it has bitten this project.
- **Assert the behaviour, not the artifact.** A database index that exists but is never
  used still passes an existence check; assert `EXPLAIN QUERY PLAN` instead.

Write the failing test first. Comments carry the *why*, often at length — match that
register, and when you change behaviour, update the comment that justified the old one.

## Privacy — this tree may hold private material outside git

The working tree may contain ignored, never-committed paths — internal documents, the
issue tracker's directory, private agent instructions, `.env` files; `.gitignore` names
them. Do not commit them, do not weaken `.gitignore`, and do
not quote their contents into tracked files. `scripts/public-scan.sh` (in the CI gate as
`make public-scan`) inspects what git *tracks* and fails on private paths, compiled
binaries and generic private shapes; on machines whose working trees hold private
material it also loads a local, never-committed pattern list — the specific patterns
cannot live in the public script, because a published blocklist is a published list of
secrets. **Never use a real person's key, address, or identity as a test vector**;
derive fixtures from the well-known synthetic keys already in the tests.

## Running it

`regtest/` is a complete local stack — the app, a test LND pair, a nostr relay — and
`regtest/README.md` drives it. Integration claims get verified there, from a wiped stack,
not reasoned about. The Umbrel packaging lives in `umbrel/`; the app itself takes generic
`LND_ADDRESS`/cert/macaroon settings and runs against any LND.
