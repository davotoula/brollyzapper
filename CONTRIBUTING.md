# Contributing to BrollyZapper

For anyone building it or sending a change. Operators want [`README.md`](README.md),
[`DEPLOYING.md`](DEPLOYING.md) and [`OPERATING.md`](OPERATING.md) instead.

## Layout

Two static binaries, two containers:

- `cmd/brollyzapper` — the server. All the attack surface: HTTP, nostr relays, sqlite.
- `cmd/brollyguard` — the guard. Credential broker; no listeners, and the sole
  holder of `admin.macaroon`.

`internal/` follows the package layout; `internal/arch` asserts that it still does.

The architecture — the guard/server split and the rules it enforces — is described where it is
enforced: [`internal/arch/arch_test.go`](internal/arch/arch_test.go) holds the structural rules
as tests, and each package's doc comment says what it may and may not touch. Read the file rather
than reaching for `go doc`: `internal/arch` is test-only, so it has no buildable package for
`go doc` to open. A rule there is verified by planting a violation and watching it go red; a
change that makes one pass by loosening it is the change to argue about.

## Build and test

Requires Go **1.27** (`go.mod` pins the floor; Go's toolchain switching fetches it on an older
install). `CGO_ENABLED=0` is a standing constraint, not a flag: it is what makes cross-compilation
free and `distroless/static` viable, and it is why the sqlite driver is pure Go and the `lnd` Go
module is not imported.

The gate, in full — the same one `.github/workflows/ci.yml` runs on every push and pull request:

```bash
go build ./... && go vet ./... && go test ./... && go test -race ./...
make cross              # both binaries, linux/amd64 + linux/arm64
gofmt -l . | grep -v '^internal/lnd/lnrpc/'   # generated code is not ours to format
go mod tidy -diff
make vuln               # govulncheck, pinned in the Makefile
make fuzz               # re-exercises the corpus, ten seconds
make toolchain-floor    # go.mod's floor against the Go the pinned base images ship
```

`make check` is build, vet and test only — enough while iterating, not the gate. `-race` and
`make vuln` are not optional: each has caught a defect the rest of the gate passed.

`make docker` builds the multi-arch distroless images locally (needs a daemon and buildx);
release images are built by `publish.yml` in CI, never from a laptop.

## Regenerating the LND stubs

`internal/lnd/lnrpc` is generated from the vendored protos in `proto/` and is
committed. The `lnd` Go module itself is deliberately not imported: it drags in cgo,
and `CGO_ENABLED=0` is what keeps cross-compilation free and `distroless/static`
viable — the same reason the sqlite driver is pure Go.

```bash
make proto     # installs pinned buf/protoc-gen-go/protoc-gen-go-grpc, regenerates
```

## How a change lands

`main` is protected: no force-push, no delete, and a commit reaches it only with the gate and
both image checks green on that exact commit. So a change is a branch, a pull request, and a
merge once CI is green. Release tags `v*` cannot be deleted or moved. The integration tests
(an LND regtest node and a nostr relay in Docker Compose) live under `regtest/`, with their own
README.

## Licence

MIT. Every input is permissive, so nothing forced the choice: lnd's vendored protos are MIT,
gRPC and protobuf are Apache-2.0, `x/crypto` and `modernc.org/sqlite` are BSD-3. MIT
matches the ecosystem this ships into — Bitcoin Core, lnd, BTCPay and LNbits are all MIT.

AGPL was considered and rejected: it defends against someone running a modified version
as a hosted service, and BrollyZapper is single-operator software bound to the operator's
own LND node, so there is no hosted business to defend against.

`proto/lnrpc/LICENSE.lnd` stays where it is. Vendored MIT code keeps its own notice
regardless of what this project chooses.
