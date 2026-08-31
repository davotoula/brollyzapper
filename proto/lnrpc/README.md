# Vendored LND protocol definitions

`lightning.proto` and `routerrpc/router.proto` are copied verbatim from
[`lightningnetwork/lnd`](https://github.com/lightningnetwork/lnd) at tag
**v0.21.2-beta** (`lnrpc/lightning.proto` and `lnrpc/routerrpc/router.proto`),
under lnd's MIT licence — a copy of which is `LICENSE.lnd` in this directory.

Nothing here is hand-edited. To move to a newer LND, replace the file from that
tag and re-run `make proto` (the `lnd` module drags in cgo, which `CGO_ENABLED=0` forbids — the reason the
protos are vendored rather than the `lnd` Go module imported).

## Why the buf module is rooted here and not at `proto/`

`router.proto` says `import "lightning.proto"` — a bare path, because lnd
generates it with `lnrpc/` on the include path. That resolves only if
`lightning.proto` is at the buf module root, which is why `buf.yaml` names
`proto/lnrpc` rather than `proto`. The alternative was to edit that one import
line, and the sentence above — nothing here is hand-edited — is worth more than
the churn avoided: an edited vendored file is a thing the next LND upgrade has
to remember, and forgetting is silent.

Two consequences, both checked when `router.proto` arrived (`d24.2`, 24 Aug
2026):

- The descriptor paths the generated code registers became `lightning.proto`
  and `routerrpc/router.proto`, from `lnrpc/lightning.proto`. That is what
  **upstream lnd itself registers**, so this moved toward it, not away.
- **The wire is unaffected.** Service and method names come from the protos'
  `package` declarations: `/lnrpc.Lightning/GetInfo` and
  `/routerrpc.Router/SendPaymentV2` are unchanged, which matters because those
  exact strings are the URI-scoped macaroon permissions in spec §6.

`buf.gen.yaml`'s `out:` is `internal/lnd/lnrpc` for the same reason, so the
generated files stay where they have always been; `routerrpc` lands beside them
and the gate's `internal/lnd/lnrpc/` gofmt exclusion still covers it.
