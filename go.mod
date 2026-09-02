module github.com/davotoula/brollyzapper

go 1.25.0

// The floor for the BUILD toolchain, separate from the language version above.
//
// Without it, `go` used whatever was installed — which locally was 1.25.0, so
// the binaries the gate tested carried every standard-library vulnerability
// fixed since then while the binaries that SHIPPED were built by
// golang:1.26-alpine and did not. govulncheck reported 32 of them the first
// time it ran, all in crypto/tls, crypto/x509, net/http and html/template, and
// all reachable (review L12). This is the floor, not a pin: a newer toolchain
// in the image is used as-is.
toolchain go1.26.7

require (
	github.com/coder/websocket v1.8.15
	github.com/nbd-wtf/go-nostr v0.52.3
	golang.org/x/crypto v0.55.0
	golang.org/x/mod v0.40.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
	gopkg.in/macaroon.v2 v2.1.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.57.0
	rsc.io/qr v0.2.0
)

require (
	github.com/ImVexed/fasturl v0.0.0-20230304231329-4e41488060f3 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.4 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.5 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/bytedance/sonic v1.13.1 // indirect
	github.com/bytedance/sonic/loader v0.2.4 // indirect
	github.com/cloudwego/base64x v0.1.5 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/puzpuzpuz/xsync/v3 v3.5.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	golang.org/x/arch v0.15.0 // indirect
	golang.org/x/exp v0.0.0-20250305212735-054e65f0b394 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	modernc.org/libc v1.74.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

// The project's ONLY replace: a fork of go-nostr carrying three commits, each a
// separate concern and each reviewable alone.
//
//  1. Relay.close() cancelled the connection context and then read a field the
//     writer goroutine nils on that same cancellation — a nil-pointer
//     dereference inside the library, and there is no recover() anywhere in this
//     tree. The fix reads the field into a local BEFORE cancelling (bym).
//  2. The three residual races on the same two fields: Subscribe reading
//     Connection while the writer nils it, close()'s read when the cancellation
//     came from a parent context, and ConnectionError written unsynchronised.
//     All reproduced under -race, then fixed with closeMutex (o34.19).
//  3. WithDialAddressCheck, a dial-time hook that hands the caller the relay's
//     URL and the address actually resolved for it, and lets it refuse. It
//     closes the TOCTOU in this app's SSRF filter: internal/nostr resolved and
//     checked, and the library then resolved again. The URL is what lets the
//     caller exempt its own configured relays, which may legitimately be on a
//     private network (vz1.4).
//
// Pinned by full commit hash, never a branch or a tag: either can be moved by
// whoever owns the fork. internal/arch asserts the target, the exact pin, and
// that the fork's own go.mod still hashes to upstream's — so it cannot have
// gained a dependency.
//
// This is NOT a carry awaiting a merge. Upstream is archived and read-only; the
// exit is the migration to fiatjaf.com/nostr, which re-evaluates the hook
// against that library's dial API.
//
// Dependabot cannot maintain this line and is not expected to (0vk.25). A
// replace target is outside the module graph it resolves, and this target is a
// commit hash on a fork of an archive — there is no newer version to find. If a
// gomod PR ever proposes a go-nostr bump, it is proposing the UPSTREAM version
// that this directive then overrides: harmless, and not the upgrade it looks
// like. Moving the fork is a manual pin change; leaving the fork is o34.18.
//
//	full reasoning: the design's §1, "go-nostr is now a
//	                pinned fork, and upstream is gone"
//	beads:          BrollyZap-bym, o34.19, vz1.4; o34.18 is the exit
//	fork:           github.com/davotoula/go-nostr @ b11ed54488455ac0b611e404dd3608edde20add8
replace github.com/nbd-wtf/go-nostr => github.com/davotoula/go-nostr v0.52.4-0.20260824010951-b11ed5448845
