#!/usr/bin/env bash
# d24.1 — the guard mints the right to spend, and takes it back.
#
# The unit tests prove the guard does what it says against a fake node. This
# proves the node AGREES: that the URI-scoped permissions really do let
# routerrpc through and really do not let the receive macaroon through, and —
# the assertion this whole script exists for — that after RevokeSpend a copy of
# the spend macaroon taken BEFORE the revocation is refused by LND.
#
# That last one is the release criterion of the P3 epic ("Disable sending makes
# LND reject the old macaroon"). It is a node-side revocation, not a local
# delete, and the only way to know is to keep a copy and present it.
#
# Everything goes through the GUARD's socket, never lncli: baking with lncli
# would prove something about lncli.
#
# Bakes macaroons and revokes root keys. Regtest only, never a real node.
set -euo pipefail
cd "$(dirname "$0")"

# BY NAME, not by address. Compose assigns addresses in start order and nothing
# in this stack pins LND's, so the literal 10.30.0.5 this used to carry pointed
# at the PAYER node after a `down -v` reshuffled them — a script that talks to
# the wrong node and reports the wrong verdict. The certificate carries
# `--tlsextradomain=lnd`, which is exactly what makes the name usable.
LND_RPC="${LND_RPC:-lnd:10009}"
LND_IMAGE="${LND_IMAGE:-lightninglabs/lnd:v0.21.1-beta}"
TOOL_IMAGE="${TOOL_IMAGE:-alpine:3.20}"
CRED_VOLUME="${CRED_VOLUME:-brollyregtest_credentials}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m   %s\n' "$*"; }
note() { printf '   \033[90m..\033[0m   %s\n' "$*"; }
die()  { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

lncli_recv() { docker compose exec -T lnd lncli --network=regtest "$@"; }
root_ids()   { lncli_recv listmacaroonids | jq -r '.root_key_ids|sort|join(",")'; }
root_count() { lncli_recv listmacaroonids | jq -r '.root_key_ids|length'; }

# svc_value <service> <key> — one key from one compose service, scoped to the
# service rather than "the first match in the file".
svc_value() {
  awk -v svc="  $1:" -v key="$2:" '
    $0 == svc { in_svc = 1; next }
    /^  [a-z]/ { in_svc = 0 }
    in_svc && $1 == key { print $2; exit }' docker-compose.yml
}

# guardctl <command> — the guard's socket, through the SERVER's own client.
#
# Inside a container because the socket lives in the credential volume, which is
# a named volume precisely so the guard can chmod it (see docker-compose.yml).
guardctl() {
  docker run --rm -v "$CRED_VOLUME:/credentials" -v "$WORK/guardctl:/guardctl:ro" \
    "$TOOL_IMAGE" /guardctl "$@"
}

# GUARD_DATA_VOLUME is the guard's OWN volume — the one the server has no mount
# for. It is mounted into guardctl only for `read-code`, which is the OPERATOR's
# step of `06v`'s ceremony; everything else goes through the socket, as the
# server does.
GUARD_DATA_VOLUME="${GUARD_DATA_VOLUME:-brollyregtest_guard-data}"

# guardctl_op <command> — guardctl with the operator's reach as well as the
# server's. Separate from guardctl() on purpose: the split IS the security
# property, and a single helper that always mounted the guard's volume would
# make every call in these scripts look like something the server can do.
guardctl_op() {
  docker run --rm -v "$CRED_VOLUME:/credentials" -v "$GUARD_DATA_VOLUME:/guard:ro" \
    -v "$WORK/guardctl:/guardctl:ro" "$TOOL_IMAGE" /guardctl "$@"
}

# permit_sending — the operator's ceremony (`06v`), through guardctl.
#
# One command rather than four steps here: this script's subject is something
# else, and three scripts each carrying their own copy of a protocol sequence had
# already drifted in the wording. The failure mode of a stale copy is a script
# that keeps passing because it stopped exercising the ceremony. regtest/authorise.sh
# deliberately keeps its steps written out — the ceremony IS its subject.
permit_sending() { guardctl_op permit-sending || die "the operator's ceremony failed"; }


# cred_read <name> — a credential out of the volume, as hex.
cred_read() {
  docker run --rm -v "$CRED_VOLUME:/c" "$TOOL_IMAGE" \
    sh -c "[ -f /c/$1 ] && od -An -v -tx1 /c/$1 | tr -d ' \n'" 2>/dev/null || true
}

cred_exists() {
  docker run --rm -v "$CRED_VOLUME:/c" "$TOOL_IMAGE" test -f "/c/$1" 2>/dev/null
}

# rpc <container> <hex macaroon> <lncli args...> — make a call from inside that
# container's network namespace, so the source address is the container's and
# the ipaddr caveat is satisfied for the credential that carries it.
#
# `|| true` deliberately: a REFUSAL is the expected outcome for half the calls
# here and lncli exits non-zero for it, which under `set -e` would kill the
# script at the very case it exists to prove. The caller reads the output.
rpc() {
  local target="$1" mac="$2" cid; shift 2
  cid=$(docker compose ps -q "$target")
  docker run --rm --entrypoint sh --net="container:$cid" \
    -v "$(pwd)/data/lnd:/lnd:ro" -e MAC="$mac" -e RPC="$LND_RPC" "$LND_IMAGE" \
    -c 'echo -n "$MAC" | xxd -r -p > /tmp/m.macaroon
        lncli --network=regtest --rpcserver="$RPC" --tlscertpath=/lnd/tls.cert \
              --macaroonpath=/tmp/m.macaroon "$@" 2>&1' -- "$@" 2>&1 || true
}

last() { printf '%s' "$1" | grep -v '^\s*$' | tail -1 | cut -c1-110; }

# The two answers that matter, and they are NOT "did the call succeed".
#
# Every call below is expected to fail — the payment hash is invented. What
# separates the arms is WHY: LND refuses an unauthorised macaroon before it
# looks at the request, and complains about the request when the macaroon was
# accepted. Asserting "it failed" would pass in both directions.
refused_by_macaroon() {
  printf '%s' "$1" | grep -qiE 'permission denied|not authorized|unknown.*macaroon|root key|invalid.*macaroon|cannot get macaroon|expected 1 macaroon'
}
# Deliberately narrow, and narrower than it first was: "not found" and "no
# payment" also match docker and transport failures, so a broken call would have
# read as "the macaroon was accepted". These are request-side answers only, which
# makes the pair near-disjoint by construction rather than by inspection.
reached_the_rpc() {
  printf '%s' "$1" | grep -qiE 'payment isn.t initiated|invalid.*hash|payment_hash|encoding/hex'
}

say "0. setup"
command -v docker >/dev/null || die "docker is not on PATH"
command -v jq >/dev/null || die "jq is not on PATH"
docker compose ps -q guard >/dev/null 2>&1 || die "the regtest stack is not up (docker compose up -d)"
# The container's architecture, not the host's: the tool runs in the container.
case "$(docker run --rm "$TOOL_IMAGE" uname -m)" in
  aarch64|arm64) GOARCH=arm64 ;;
  x86_64|amd64)  GOARCH=amd64 ;;
  *) die "cannot map the container architecture to a GOARCH" ;;
esac
CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH go build -o "$WORK/guardctl" ./tools/guardctl \
  || die "could not build tools/guardctl"
CGO_ENABLED=0 go build -o "$WORK/mactool" ./tools/mactool || die "could not build tools/mactool"
ok "guardctl (linux/$GOARCH) and mactool built"

SERVER_IP=$(svc_value guard SERVER_IP)
[ -n "$SERVER_IP" ] || die "could not read SERVER_IP from docker-compose.yml"

RECV_MAC=$(cred_read recv.macaroon)
[ -n "$RECV_MAC" ] || die "there is no recv.macaroon in the credential volume; the stack is not linked"
ok "the stack is linked: recv.macaroon present, server locked to $SERVER_IP"

# Sending must start OFF. If a previous run left it on, the counts below would
# measure nothing.
if cred_exists spend.macaroon; then
  note "a spend.macaroon is left over from an earlier run; revoking it first"
  guardctl revoke-spend >/dev/null 2>&1 || true
fi
BEFORE_IDS=$(root_ids)
BEFORE_COUNT=$(root_count)
note "root key ids before: $BEFORE_IDS"

# ---------------------------------------------------------------------------
say "1. the receive macaroon cannot pay — before anything is baked"
# The premise of the whole epic, and the thing a wrong permission list would
# quietly break. Asserted BEFORE the spend macaroon exists so it cannot be
# confused with a stale credential.
OUT=$(rpc brollyzapper "$RECV_MAC" trackpayment 0000000000000000000000000000000000000000000000000000000000000001)
refused_by_macaroon "$OUT" \
  || die "the RECEIVE macaroon reached routerrpc; it grants five lnrpc methods and must not be able to pay: $(last "$OUT")"
ok "routerrpc refuses the receive macaroon — $(last "$OUT")"

# ---------------------------------------------------------------------------
say "2. bake the spend macaroon THROUGH THE GUARD"
# The operator permits sending first (`06v`): a fresh install's latch is off,
# and the guard refuses to bake without it whatever the environment says.
permit_sending
guardctl bake-spend || die "the guard refused to bake the spend macaroon"
cred_exists spend.macaroon || die "no spend.macaroon appeared in the credential volume"
SPEND_MAC=$(cred_read spend.macaroon)
[ -n "$SPEND_MAC" ] || die "spend.macaroon is empty"

AFTER_COUNT=$(root_count)
GAINED=$((AFTER_COUNT - BEFORE_COUNT))
[ "$GAINED" -eq 1 ] \
  || die "listmacaroonids gained $GAINED ids, want exactly 1 — one credential, one live root key (spec §6)"
ok "the node gained exactly one root key id"

# The caveats, through production's own two checks — the pair d24.7 showed can
# fail separately. RequireCaveats asks whether an ipaddr caveat is there at all;
# CaveatValue reads which address it is locked to, and a macaroon bound to the
# wrong container passes the first and is refused only by LND.
printf '%s\n' "$SPEND_MAC" | "$WORK/mactool" -require ipaddr \
  || die "the spend macaroon carries no ipaddr caveat"
printf '%s\n' "$SPEND_MAC" | "$WORK/mactool" -require time-before \
  || die "the spend macaroon carries no time-before caveat"
LOCKED_TO=$(printf '%s\n' "$SPEND_MAC" | "$WORK/mactool" -value ipaddr)
[ "$LOCKED_TO" = "$SERVER_IP" ] \
  || die "the spend macaroon is locked to $LOCKED_TO, not the server's $SERVER_IP"
ok "hardened: ipaddr $LOCKED_TO, and a time-before caveat"

# ---------------------------------------------------------------------------
say "3. the spend macaroon reaches routerrpc — the positive control"
# Without this the refusals either side prove nothing: a macaroon LND rejects
# for ANY reason would satisfy them.
OUT=$(rpc brollyzapper "$SPEND_MAC" trackpayment 0000000000000000000000000000000000000000000000000000000000000001)
if refused_by_macaroon "$OUT"; then
  die "LND refused the freshly baked spend macaroon: $(last "$OUT")"
fi
reached_the_rpc "$OUT" \
  || die "the spend macaroon was neither refused nor did it reach the RPC; the assertion cannot tell the arms apart: $OUT"
ok "TrackPaymentV2 accepted it and complained about the request — $(last "$OUT")"

# And from ANYWHERE ELSE it is inert, because of the ipaddr caveat (d24.7).
OUT=$(rpc guard "$SPEND_MAC" trackpayment 0000000000000000000000000000000000000000000000000000000000000001)
refused_by_macaroon "$OUT" \
  || die "the spend macaroon worked from the GUARD container; the ipaddr caveat binds nothing: $(last "$OUT")"
ok "and it is refused from another container — the ipaddr caveat binds"

# The copy an attacker would have. Taken while it is valid, presented after the
# revocation: this is the whole point of section 5.
EXFILTRATED="$SPEND_MAC"

# ---------------------------------------------------------------------------
say "4. revoke THROUGH THE GUARD"
IDS_WITH_SPEND=$(root_ids)
guardctl revoke-spend || die "the guard refused to revoke the spend macaroon"

# The SET, not the count: equal sets have equal cardinality, so this is the
# strictly stronger of the two and the count check it replaces could not have
# failed on its own.
[ "$(root_ids)" = "$BEFORE_IDS" ] \
  || die "the surviving ids are $(root_ids), want the original $BEFORE_IDS — the revocation took the wrong key"
ok "the spend root key is gone, and only it: $IDS_WITH_SPEND -> $BEFORE_IDS"

cred_exists spend.macaroon && die "spend.macaroon is still in the credential volume"
ok "spend.macaroon is gone from the credential volume"

STATUS=$(guardctl status)
[ "$(printf '%s' "$STATUS" | jq -r .spend_macaroon_present)" = "false" ] \
  || die "Status still reports a spend macaroon: $STATUS"
[ "$(printf '%s' "$STATUS" | jq -r .spend_root_key_listed)" = "false" ] \
  || die "Status still reports the spend root key as listed: $STATUS"
ok "Status tells the truth: no spend macaroon, key not listed"

# ---------------------------------------------------------------------------
say "5. THE RELEASE CRITERION: LND rejects the copy taken before the revocation"
# A local delete would pass everything above and fail this. §6 is explicit that
# RevokeSpend is a node-side revocation precisely so it holds against an
# attacker who already has the bytes — and the bytes are what is presented here.
OUT=$(rpc brollyzapper "$EXFILTRATED" trackpayment 0000000000000000000000000000000000000000000000000000000000000001)
refused_by_macaroon "$OUT" \
  || die "LND did NOT refuse the credential: Disable sending would be a local delete, and a copy taken before it would keep paying. $OUT"
ok "refused — $(last "$OUT")"
note "this is the same bytes that worked in section 3, from the same container."

# ---------------------------------------------------------------------------
say "6. re-enabling gets a FRESH key, and revoked stayed revoked in between"
# Revoking dropped the latch — "off must latch off" (`06v`, Ruling 1) — so
# turning sending back on is a fresh ceremony, exactly as it is for an operator.
permit_sending
guardctl bake-spend || die "the guard refused to re-bake the spend macaroon"
SPEND_AGAIN=$(cred_read spend.macaroon)
[ "$SPEND_AGAIN" != "$EXFILTRATED" ] \
  || die "the re-bake produced the same credential; the revoked one would be live again"
[ "$(root_count)" -eq "$((BEFORE_COUNT + 1))" ] \
  || die "the re-bake left $(root_count) ids, want $((BEFORE_COUNT + 1))"
OUT=$(rpc brollyzapper "$SPEND_AGAIN" trackpayment 0000000000000000000000000000000000000000000000000000000000000001)
refused_by_macaroon "$OUT" && die "the re-baked spend macaroon does not work: $(last "$OUT")"
# BOTH arms, as in section 3. Checking only the refusal would let a docker or
# transport failure — which is neither answer — pass as success.
reached_the_rpc "$OUT" \
  || die "the re-baked macaroon was not refused, but it did not reach the RPC either: $OUT"
ok "sending is back on under a new root key, and the old credential stays dead"

# Leave the stack as it was found: sending OFF.
guardctl revoke-spend >/dev/null || die "could not put the stack back"
[ "$(root_ids)" = "$BEFORE_IDS" ] || die "the stack was not restored: $(root_ids) != $BEFORE_IDS"
ok "stack restored — sending off, root key ids back to $BEFORE_IDS"

printf '\n\033[32mSPEND CHECK PASSED\033[0m — the guard mints the right to spend, and LND rejects it after RevokeSpend.\n\n'
