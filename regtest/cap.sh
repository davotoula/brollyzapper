#!/usr/bin/env bash
# tna.3 — §14's two "done when" criteria for P4, on a live node.
#
#   1. a payment over the rolling cap is rejected by the guard, EVEN WITH THE
#      SERVER'S OWN CHECKS STUBBED OUT;
#   2. killing the guard makes LND reject the spend macaroon OUTRIGHT.
#
# WHAT "STUBBED OUT" MEANS HERE, because the brief asks the script to say it:
# nothing is patched. Every call below is made **directly to LND with the spend
# macaroon**, from inside the server's own network namespace so the `ipaddr`
# caveat is satisfied — which bypasses, by construction and not by mocking:
#
#   - §5's working ceiling and the wallet reservation (`internal/wallet`),
#   - §8's rejection ladder and the NWC budget checks,
#   - §11's Tier-2 refusals, including the two rows `tna.2` added.
#
# That is precisely the compromised-server model §6 is written against: the
# attacker holds the credential and calls the RPC itself. If anything below
# refuses, it is the guard or the node — nothing of ours is in the path.
#
# Bakes macaroons, revokes root keys and stops the guard. Regtest only.
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

# The guard goes back up whatever happens. e2e.sh restarts what it stopped from
# an EXIT trap and the same discipline applies here: a run that dies between
# "stop the guard" and "start it again" would leave the next run failing for a
# reason that has nothing to do with the next run.
GUARD_STOPPED=0
cleanup() {
  if [ "$GUARD_STOPPED" = 1 ]; then
    printf '   \033[90m..\033[0m   putting the guard back\n'
    docker compose start guard >/dev/null 2>&1 || true
    wait_for_middleware || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m   %s\n' "$*"; }
note() { printf '   \033[90m..\033[0m   %s\n' "$*"; }
die()  { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

last() { printf '%s' "$1" | grep -v '^\s*$' | tail -1 | cut -c1-160; }

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


cred_read() {
  docker run --rm -v "$CRED_VOLUME:/c" "$TOOL_IMAGE" \
    sh -c "[ -f /c/$1 ] && od -An -v -tx1 /c/$1 | tr -d ' \n'" 2>/dev/null || true
}

cred_exists() {
  docker run --rm -v "$CRED_VOLUME:/c" "$TOOL_IMAGE" test -f "/c/$1" 2>/dev/null
}

# rpc <container> <hex macaroon> <lncli args...>
#
# `|| true` deliberately: a refusal is the expected outcome for most calls here
# and lncli exits non-zero for it, which under `set -e` would kill the script at
# the very case it exists to prove. The caller reads the output.
rpc() {
  local target="$1" mac="$2" cid; shift 2
  cid=$(docker compose ps -q "$target")
  docker run --rm --entrypoint sh --net="container:$cid" \
    -v "$(pwd)/data/lnd:/lnd:ro" -e MAC="$mac" -e RPC="$LND_RPC" "$LND_IMAGE" \
    -c 'echo -n "$MAC" | xxd -r -p > /tmp/m.macaroon
        lncli --network=regtest --rpcserver="$RPC" --tlscertpath=/lnd/tls.cert \
              --macaroonpath=/tmp/m.macaroon "$@" 2>&1' -- "$@" 2>&1 || true
}

# The guard's own refusal, which travels back through LND as the RPC's error.
# Matched on the prefix the guard itself puts there — see errSpendRefused in
# internal/guard/spendcap.go — rather than on wording that may be reworded.
refused_by_the_guard() { printf '%s' "$1" | grep -q 'brollyzapper guard'; }

# LND refusing the macaroon BECAUSE nothing is registered for its custom caveat.
# The node's own words: rpcperms/interceptor.go answers an unregistered custom
# caveat with "unknown custom caveat condition used in macaroon: <name>".
refused_for_an_unhonoured_caveat() {
  printf '%s' "$1" | grep -qi 'custom caveat'
}

# invoice <amount sats> — a payable request from the OTHER node, so the amount
# is real and signed rather than something this script asserts about itself.
invoice() {
  docker compose exec -T lnd-payer lncli --network=regtest addinvoice --amt "$1" \
    | jq -r '.payment_request'
}

local_sats() {
  docker compose exec -T lnd lncli --network=regtest channelbalance | jq -r '.local_balance.sat'
}

# ensure_liquidity <sats> — make sure the app's node can actually SEND that much.
#
# THE PAYMENTS IN SECTION 1 HAVE TO SUCCEED, and that is a measured requirement
# rather than a preference. §14 lets the guard return an attempt to the window on
# an observed terminal failure, and an unroutable payment is not slow about it:
# LND answers FAILURE_REASON_INSUFFICIENT_BALANCE in about THIRTEEN MILLISECONDS,
# so a burst of payments that cannot route is refunded as fast as it is made and
# the window never fills. Measured on this stack, 2026-08-26 — the first version
# of this script fired eight at once and every one was allowed.
#
# Payments that SETTLE are not refunded, so they accumulate. That also makes the
# assertion stronger: the cap is shown stopping real spending, not attempts that
# were going nowhere.
ensure_liquidity() {
  local want="$1" have
  have=$(local_sats)
  if [ "$have" -ge "$want" ]; then
    note "the app's node can send $have sats; no rebalance needed"
    return 0
  fi
  local top_up=$((want - have + 10000))
  note "the app's node can send only $have sats; pulling $top_up back from the payer"
  local req
  req=$(docker compose exec -T lnd lncli --network=regtest addinvoice --amt "$top_up" \
        | jq -r '.payment_request')
  [ -n "$req" ] || die "the app's node would not mint a rebalancing invoice"
  docker compose exec -T lnd-payer lncli --network=regtest payinvoice --force "$req" >/dev/null 2>&1 \
    || die "the payer could not rebalance the channel"
  have=$(local_sats)
  [ "$have" -ge "$want" ] \
    || die "after rebalancing the app's node can send $have sats, want $want"
  note "rebalanced: the app's node can send $have sats"
}

spend_used() { guardctl status | jq -r '.spend_used_msat // 0'; }
spend_limit() { guardctl status | jq -r '.spend_limit_msat // 0'; }

# reset_the_window empties the guard's rolling window, so the burst below starts
# from a known headroom.
#
# IT HAS TO BE DONE BY HAND, and that is a PROPERTY rather than an inconvenience:
# nothing in the guard's API clears the window. Revoking and re-baking does not —
# section 1b asserts it — because both are operations the SERVER can call, and a
# cap a compromised server could reset by toggling sending twice would be no cap
# at all. Records leave only by ageing out of the 24 hours.
#
# The guard is stopped first: it rewrites this file on every attempt, and an edit
# underneath a running process is a lost update.
reset_the_window() {
  docker compose stop guard >/dev/null 2>&1 || die "could not stop the guard"
  GUARD_STOPPED=1
  # The state is compact JSON and spend_attempts holds no nested array, so the
  # first `]` closes it.
  docker run --rm --user 0:0 -v brollyregtest_guard-data:/g "$TOOL_IMAGE" \
    sh -c 'sed -i "s/\"spend_attempts\":\[[^]]*\],//" /g/guard-state.json' \
    || die "could not clear the guard's spend window"
  docker compose start guard >/dev/null 2>&1 || die "could not restart the guard"
  GUARD_STOPPED=0
  wait_for_middleware || die "the guard did not re-register after the window was reset"
}

wait_for_middleware() {
  local i=0
  while [ "$i" -lt 60 ]; do
    if [ "$(guardctl status 2>/dev/null | jq -r '.middleware_registered // false')" = "true" ]; then
      return 0
    fi
    i=$((i + 1)); sleep 1
  done
  return 1
}

# ---------------------------------------------------------------------------
say "0. setup"
command -v docker >/dev/null || die "docker is not on PATH"
command -v jq >/dev/null || die "jq is not on PATH"
docker compose ps -q guard >/dev/null 2>&1 || die "the regtest stack is not up (docker compose up -d)"
case "$(docker run --rm "$TOOL_IMAGE" uname -m)" in
  aarch64|arm64) GOARCH=arm64 ;;
  x86_64|amd64)  GOARCH=amd64 ;;
  *) die "cannot map the container architecture to a GOARCH" ;;
esac
CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH go build -o "$WORK/guardctl" ./tools/guardctl \
  || die "could not build tools/guardctl"
ok "guardctl (linux/$GOARCH) built"

wait_for_middleware \
  || die "the guard is not registered as an RPC middleware; without that the node refuses the
          spend macaroon for a different reason and neither criterion below means anything"
ok "the guard is registered with the node as an RPC middleware"

# A FRESH spend macaroon, and a fresh window with it: a leftover from an earlier
# run would carry that run's spending, and criterion 1 counts.
if cred_exists spend.macaroon; then
  note "revoking a spend macaroon left over from an earlier run"
  guardctl revoke-spend >/dev/null 2>&1 || true
fi
permit_sending
guardctl bake-spend || die "the guard refused to bake the spend macaroon"
SPEND_MAC=$(cred_read spend.macaroon)
[ -n "$SPEND_MAC" ] || die "no spend.macaroon in the credential volume after a bake"

LIMIT=$(spend_limit)
[ "$LIMIT" -gt 0 ] || die "the guard reports no spend limit; GUARD_MAX_SPEND_MSAT is unset"
ok "spend macaroon baked; the guard's window is $LIMIT msat"

# ---------------------------------------------------------------------------
say "1. THE FIRST CRITERION: the guard refuses a payment over its rolling cap"
# Attempts are made until one is refused BY THE WINDOW. The count is not
# asserted, deliberately: what it takes depends on the per-payment cap and on
# whatever fee limit lncli chooses, and a script that pinned "the fifth one" would
# fail the first time either moved for a reason that has nothing to do with the
# cap. What IS asserted is the shape — some were allowed, one was refused, and
# the refusal names the window rather than the per-payment limit.
#
# THE PAYMENTS NEED NO LIQUIDITY. The guard answers before LND performs the RPC,
# so a payment that would fail to route is refused or counted at exactly the same
# point — and one that IS allowed still counts against the window, which is §14's
# attempt-based rule getting an incidental proof.
AMOUNT_SATS=20000

# A KNOWN HEADROOM. The window deliberately survives everything the guard's own
# API can do to it (see reset_the_window and section 1b), so a run within 24
# hours of another would otherwise start part-full and the count below would be
# guesswork.
reset_the_window
BEFORE=$(spend_used)
[ "$BEFORE" = "0" ] \
  || die "the window still holds $BEFORE msat after being reset; the fixture is not working
          and every count below would be measuring the previous run"

# Enough outbound to fill the window and then some, so the run is bounded by the
# CAP and not by the channel.
ensure_liquidity $(( LIMIT / 1000 + AMOUNT_SATS * 2 ))

ALLOWED=0
REFUSAL=""
for attempt in $(seq 1 12); do
  BOLT11=$(invoice "$AMOUNT_SATS")
  [ -n "$BOLT11" ] || die "the payer node would not mint a $AMOUNT_SATS sat invoice"
  OUT=$(rpc brollyzapper "$SPEND_MAC" sendpayment --force --pay_req "$BOLT11" --timeout 30s)
  USED=$(spend_used)
  if refused_by_the_guard "$OUT"; then
    REFUSAL="$OUT"
    # A refusal must not charge the window. That would be the cap leaking in the
    # direction nobody would notice: every refused payment bringing the next one
    # closer to being refused too.
    [ "$USED" -le "$LIMIT" ] \
      || die "the window holds $USED msat, over the $LIMIT msat limit — a refused payment was
              counted"
    note "attempt $attempt refused with the window at $USED of $LIMIT msat"
    break
  fi
  ALLOWED=$((ALLOWED + 1))
  note "attempt $attempt allowed; window now $USED of $LIMIT msat"
done

[ -n "$REFUSAL" ] \
  || die "twelve payments of $AMOUNT_SATS sats each did not exhaust a $LIMIT msat window; the cap
          is not being applied to payments made directly with the credential"
[ "$ALLOWED" -gt 0 ] \
  || die "the FIRST attempt was refused, so this proves nothing about the window — it would read
          the same if the per-payment cap or the credential were the problem: $(last "$REFUSAL")"
printf '%s' "$REFUSAL" | grep -q "over the limit of $LIMIT msat" \
  || die "the refusal does not name the WINDOW limit, so it may be the per-payment cap or
          something else entirely: $(last "$REFUSAL")"
ok "$ALLOWED payment(s) allowed, then refused at the window — $(last "$REFUSAL")"

AFTER=$(spend_used)
[ "$AFTER" -gt 0 ] \
  || die "the window is empty ($AFTER msat) after $ALLOWED allowed payments; §14 counts the
          ATTEMPT, and a counter that waited for settlement would be empty here too"
ok "the window holds $AFTER of $LIMIT msat"

# ---------------------------------------------------------------------------
say "1b. turning sending off and on again does NOT hand back a fresh window"
# Both operations are on the guard's four-call socket API, which means a
# compromised server can call them. If either cleared the window, the cap would
# be a formality: revoke, re-bake, spend another full window, repeat. §6's whole
# claim is that the server cannot raise its own limit.
FULL=$(spend_used)
guardctl revoke-spend >/dev/null || die "the guard refused to revoke"
permit_sending
guardctl bake-spend >/dev/null || die "the guard refused to re-bake"
AFTER_TOGGLE=$(spend_used)
[ "$AFTER_TOGGLE" = "$FULL" ] \
  || die "the window went from $FULL to $AFTER_TOGGLE msat across a revoke and a re-bake; a
          compromised server would reset the cap by toggling sending and spend without bound"
ok "the window is still $AFTER_TOGGLE msat after a full revoke and re-bake"
SPEND_MAC=$(cred_read spend.macaroon)
[ -n "$SPEND_MAC" ] || die "no spend.macaroon after the re-bake"

# And the fresh credential is refused too, which is the same fact from the other
# side: the cap belongs to the NODE's spending, not to a particular macaroon.
BOLT11=$(invoice "$AMOUNT_SATS")
OUT=$(rpc brollyzapper "$SPEND_MAC" sendpayment --force --pay_req "$BOLT11" --timeout 5s)
refused_by_the_guard "$OUT" \
  || die "a payment on the FRESH credential was allowed while the window is full ($AFTER_TOGGLE of
          $LIMIT msat); the cap follows the credential rather than the window: $(last "$OUT")"
ok "a payment on the fresh credential is refused as well — $(last "$OUT")"

# And it was the GUARD that refused, inside LND's request path, with nothing of
# ours in the way. §5's ceiling would have refused at 0 sats; §8's ladder never
# ran; §11's Tier-2 rows were never consulted.
note "no server-side check was in the path: the call went straight to LND with the credential"

# ---------------------------------------------------------------------------
say "2. THE SECOND CRITERION: killing the guard makes LND reject the macaroon"
# The positive control first, or the assertion below cannot tell "the node
# refuses this macaroon" from "the node refuses this macaroon for some other
# reason". TrackPaymentV2 is used rather than a payment: it is in the same
# credential, it moves nothing, and the guard's middleware does not price it —
# so what changes between the two calls is only whether the guard is alive.
OUT=$(rpc brollyzapper "$SPEND_MAC" trackpayment 0000000000000000000000000000000000000000000000000000000000000001)
if refused_for_an_unhonoured_caveat "$OUT"; then
  die "the node already refuses the caveat with the guard UP: $(last "$OUT")"
fi
ok "with the guard up, the node accepts the macaroon — $(last "$OUT")"

docker compose stop guard >/dev/null 2>&1 || die "could not stop the guard"
GUARD_STOPPED=1
note "the guard is stopped; its middleware registration is gone with it"

OUT=$(rpc brollyzapper "$SPEND_MAC" trackpayment 0000000000000000000000000000000000000000000000000000000000000001)
refused_for_an_unhonoured_caveat "$OUT" \
  || die "the node still honoured the spend macaroon with no middleware registered. The custom
          caveat has to FAIL CLOSED, or a guard that dies leaves sending UNRESTRICTED — which is
          the opposite of what §14 claims: $(last "$OUT")"
ok "LND rejects it outright — $(last "$OUT")"

# The same call with the RECEIVE macaroon still works, which is what makes the
# rejection specific rather than "the node is unhappy". It carries no custom
# caveat, so nothing about it depends on the guard being alive — and zap
# receiving surviving a dead guard is the property that pays for fail-closed
# being acceptable at all.
RECV_MAC=$(cred_read recv.macaroon)
[ -n "$RECV_MAC" ] || die "no recv.macaroon in the credential volume"
OUT=$(rpc brollyzapper "$RECV_MAC" getinfo)
printf '%s' "$OUT" | grep -q 'identity_pubkey' \
  || die "the RECEIVE macaroon stopped working with the guard down; the custom caveat is only
          on the spend credential and receiving must be unaffected: $(last "$OUT")"
ok "and the receive macaroon still works — receiving is unaffected by a dead guard"

docker compose start guard >/dev/null 2>&1 || die "could not restart the guard"
GUARD_STOPPED=0
wait_for_middleware || die "the guard did not re-register after being restarted"
ok "the guard is back and registered; the stack is as it was found"

# ---------------------------------------------------------------------------
say "done — P4's two done-when criteria hold against a live node"
