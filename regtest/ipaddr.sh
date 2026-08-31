#!/usr/bin/env bash
# d24.7 — what LND's ipaddr caveat actually binds to, on a real node.
#
# §18 assumed the source address LND sees for a container's gRPC call is the
# address compose assigned it. d24.1 is about to bake a SPEND macaroon carrying
# that caveat, and if the assumption is wrong the credential is either useless
# (bound to an address that never calls) or unbound (bound to something every
# container shares). This measures it instead.
#
# Both directions, always. A macaroon that is accepted proves nothing on its
# own: an ipaddr caveat LND ignored would also be accepted. The REJECTION from
# a different source is the proof the caveat binds at all.
#
# Bakes only on the regtest node. Never run this against a real LND: it creates
# root keys, and root key ids are the thing the guard's rotation logic counts.
set -euo pipefail
cd "$(dirname "$0")"

# BY NAME, not by address (`2af`). Compose assigns addresses in start order and
# nothing pins LND's, so the literal 10.30.0.5 this used to carry pointed at the
# PAYER node after a `down -v` reshuffled them. The certificate carries
# `--tlsextradomain=lnd`, which is what makes the name usable.
LND_RPC="${LND_RPC:-lnd:10009}"
LND_IMAGE="${LND_IMAGE:-lightninglabs/lnd:v0.21.1-beta}"
# Root key ids for this script's macaroons, well clear of anything the app bakes.
ROOT_KEY_BASE="${ROOT_KEY_BASE:-9040}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m   %s\n' "$*"; }
note() { printf '   \033[90m..\033[0m   %s\n' "$*"; }
die()  { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

lncli_recv() { docker compose exec -T lnd lncli --network=regtest "$@"; }

# svc_value <service> <key> — one key from one compose service.
svc_value() {
  awk -v svc="  $1:" -v key="$2:" '
    $0 == svc { in_svc = 1; next }
    /^  [a-z]/ { in_svc = 0 }
    in_svc && $1 == key { print $2; exit }' docker-compose.yml
}

container_ip() {
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$(docker compose ps -q "$1")"
}

# present <container> <hex macaroon> — make a gRPC call to LND from inside that
# container's network namespace, so the source address is the container's.
#
# --net=container: rather than a fresh container on the network, because the
# question is what LND sees for THAT container specifically.
present() {
  local target="$1" mac="$2" cid
  cid=$(docker compose ps -q "$target")
  docker run --rm --entrypoint sh --net="container:$cid" \
    -v "$(pwd)/data/lnd:/lnd:ro" -e MAC="$mac" -e RPC="$LND_RPC" "$LND_IMAGE" \
    -c 'echo -n "$MAC" | xxd -r -p > /tmp/m.macaroon
        lncli --network=regtest --rpcserver="$RPC" --tlscertpath=/lnd/tls.cert \
              --macaroonpath=/tmp/m.macaroon getinfo 2>&1' 2>&1 || true
  # Always zero, deliberately. A REFUSAL is the expected outcome for most calls
  # here and lncli exits non-zero for it, which under `set -e` killed the script
  # silently at the first rejection — the very case this exists to prove.
  # accepted() reads the output; the exit status carries no meaning we want.
}

# last reports one line of an outcome, for a message. The full output is what
# accepted() reads: an earlier version truncated here and cut off the very line
# that says the call worked, so a success read as a refusal.
last() { printf '%s' "$1" | grep -v '^\s*$' | tail -1 | cut -c1-96; }

accepted() { printf '%s' "$1" | grep -q '"identity_pubkey"'; }

# must_accept / must_refuse — one shape for the assertion this whole script is
# built around, so the both-directions structure is visible at a glance rather
# than written four different ways.
must_accept() { accepted "$1" || die "$2: $(last "$1")"; }
must_refuse() { accepted "$1" && die "$2"; return 0; }

say "0. setup"
command -v docker >/dev/null || die "docker is not on PATH"
docker compose ps -q lnd >/dev/null 2>&1 || die "the regtest stack is not up (docker compose up -d)"
go build -o "$WORK/mactool" ./tools/mactool || die "could not build tools/mactool"
ok "mactool built — it adds the one caveat lncli cannot"

SERVER_IP=$(container_ip brollyzapper)
GUARD_IP=$(container_ip guard)
RELAY_IP=$(container_ip relay)
[ -n "$SERVER_IP" ] && [ -n "$GUARD_IP" ] || die "could not read the container addresses"
# Three names for one address, read from the compose file rather than from
# docker so that any two of them can disagree and be seen to:
#
#   ASSIGNED   what compose PINS the server container (§18's static allocation)
#   BAKED_FOR  what the guard is TOLD to put in the ipaddr caveat
#   SERVER_IP  what docker actually gave the container, read above
#
# The compose file's own comment beside ipv4_address says the two settings must
# be equal. This is that comment, checked. If they ever drift, the credential is
# bound to an address that never calls and every symptom appears at LND.
#
# Each read is scoped to its service rather than "the first match in the file":
# NETWORK_CIDR and SERVER_IP belong to the GUARD, which is what bakes, while
# ipv4_address belongs to the server, which is what connects — and an unscoped
# grep for either would have quietly found the wrong one.
ASSIGNED=$(svc_value brollyzapper ipv4_address)
BAKED_FOR=$(svc_value guard SERVER_IP)
# NETWORK_CIDR, and not the network's own `subnet:` key, because this is the
# value §6's iprange fallback would actually ship — so it is the one worth
# proving.
SUBNET=$(svc_value guard NETWORK_CIDR)
[ -n "$ASSIGNED" ] && [ -n "$BAKED_FOR" ] && [ -n "$SUBNET" ] \
  || die "could not read ipv4_address / SERVER_IP / NETWORK_CIDR from docker-compose.yml"
ok "server $SERVER_IP (compose assigns $ASSIGNED, guard bakes for $BAKED_FOR), guard $GUARD_IP, relay $RELAY_IP, subnet $SUBNET"
[ "$SERVER_IP" = "$ASSIGNED" ] \
  || die "docker gave the server $SERVER_IP but the compose file assigns $ASSIGNED"
[ "$BAKED_FOR" = "$ASSIGNED" ] \
  || die "the guard bakes ipaddr $BAKED_FOR but the server container is $ASSIGNED; the credential would be bound to an address that never calls"

# ---------------------------------------------------------------------------
say "1. bake a macaroon carrying 'ipaddr <server>'"
IPADDR_MAC=$(lncli_recv bakemacaroon --ip_address="$SERVER_IP" \
  --root_key_id="$ROOT_KEY_BASE" uri:/lnrpc.Lightning/GetInfo 2>/dev/null | tail -1)
[ -n "$IPADDR_MAC" ] || die "bakemacaroon produced nothing"
# Parsed, not grepped — and in the two steps production takes, because they can
# fail separately. A strings(1) scan matches a byte sequence anywhere in the
# serialised macaroon. lnd.RequireCaveats asks whether an ipaddr caveat is there
# at all; lnd.CaveatValue reads the address it is locked TO. A macaroon bound to
# the wrong container passes the first and is refused by the node, which is the
# failure §11's post-bake verification exists to catch. Both are the guard's own
# functions.
printf '%s\n' "$IPADDR_MAC" | "$WORK/mactool" -require ipaddr \
  || die "the baked macaroon carries no ipaddr caveat at all; it carries: $(printf '%s\n' "$IPADDR_MAC" | "$WORK/mactool" -caveats | paste -sd', ' -)"
LOCKED_TO=$(printf '%s\n' "$IPADDR_MAC" | "$WORK/mactool" -value ipaddr)
[ "$LOCKED_TO" = "$SERVER_IP" ] \
  || die "the macaroon is locked to $LOCKED_TO, not the $SERVER_IP it was baked for"
ok "baked, root key id $ROOT_KEY_BASE, carrying 'ipaddr $SERVER_IP'"

# ---------------------------------------------------------------------------
say "2. accepted from the server container"
OUT=$(present brollyzapper "$IPADDR_MAC")
must_accept "$OUT" "the server container was refused with its own macaroon"
ok "GetInfo succeeded from $SERVER_IP"

# ---------------------------------------------------------------------------
say "3. rejected from every other source — this is the proof"
# Without this half, a caveat LND silently ignored would look identical to one
# it enforces.
for name in guard relay; do
  OUT=$(present "$name" "$IPADDR_MAC")
  must_refuse "$OUT" "the $name container was ACCEPTED with a macaroon bound to $SERVER_IP; the caveat binds nothing"
  # Refused is not enough. A wrong path, a bad cert or a mistyped macaroon is
  # also refused, and would read as proof the caveat works. The refusal has to
  # name the caveat.
  printf '%s' "$OUT" | grep -q "ipaddr $SERVER_IP" \
    || die "the $name container was refused, but not by the ipaddr caveat: $OUT"
  note "$name: $(last "$OUT")"
done
ok "both other containers refused, each naming the caveat"

# LND's gRPC is deliberately NOT published to the host in this stack — only the
# app's 8080 is — so "from the host" is not reachable here. Recorded rather than
# skipped silently: the caveat's job is to bind the credential to the server
# container, and three distinct in-network sources is what proves it does.
note "the host arm is not testable: docker-compose.yml publishes 8080 and not LND's 10009"

# ---------------------------------------------------------------------------
say "4. the §18 fact: which source address does LND observe?"
# Measured by binding a macaroon to the GUARD's address and presenting it from
# the guard. If LND saw anything else — a gateway, a NAT address, a shared
# docker-proxy source — this would be refused exactly as section 3 was.
GUARD_MAC=$(lncli_recv bakemacaroon --ip_address="$GUARD_IP" \
  --root_key_id="$((ROOT_KEY_BASE + 1))" uri:/lnrpc.Lightning/GetInfo 2>/dev/null | tail -1)
OUT=$(present guard "$GUARD_MAC")
must_accept "$OUT" \
  "a macaroon bound to the guard's own address $GUARD_IP was refused FROM the guard; LND is observing some other source"
ok "a macaroon bound to $GUARD_IP is accepted from the guard — LND observes the container's own compose-assigned address"
note "FACT for d24.1: docker does NOT rewrite the source for container-to-container"
note "traffic on this user-defined bridge. SERVER_IP is the app container's address"
note "on the app network — $SERVER_IP here — not a gateway and not the host."

# ---------------------------------------------------------------------------
say "5. the iprange fallback (§6), both directions"
# lncli has no flag for this caveat, so it is added directly. §6 names iprange
# as what ships when a static container address cannot be obtained, and a
# fallback that has never been run is not a fallback.
BASE_MAC=$(lncli_recv bakemacaroon --root_key_id="$((ROOT_KEY_BASE + 2))" \
  uri:/lnrpc.Lightning/GetInfo 2>/dev/null | tail -1)
RANGE_MAC=$(printf '%s\n' "$BASE_MAC" | "$WORK/mactool" "iprange $SUBNET") \
  || die "could not add the iprange caveat"
OUT=$(present brollyzapper "$RANGE_MAC")
must_accept "$OUT" "in-range source was refused with 'iprange $SUBNET'"
ok "in-range: accepted from $SERVER_IP with 'iprange $SUBNET'"

# Out of range: a CIDR the containers are not in. If this is accepted the caveat
# is not being enforced, and §6's fallback is decoration.
NARROW_MAC=$(printf '%s\n' "$BASE_MAC" | "$WORK/mactool" "iprange 192.0.2.0/24") \
  || die "could not add the narrow iprange caveat"
OUT=$(present brollyzapper "$NARROW_MAC")
must_refuse "$OUT" "a macaroon restricted to 192.0.2.0/24 was ACCEPTED from $SERVER_IP; the iprange caveat binds nothing, and §6's fallback would ship unenforced"
ok "out-of-range: refused — $(last "$OUT")"

printf '\n\033[32mIPADDR CHECK PASSED\033[0m — the caveat binds to the container'"'"'s own address.\n\n'
