#!/usr/bin/env bash
# o34.7 criterion 10 — a REAL nostr client, not our own code.
#
# The criterion is manual by nature: "confirm it renders the receipt as a zap".
# What can be automated is everything a client does BEFORE it renders — find the
# receipt by subscribing with a normal filter, re-derive its id, check its
# signature, and resolve its tags into the entities a UI would show. This script
# does that half with `nak`, and prints what a client sees so the human half is
# a glance rather than an investigation.
#
# nak is the third client the criterion names, and it is the right one to script:
# Damus and Amethyst are phone apps. It is also INDEPENDENT in the way that
# matters — a different author, a different codebase, and upstream go-nostr
# rather than this repo's pinned fork. A check that shares the implementation it
# is checking is not a check.
#
#   go install github.com/fiatjaf/nak@latest
#   ./client-check.sh
set -euo pipefail
cd "$(dirname "$0")"

APP="http://localhost:${APP_PORT:-8080}"
RELAY_HOST="ws://localhost:${RELAY_PORT:-7777}"
RELAY_ADVERTISED="${RELAY_ADVERTISED:-wss://relay.invalid}"
NAME="${ADDRESS_NAME:-test}"
PASS="${ADMIN_PASSWORD:-regtest-admin}"
AMOUNT_MSAT="${AMOUNT_MSAT:-21000}"

command -v nak >/dev/null || { echo "nak is not on PATH: go install github.com/fiatjaf/nak@latest" >&2; exit 1; }

JAR=$(mktemp); WORK=$(mktemp -d); ZT="$WORK/zaptool"
trap 'rm -rf "$JAR" "$WORK"' EXIT

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m   %s\n' "$*"; }
die()  { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }
csrf() { grep -o 'name="csrf_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//'; }
lncli_recv()  { docker compose exec -T lnd lncli --network=regtest "$@"; }
lncli_payer() { docker compose exec -T lnd-payer lncli --network=regtest "$@"; }

( cd tools/zaptool && go build -o "$ZT" . ) || die "could not build tools/zaptool"
TOK=$(curl -s -c "$JAR" "$APP/login" | csrf)
curl -s -b "$JAR" -c "$JAR" -X POST "$APP/login" \
  --data-urlencode "csrf_token=$TOK" --data-urlencode "password=$PASS" -o /dev/null

DOC=$(curl -s "$APP/.well-known/lnurlp/$NAME")
RECIPIENT=$(echo "$DOC" | jq -r .nostrPubkey)
CALLBACK=$(echo "$DOC" | jq -r .callback)

say "1. zap a note, so there is something for a client to render"
NOTE=$(head -c 32 /dev/urandom | xxd -p -c 64)
ZR=$("$ZT" request "$RELAY_ADVERTISED" "$RECIPIENT" "$AMOUNT_MSAT" -e "$NOTE" \
     -content "zapped from the regtest stack")
PR=$(curl -s -G "$CALLBACK" --data-urlencode "amount=$AMOUNT_MSAT" \
      --data-urlencode "nostr=$ZR" --data-urlencode "comment=nice note" | jq -r '.pr // empty')
[ -n "$PR" ] || die "no invoice minted"
PH=$(lncli_recv decodepayreq --pay_req "$PR" | jq -r .payment_hash)
lncli_payer payinvoice --force --pay_req "$PR" --timeout 60s >/dev/null 2>&1 || true
for i in $(seq 1 30); do
  [ "$(lncli_recv lookupinvoice --rhash "$PH" | jq -r .state)" = "SETTLED" ] && break
  sleep 1
done
ok "note ${NOTE:0:16}… zapped, invoice settled"

say "2. a client subscribes and finds it"
# A NORMAL filter — kind 9735, and where there is a note, the e tag a client
# would use to show zaps under that note. Nothing bespoke.
R="$WORK/receipt.json"
for i in $(seq 1 10); do
  nak req -k 9735 --tag e="$NOTE" "$RELAY_HOST" 2>/dev/null | grep '^{' > "$R" || true
  [ -s "$R" ] && break
  sleep 2
done
[ -s "$R" ] || die "nak found no kind-9735 for this zap on $RELAY_HOST"
ok "nak returned the receipt for a plain kind-9735 subscription"

say "3. the client's acceptance check"
nak verify < "$R" || die "nak REJECTED the receipt — a conforming client would discard it (§16)"
ok "nak verify: id re-derives and the signature checks"

# The control. Without it, "nak said nothing" is indistinguishable from nak not
# checking — which is the exact shape §16 keeps finding.
TAMPERED="$WORK/tampered.json"
jq -c '.sig = (if (.sig|startswith("b")) then "c" else "b" end) + (.sig[1:])' < "$R" > "$TAMPERED"
if nak verify < "$TAMPERED" >/dev/null 2>&1; then
  die "nak ACCEPTED a receipt with a corrupted signature; this check proves nothing"
fi
ok "nak rejects the same receipt with one signature byte flipped — the check is real"

say "4. what the client has to render with"
echo "   kind        $(jq -r .kind < "$R")  ($(nak kind 9735 | jq -r .description))"
echo "   receipt id  $(jq -r .id < "$R")"
echo "   signed by   $(nak encode npub "$(jq -r .pubkey < "$R")")   <- this node's zap receipt key"
echo "   recipient   $(nak encode npub "$(jq -r '[.tags[]|select(.[0]=="p")|.[1]][0]' < "$R")")   <- p"
echo "   sender      $(nak encode npub "$(jq -r '[.tags[]|select(.[0]=="P")|.[1]][0]' < "$R")")   <- P"
E=$(jq -r '[.tags[]|select(.[0]=="e")|.[1]][0] // ""' < "$R")
[ -n "$E" ] && echo "   on note     $(nak encode nevent "$E")   <- e"
echo "   amount      $(jq -r '.tags[]|select(.[0]=="description")|.[1]' < "$R" | jq -r '[.tags[]|select(.[0]=="amount")|.[1]][0]') msat  <- from the description tag"
echo "   comment     $(jq -r '.tags[]|select(.[0]=="description")|.[1]' < "$R" | jq -r .content)"
echo "   tags        $(jq -r '[.tags[][0]]|join(" ")' < "$R")"

say "5. the description tag is a valid zap request in its own right"
jq -r '.tags[]|select(.[0]=="description")|.[1]' < "$R" > "$WORK/request.json"
nak verify < "$WORK/request.json" || die "the description tag is not a verifiable kind-9734"
ok "nak verify accepts the embedded zap request too — the sender's signature survives the round trip"
WANT=$(lncli_recv decodepayreq --pay_req "$PR" | jq -r .description_hash)
GOT=$(tr -d '\n' < "$WORK/request.json" | shasum -a 256 | cut -d' ' -f1)
[ "$GOT" = "$WANT" ] \
  && ok "sha256(description) == the invoice's description_hash — Appendix E's check, done as a client does it" \
  || die "sha256(description) $GOT != the invoice's description_hash $WANT"

printf '\n\033[32mCLIENT CHECK PASSED\033[0m — an independent implementation accepted the receipt.\n'
printf 'The remaining half of criterion 10 is a human looking at a phone.\n\n'
