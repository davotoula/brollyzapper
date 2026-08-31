#!/usr/bin/env bash
# Criterion 6: prove the stack. Mint an invoice through the LNURL callback, pay
# it from the second node, assert the wallet credited exactly once, and assert a
# kind-9735 receipt is READABLE BACK off the relay with the right description
# hash.
#
# This is o34.7's skeleton, not o34.7. That bead adds the replay, the profile
# zap, relay-down-then-up, and the manual Damus/Amethyst check.
set -euo pipefail
cd "$(dirname "$0")"

APP="http://localhost:${APP_PORT:-8080}"
RELAY_HOST="ws://localhost:${RELAY_PORT:-7777}"   # as the host sees it
RELAY_APP="ws://relay:7777"                       # as the app sees it (operator default set)
# What the ZAP REQUEST advertises. It cannot be RELAY_APP: a zap request is
# anonymous input, and the app refuses to dial anything a stranger names that
# looks local — including any single-label hostname, which every compose
# service name is (internal/lnurl/zaprequest.go, isLocalHost). That guard is
# correct and we do not want it relaxed for a test. So the request names a
# dotted host that will never resolve, and the receipt reaches our relay
# through the operator-configured default set instead — which is the path an
# operator actually relies on.
RELAY_ADVERTISED="${RELAY_ADVERTISED:-wss://relay.invalid}"
NAME="${ADDRESS_NAME:-test}"
AMOUNT_MSAT="${AMOUNT_MSAT:-21000}"
PASS="${ADMIN_PASSWORD:-regtest-admin}"
JAR=$(mktemp); ZT=$(mktemp -d)/zaptool
trap 'rm -f "$JAR"' EXIT

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m  %s\n' "$*"; }
die()  { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }
csrf() { grep -o 'name="csrf_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//'; }
lncli_payer() { docker compose exec -T lnd-payer lncli --network=regtest "$@"; }
lncli_recv()  { docker compose exec -T lnd lncli --network=regtest "$@"; }

say "0. build the zap helper"
( cd tools/zaptool && go build -o "$ZT" . ) || die "could not build tools/zaptool"
ok "zaptool built"

say "1. the app is up"
for i in $(seq 1 60); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$APP/health" || true)" = "200" ] && break
  sleep 2
done
[ "$(curl -s -o /dev/null -w '%{http_code}' "$APP/health")" = "200" ] || die "$APP/health never returned 200"
ok "/health 200"

say "2. sign in and configure the lightning address"
TOK=$(curl -s -c "$JAR" "$APP/login" | csrf)
curl -s -b "$JAR" -c "$JAR" -X POST "$APP/login" \
  --data-urlencode "csrf_token=$TOK" --data-urlencode "password=$PASS" -o /dev/null
TOK=$(curl -s -b "$JAR" "$APP/settings" | csrf)
curl -s -b "$JAR" -c "$JAR" -X POST "$APP/settings" \
  --data-urlencode "csrf_token=$TOK" \
  --data-urlencode "domain=$APP" \
  --data-urlencode "address_name=$NAME" \
  --data-urlencode "default_relays=$RELAY_APP" \
  --data-urlencode "trusted_proxies=" \
  --data-urlencode "public_rate_limit_per_min=600" \
  --data-urlencode "public_rate_limit_per_hour=6000" \
  --data-urlencode "max_fee_ppm=10000" --data-urlencode "max_fee_floor_msat=10000" \
  --data-urlencode "log_level=INFO" --data-urlencode "credit_received=on" -o /dev/null
ok "address $NAME@$APP, relay $RELAY_APP"

say "3. the LNURL pay document"
DOC=$(curl -s "$APP/.well-known/lnurlp/$NAME")
echo "$DOC" | jq -e '.callback and .metadata and .allowsNostr==true and (.nostrPubkey|length==64)' >/dev/null \
  || die "unexpected payRequest: $DOC"
CALLBACK=$(echo "$DOC" | jq -r .callback)
RECIPIENT=$(echo "$DOC" | jq -r .nostrPubkey)
ok "callback $CALLBACK"
ok "nostrPubkey $RECIPIENT"

say "4. a signed zap request (kind 9734)"
ZAPREQ=$("$ZT" request "$RELAY_ADVERTISED" "$RECIPIENT" "$AMOUNT_MSAT")
echo "$ZAPREQ" | jq -e '.kind==9734 and (.sig|length==128)' >/dev/null || die "zap request not signed: $ZAPREQ"
ok "kind 9734 signed by $(echo "$ZAPREQ" | jq -r .pubkey | cut -c1-16)… advertising $RELAY_ADVERTISED"

say "5. mint the invoice"
INV=$(curl -s -G "$CALLBACK" --data-urlencode "amount=$AMOUNT_MSAT" --data-urlencode "nostr=$ZAPREQ")
PR=$(echo "$INV" | jq -r '.pr // empty')
[ -n "$PR" ] || die "no invoice: $INV"
ok "bolt11 ${PR:0:40}…"

DEC=$(lncli_recv decodepayreq --pay_req "$PR")
DHASH=$(echo "$DEC" | jq -r .description_hash)
WANT=$(printf '%s' "$ZAPREQ" | shasum -a 256 | cut -d' ' -f1)
ok "invoice amount $(echo "$DEC" | jq -r .num_msat) msat, expiry $(echo "$DEC" | jq -r .expiry)s"
[ "$DHASH" = "$WANT" ] \
  && ok "description_hash == sha256(zap request)  $DHASH" \
  || die "description_hash $DHASH != sha256(zap request) $WANT"

say "6. balance before"
BEFORE=$(curl -s -b "$JAR" "$APP/" | sed -e 's/<[^>]*>/ /g' | tr -s ' ' | grep -o 'Balance: [0-9.]*' | head -1 | awk '{print $2}')
ok "balance $BEFORE sats"

say "7. pay it from the second node"
lncli_payer payinvoice --force --pay_req "$PR" --timeout 60s >/dev/null 2>&1 || true
for i in $(seq 1 30); do
  STATE=$(lncli_recv lookupinvoice --rhash "$(echo "$DEC" | jq -r .payment_hash)" | jq -r .state)
  [ "$STATE" = "SETTLED" ] && break
  sleep 2
done
[ "$STATE" = "SETTLED" ] || die "invoice never settled (state=$STATE)"
ok "invoice SETTLED on the receiving node"

say "8. the wallet credited exactly once"
sleep 4
AFTER=$(curl -s -b "$JAR" "$APP/" | sed -e 's/<[^>]*>/ /g' | tr -s ' ' | grep -o 'Balance: [0-9.]*' | head -1 | awk '{print $2}')
ok "balance $BEFORE -> $AFTER sats"
CREDITS=$(docker compose logs brollyzapper 2>&1 | grep -c "\"payment_hash\":\"$(echo "$DEC" | jq -r .payment_hash)\"" || true)
awk -v a="$AFTER" -v b="$BEFORE" -v amt="$AMOUNT_MSAT" \
  'BEGIN{ d=(a-b)*1000; if (d==amt) exit 0; else exit 1 }' \
  && ok "credited exactly $AMOUNT_MSAT msat, once" \
  || die "balance moved by $(awk -v a="$AFTER" -v b="$BEFORE" 'BEGIN{print (a-b)*1000}') msat, expected $AMOUNT_MSAT"

say "9. the receipt is readable back off the relay"
# Polled, because zaptool returns at end-of-stored-events rather than waiting out
# a window: a single read could land before the receipt is published. The waiting
# lives here now, in the unit this script thinks in.
RECEIPTS=""
for _ in $(seq 1 15); do
  RECEIPTS=$("$ZT" receipts "$RELAY_HOST" 10 2>/dev/null || true)
  [ -n "$RECEIPTS" ] && break
  sleep 2
done
[ -n "$RECEIPTS" ] || die "no kind-9735 readable on $RELAY_HOST"
MATCH=$(echo "$RECEIPTS" | jq -c --arg pr "$PR" 'select(.kind==9735) | select([.tags[]|select(.[0]=="bolt11")|.[1]]|index($pr))' | head -1)
[ -n "$MATCH" ] || die "a kind-9735 was readable but none carried this invoice"
ok "kind 9735 id $(echo "$MATCH" | jq -r .id | cut -c1-16)…"
RDESC=$(echo "$MATCH" | jq -r '[.tags[]|select(.[0]=="description")|.[1]][0]')
RHASH=$(printf '%s' "$RDESC" | shasum -a 256 | cut -d' ' -f1)
[ "$RHASH" = "$DHASH" ] \
  && ok "receipt description hashes to the invoice's description_hash" \
  || die "receipt description hash $RHASH != invoice description_hash $DHASH"

printf '\n\033[32mSMOKE PASSED\033[0m — stack proven: invoice minted, paid, credited once, receipt read back.\n\n'
