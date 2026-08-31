#!/usr/bin/env bash
# o34.7 — every end-to-end criterion smoke.sh does NOT cover, as a script that
# exits non-zero on failure, so the stack can re-prove the product without a
# human (criterion 11).
#
# smoke.sh is the skeleton: mint, pay, credit once, receipt readable back. This
# adds the receipt shapes, the LUD-12 comment round trip, the settle time, the
# relay-down retry across a server restart, the websocket eviction, the
# settle_index resume, and the replay.
#
# Run smoke.sh first, or not — this is self-contained and does not depend on it.
#
#   ./e2e.sh              everything
#   ./e2e.sh 3 4 5        only those criteria
#
# Criteria run in a deliberate order and the last one REWINDS the resume point,
# so a partial run is fine but a re-ordered one may not be.
set -euo pipefail
cd "$(dirname "$0")"

APP="http://localhost:${APP_PORT:-8080}"
RELAY_HOST="ws://localhost:${RELAY_PORT:-7777}"
RELAY_APP="ws://relay:7777"
# See smoke.sh: a zap request cannot name a single-label host, because the app
# refuses to dial anything a stranger names that looks local. The receipt
# reaches our relay through the operator-configured default set instead, which
# is the path an operator actually relies on.
RELAY_ADVERTISED="${RELAY_ADVERTISED:-wss://relay.invalid}"
NAME="${ADDRESS_NAME:-test}"
PASS="${ADMIN_PASSWORD:-regtest-admin}"
AMOUNT_MSAT="${AMOUNT_MSAT:-21000}"

JAR=$(mktemp)
WORK=$(mktemp -d)
ZT="$WORK/zaptool"
# Several criteria deliberately stop the relay or the server. If an assertion
# fires between the stop and the start, the stack is left broken for the next
# run — and the next run then fails for a reason that has nothing to do with
# what it is testing. Put everything back on the way out, whatever happened.
cleanup() {
  local code=$?
  rm -rf "$JAR" "$WORK"
  if [ "$code" -ne 0 ]; then
    printf '   \033[90m..\033[0m   restarting anything this run had stopped\n' >&2
    docker compose start brollyzapper relay relay2 >/dev/null 2>&1 || true
  fi
  return $code
}
trap cleanup EXIT

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
sub()  { printf '\033[1m   -- %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m   %s\n' "$*"; }
note() { printf '   \033[90m..\033[0m   %s\n' "$*"; }
die()  { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

csrf() { grep -o 'name="csrf_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//'; }
lncli_payer() { docker compose exec -T lnd-payer lncli --network=regtest "$@"; }
lncli_recv()  { docker compose exec -T lnd lncli --network=regtest "$@"; }

# ---------------------------------------------------------------------------
# The server's database.
#
# The server image is distroless and has no shell — deliberately, it is all the
# attack surface. So SQL goes through a throwaway sqlite container on the same
# named volume (tools/sqlite). Read-only by default; sqlw is for the ONE write
# this file makes, the settle_index rewind in criterion 1, and the server must
# be stopped for it.
# ---------------------------------------------------------------------------
DBVOL="${DBVOL:-brollyregtest_server-data}"
sql()  { docker run --rm -v "$DBVOL:/data" brollyregtest-sqlite -readonly /data/brollyzapper.db "$@"; }
sqlw() { docker run --rm -v "$DBVOL:/data" brollyregtest-sqlite /data/brollyzapper.db "$@"; }

balance_msat() { sql "SELECT COALESCE(SUM(amount_msat),0) FROM balance_entries;"; }
txn_count()    { sql "SELECT COUNT(*) FROM txns WHERE payment_hash='$1';"; }
abandoned()    { sql "SELECT COUNT(*) FROM audit_events WHERE event='zap.receipt.abandoned';"; }

# audit_events_since <epoch> — how many audit rows this run has produced.
#
# The control for every "X has NOT fired" assertion below. Counting a row that
# stays at zero proves nothing if the table is inert, the Auditor is never
# called, or the event name is misspelled — and this project has had exactly
# that: "the Auditor went uncalled for three waves and audit_events was empty in
# practice while every component's tests passed."
audit_events_since() { sql "SELECT COUNT(*) FROM audit_events WHERE created_at >= $1;"; }
pending_rows() { sql "SELECT COUNT(*) FROM pending_zap_receipts WHERE payment_hash='$1';"; }
receipt_id()   { sql "SELECT COALESCE(zap_receipt_id,'') FROM txns WHERE payment_hash='$1';"; }
settle_index() { sql "SELECT value FROM settings WHERE key='last_settle_index';"; }

# How many times the server logged a COMPLETED credit for this payment hash.
#
# main.go logs "invoice settled" only when CreditInvoice reports that THIS call
# was the one that credited. So the count is the number of times the settlement
# actually took effect — which is what separates "the replay was handled as a
# no-op" from "the replay never arrived", and those two look identical in the
# database.
# The hash is matched on its first 8 characters because that is all §12 lets
# into a log line: logging.PaymentHash truncates it. Eight hex digits over the
# handful of invoices one run mints is not a collision worth guarding.
settled_logs() {
  docker compose logs brollyzapper 2>&1 \
    | grep -c "\"msg\":\"invoice settled\",\"payment_hash\":\"${1:0:8}\"" || true
}

# Established websockets from the server to a relay container. The server has no
# shell, so this joins its network namespace from a sidecar rather than exec'ing
# in — which is also the only way to see the sockets as the server has them.
conns_to() {
  local srv ip
  srv=$(docker compose ps -q brollyzapper)
  ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(docker compose ps -q "$1")")
  docker run --rm --net="container:$srv" alpine:3.20 netstat -tn 2>/dev/null \
    | grep -c "$ip:7777.*ESTABLISHED" || true
}

# relay2_connects counts the connections strfry ACCEPTED from one address.
#
# Counted at the relay rather than sampled with netstat, and that is the whole
# point. The first version of this criterion polled `netstat` four times a
# second and reported "0 sockets across 10 samples" while the planted build was
# busy dialling relay2 and delivering a receipt to it — a transient publish
# socket lives well under 250ms, so the sampler simply looked between the frames.
# It asserted an absence it could not have observed. strfry logs every accepted
# connection, so this counts what happened rather than what we caught happening.
relay2_connects() {
  docker compose logs relay2 2>&1 | grep -c "Connect from $1" || true
}

# app_log_count counts the app's log lines matching a pattern.
#
# Every caller takes a reading BEFORE and AFTER rather than filtering by time,
# and that is not a style choice: `docker compose logs --since` reads a bare
# timestamp as LOCAL time and silently matches nothing, which is the trap
# recorded in regtest/README.md. Written once here so the reason is too.
app_log_count() { docker compose logs brollyzapper 2>&1 | grep -c "$1" || true; }

# stream_drops counts the times the invoice subscription has dropped.
stream_drops() { app_log_count '"msg":"invoice stream dropped; reconnecting"'; }

# refused_lines counts the publishes whose INFO line named the sender-named
# relay in `refused`.
refused_lines() { app_log_count '"msg":"relays chosen for this publish".*relay2\.zap\.test'; }

wait_health() {
  local i
  for i in $(seq 1 90); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$APP/health" || true)" = "200" ] && return 0
    sleep 1
  done
  die "$APP/health never returned 200"
}

login() {
  local tok
  tok=$(curl -s -c "$JAR" "$APP/login" | csrf)
  curl -s -b "$JAR" -c "$JAR" -X POST "$APP/login" \
    --data-urlencode "csrf_token=$tok" --data-urlencode "password=$PASS" -o /dev/null
}

configure() {
  local tok
  tok=$(curl -s -b "$JAR" "$APP/settings" | csrf)
  curl -s -b "$JAR" -c "$JAR" -X POST "$APP/settings" \
    --data-urlencode "csrf_token=$tok" \
    --data-urlencode "domain=$APP" \
    --data-urlencode "address_name=$NAME" \
    --data-urlencode "default_relays=$RELAY_APP" \
    --data-urlencode "trusted_proxies=" \
    --data-urlencode "public_rate_limit_per_min=600" \
    --data-urlencode "public_rate_limit_per_hour=6000" \
    --data-urlencode "max_fee_ppm=10000" --data-urlencode "max_fee_floor_msat=10000" \
    --data-urlencode "log_level=INFO" --data-urlencode "credit_received=on" -o /dev/null
}

wallet_html() { curl -s -b "$JAR" "$APP/"; }

# wallet_row <marker> — the one transaction-history row containing marker.
#
# Scoped rather than counted. Counting occurrences of a CSS class across the
# whole history makes an assertion depend on the outcome of every earlier
# criterion, and on nothing being left over from a previous run.
wallet_row() {
  wallet_html | tr -d '\n' | sed 's|<tr>|\
<tr>|g' | grep -F "$1" | head -1
}

# mint <zap-request-json> [comment] -> prints the bolt11
mint() {
  local zapreq="$1" comment="${2:-}" callback out pr
  callback=$(curl -s "$APP/.well-known/lnurlp/$NAME" | jq -r .callback)
  if [ -n "$comment" ]; then
    out=$(curl -s -G "$callback" --data-urlencode "amount=$AMOUNT_MSAT" \
            --data-urlencode "nostr=$zapreq" --data-urlencode "comment=$comment")
  else
    out=$(curl -s -G "$callback" --data-urlencode "amount=$AMOUNT_MSAT" \
            --data-urlencode "nostr=$zapreq")
  fi
  pr=$(echo "$out" | jq -r '.pr // empty')
  [ -n "$pr" ] || die "no invoice minted: $out"
  echo "$pr"
}

payment_hash_of() { lncli_recv decodepayreq --pay_req "$1" | jq -r .payment_hash; }

# pay_and_settle <bolt11> <payment_hash>
pay_and_settle() {
  local pr="$1" ph="$2" state="" i
  lncli_payer payinvoice --force --pay_req "$pr" --timeout 60s >/dev/null 2>&1 || true
  for i in $(seq 1 30); do
    state=$(lncli_recv lookupinvoice --rhash "$ph" | jq -r .state)
    [ "$state" = "SETTLED" ] && return 0
    sleep 1
  done
  die "invoice $ph never settled (state=$state)"
}

# wait_credit <payment_hash> — the server has seen the settlement and written it
wait_credit() {
  local i
  for i in $(seq 1 40); do
    [ "$(txn_count "$1")" = "1" ] && return 0
    sleep 1
  done
  die "the server never recorded a txn for $1"
}

# wait_receipt <bolt11> [seconds] [relay] — the kind-9735 carrying that invoice.
#
# One function, one knob. zaptool returns at end-of-stored-events now — about a
# second — so THIS loop is the waiting, and the timeout is stated once in the
# unit the caller thinks in. The previous shape had a window inside zaptool and
# a try count outside it, which multiplied into an unstated timeout and, because
# the window doubled as the sleep, burned it in full on every poll even when the
# receipt was already there.
#
# The waiting policy belongs here rather than in the tool: only the caller knows
# what it is waiting for. A fresh publish lands in about a second; a receipt
# queued while the relay was down waits on zapRetryInterval, which is 30s.
wait_receipt() {
  local pr="$1" secs="${2:-45}" relay="${3:-$RELAY_HOST}" waited=0 got
  while [ "$waited" -lt "$secs" ]; do
    got=$("$ZT" receipts "$relay" 10 2>/dev/null \
          | jq -c --arg pr "$pr" 'select(.kind==9735) | select([.tags[]|select(.[0]=="bolt11")|.[1]]|index($pr))' \
          | head -1)
    [ -n "$got" ] && { echo "$got"; return 0; }
    sleep 2
    waited=$((waited + 3))
  done
  return 1
}

tag_value() { jq -r --arg t "$2" '[.tags[]|select(.[0]==$t)|.[1]][0] // ""' <<<"$1"; }
has_tag()   { jq -e --arg t "$2" 'any(.tags[]; .[0]==$t)' >/dev/null <<<"$1"; }

server_started_at() {
  docker inspect -f '{{.State.StartedAt}}' "$(docker compose ps -q brollyzapper)"
}

# restart_server asserts the restart HAPPENED.
#
# Without this, criterion 2 passes unchanged if the restart silently does not
# occur — three settlements credit three times whether or not the stream was
# ever torn down, and the resume path, which is the whole point, goes untested.
restart_server() {
  local before after
  before=$(server_started_at)
  docker compose restart brollyzapper >/dev/null
  wait_health
  after=$(server_started_at)
  [ "$after" != "$before" ] \
    || die "the server did not actually restart (StartedAt is still $before); the resume path was not exercised"
  login
}

# ---------------------------------------------------------------------------
# Stamped before anything this script does, so the audit control below has the
# whole run to find a row in — the login two steps down writes an auth.ok, which
# is the cheapest proof the table is live.
RUN_EPOCH=$(date -u +%s)

say "0. setup"
( cd tools/zaptool && go build -o "$ZT" . ) || die "could not build tools/zaptool"
ok "zaptool built"
docker build -q -t brollyregtest-sqlite tools/sqlite >/dev/null || die "could not build tools/sqlite"
ok "sqlite helper built"
wait_health
ok "/health 200"
login
configure
RECIPIENT=$(curl -s "$APP/.well-known/lnurlp/$NAME" | jq -r .nostrPubkey)
[ "${#RECIPIENT}" = 64 ] || die "no nostrPubkey announced"
# The identifier as SERVED, not as configured: o34.13 stores the domain bare and
# a lightning address never carries a scheme, so "$NAME@$APP" printed an address
# that does not exist.
ok "address $(curl -s "$APP/.well-known/lnurlp/$NAME" | jq -r '.metadata|fromjson|.[]|select(.[0]=="text/identifier")|.[1]') -> relay $RELAY_APP, recipient ${RECIPIENT:0:16}…"

# Which criteria to run. A STRING, not an array: macOS ships bash 3.2, where
# ${#arr[@]} on an empty array is an unbound-variable error under set -u.
WANT=" $* "
run() {
  [ "$WANT" = "  " ] && return 0
  case "$WANT" in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

# ===========================================================================
# 3. A PROFILE zap — no e tag, no a tag. The prior art nil-derefs here.
# ===========================================================================
if run 3; then
say "3. profile zap: a receipt with p and P, and no e and no a"
ZR=$("$ZT" request "$RELAY_ADVERTISED" "$RECIPIENT" "$AMOUNT_MSAT" -content "profile zap")
has_tag "$ZR" e && die "the request under test must have no e tag"
PR=$(mint "$ZR"); PH=$(payment_hash_of "$PR")
pay_and_settle "$PR" "$PH"; wait_credit "$PH"
R=$(wait_receipt "$PR") || die "no receipt for the profile zap"
ok "receipt $(jq -r .id <<<"$R" | cut -c1-16)…"
has_tag "$R" p || die "the receipt has no p tag"
has_tag "$R" P || die "the receipt has no P tag (the zap request's sender)"
has_tag "$R" e && die "a PROFILE zap's receipt must not carry an e tag"
has_tag "$R" a && die "a PROFILE zap's receipt must not carry an a tag"
ok "tags: $(jq -r '[.tags[][0]]|join(" ")' <<<"$R")"
echo "$R" | "$ZT" verify >/dev/null || die "the receipt does not verify"
# The control. Without it, "verify said nothing" and "verify was not checking"
# look identical — the exact shape §16 keeps finding, and client-check.sh
# already applies this rule to nak.
echo "$R" | jq -c '.sig = (if (.sig|startswith("b")) then "c" else "b" end) + (.sig[1:])' \
  | "$ZT" verify >/dev/null 2>&1 \
  && die "verify ACCEPTED a receipt with a corrupted signature; this check proves nothing"
ok "id re-derives and the signature checks — and a one-byte-flipped copy is rejected"
fi

# ===========================================================================
# 4. An event zap and an addressable zap carry their tag verbatim.
# ===========================================================================
if run 4; then
say "4. event zap and addressable zap carry e and a verbatim"
EVENT_ID=$(head -c 32 /dev/urandom | xxd -p -c 64)
sub "an e tag"
ZR=$("$ZT" request "$RELAY_ADVERTISED" "$RECIPIENT" "$AMOUNT_MSAT" -e "$EVENT_ID")
PR=$(mint "$ZR"); PH=$(payment_hash_of "$PR")
pay_and_settle "$PR" "$PH"; wait_credit "$PH"
R=$(wait_receipt "$PR") || die "no receipt for the event zap"
GOT=$(tag_value "$R" e)
[ "$GOT" = "$EVENT_ID" ] || die "receipt e tag $GOT != request's $EVENT_ID"
ok "e $GOT carried verbatim"
has_tag "$R" a && die "an event zap's receipt must not invent an a tag"

sub "a k tag alongside the e tag"
# o34.20. NIP-57 Appendix A lists k on the request and Appendix E's own example
# receipt carries one; we used to copy e and a and drop k.
ZR=$("$ZT" request "$RELAY_ADVERTISED" "$RECIPIENT" "$AMOUNT_MSAT" -e "$EVENT_ID" -k 1)
PR=$(mint "$ZR"); PH=$(payment_hash_of "$PR")
pay_and_settle "$PR" "$PH"; wait_credit "$PH"
R=$(wait_receipt "$PR") || die "no receipt for the k-tagged zap"
GOT=$(tag_value "$R" k)
[ "$GOT" = "1" ] || die "receipt k tag is \"$GOT\", want the request's \"1\""
ok "k $GOT carried verbatim"

sub "an a tag"
COORD="30023:$RECIPIENT:regtest-e2e"
ZR=$("$ZT" request "$RELAY_ADVERTISED" "$RECIPIENT" "$AMOUNT_MSAT" -a "$COORD")
PR=$(mint "$ZR"); PH=$(payment_hash_of "$PR")
pay_and_settle "$PR" "$PH"; wait_credit "$PH"
R=$(wait_receipt "$PR") || die "no receipt for the addressable zap"
GOT=$(tag_value "$R" a)
[ "$GOT" = "$COORD" ] || die "receipt a tag $GOT != request's $COORD"
ok "a $GOT carried verbatim"
fi

# ===========================================================================
# 5. A LUD-12 comment round-trips, and does NOT change the description hash.
# ===========================================================================
if run 5; then
say "5. the LUD-12 comment round trip, and the hash it must not touch"
COMMENT="thanks for the regtest sats — o34.7"
ZR=$("$ZT" request "$RELAY_ADVERTISED" "$RECIPIENT" "$AMOUNT_MSAT" -content "commented zap")
PR=$(mint "$ZR" "$COMMENT"); PH=$(payment_hash_of "$PR")
STORED=$(sql "SELECT COALESCE(comment,'') FROM invoices WHERE payment_hash='$PH';")
[ "$STORED" = "$COMMENT" ] || die "invoice comment is \"$STORED\", want \"$COMMENT\""
ok "stored on the invoice"

sub "the description hash is identical with and without a comment"
# Same zap request, minted twice — once with a comment and once without. For a
# ZAP the description_hash is sha256 of the zap request, which the comment is
# deliberately not part of: folding it in would change a hash the wallet has
# already committed to (o34.12).
PR2=$(mint "$ZR"); PH2=$(payment_hash_of "$PR2")
H1=$(sql "SELECT description_hash FROM invoices WHERE payment_hash='$PH';")
H2=$(sql "SELECT description_hash FROM invoices WHERE payment_hash='$PH2';")
# Anchored, not just compared to each other. Two empty strings are equal, and so
# are two hashes of the WRONG bytes — a regression that hashed the LUD-06
# metadata on the zap path would keep H1 == H2 and leave this green, while every
# receipt became unverifiable. The invoice is the anchor: it is the hash the
# paying wallet has already committed to.
INV_HASH=$(lncli_recv decodepayreq --pay_req "$PR" | jq -r .description_hash)
WANT_HASH=$(printf '%s' "$ZR" | shasum -a 256 | cut -d' ' -f1)
[ -n "$H1" ] || die "no description_hash stored for $PH"
[ "$H1" = "$INV_HASH" ] || die "the stored description_hash $H1 is not the invoice's $INV_HASH"
[ "$H1" = "$WANT_HASH" ] \
  || die "description_hash $H1 is not sha256 of the zap request ($WANT_HASH) — the wrong bytes were hashed"
ok "description_hash $H1 == the invoice's == sha256(zap request)"
[ "$H1" = "$H2" ] || die "zap description_hash differs with a comment: $H1 vs $H2"
ok "unchanged by the comment"

# And the PLAIN payment, which is the path o34.12's ruling is actually about:
# there the hash is sha256 of the LUD-06 METADATA, and folding a comment in
# would change a hash the wallet has already committed to.
CB=$(curl -s "$APP/.well-known/lnurlp/$NAME" | jq -r .callback)
P1=$(curl -s -G "$CB" --data-urlencode "amount=$AMOUNT_MSAT" | jq -r .pr)
P2=$(curl -s -G "$CB" --data-urlencode "amount=$AMOUNT_MSAT" --data-urlencode "comment=$COMMENT" | jq -r .pr)
[ -n "$P1" ] && [ -n "$P2" ] || die "a plain (non-zap) payment could not be minted"
M1=$(sql "SELECT description_hash FROM invoices WHERE payment_hash='$(payment_hash_of "$P1")';")
M2=$(sql "SELECT description_hash FROM invoices WHERE payment_hash='$(payment_hash_of "$P2")';")
[ "$M1" = "$M2" ] \
  && ok "metadata description_hash $M1 — unchanged by the comment" \
  || die "metadata description_hash differs with a comment: $M1 vs $M2 — the comment was folded into the metadata"

pay_and_settle "$PR" "$PH"; wait_credit "$PH"
TXNC=$(sql "SELECT COALESCE(comment,'') FROM txns WHERE payment_hash='$PH';")
[ "$TXNC" = "$COMMENT" ] || die "txn comment is \"$TXNC\", want \"$COMMENT\""
ok "carried to the txn at settlement"
# grep -cF, not grep -qF, and this line is why the distinction is worth a
# comment. `-q` exits at the first match, curl takes SIGPIPE with the rest of the
# page still unwritten, and `set -o pipefail` then reports FAILURE FOR A MATCH
# THAT WAS FOUND. It passed for months because the whole page fitted in the 64 kB
# pipe buffer; wave 27 lengthened the transaction history and it began failing
# intermittently, with a message saying the opposite of what was true. `-c` reads
# its input to the end.
[ "$(wallet_html | grep -cF "$COMMENT" || true)" != "0" ]   || die "the comment is not in the Wallet transaction history"
ok "visible in the Wallet transaction history"
fi

# ===========================================================================
# 6. created_at is the SETTLE time LND reports, not the publish time.
# ===========================================================================
if run 6; then
say "6. the receipt's created_at is LND's settle_date"
# THE GAP IS THE TEST (o34.21).
#
# Settling while the server is running proves nothing: it handles the settlement
# in the same second LND settles it, so the node's time and the handler's clock
# agree and the assertion passes either way. It did, for four waves. So the
# invoice is settled with the server STOPPED and delivered afterwards by the
# settle_index resume path — which is a plain restart, not an exotic case — and
# the two times can then only agree if the node's is the one being used.
ZR=$("$ZT" request "$RELAY_ADVERTISED" "$RECIPIENT" "$AMOUNT_MSAT" -content "settle time")
PR=$(mint "$ZR"); PH=$(payment_hash_of "$PR")

docker compose stop brollyzapper >/dev/null
ok "server stopped — LND is about to settle an invoice nobody is listening for"
# pay_and_settle talks only to the two nodes, so it works with the server down.
pay_and_settle "$PR" "$PH"
SETTLE=$(lncli_recv lookupinvoice --rhash "$PH" | jq -r .settle_date)
[ "$SETTLE" -gt 0 ] || die "the invoice settled with no settle_date"
# Long enough that a handler clock and the node's clock cannot round together.
sleep 20
docker compose start brollyzapper >/dev/null
wait_health; login
GAP=$(( $(date -u +%s) - SETTLE ))
ok "settled at $SETTLE, server restarted ${GAP}s later"

wait_credit "$PH"
R=$(wait_receipt "$PR" 90) || die "no receipt after the resume path delivered the settlement"
CREATED=$(jq -r .created_at <<<"$R")
[ "$CREATED" = "$SETTLE" ] \
  && ok "created_at $CREATED == lookupinvoice settle_date $SETTLE, across a ${GAP}s gap" \
  || die "created_at $CREATED != settle_date $SETTLE (out by $(( CREATED - SETTLE ))s) — the receipt says the zap happened when the server noticed, not when it was paid"
fi

# ===========================================================================
# 9. A sender-named relay that resolves onto a private address is refused.
# ===========================================================================
if run 9; then
say "9. a sender-named relay that resolves onto the LAN is refused"
# REWRITTEN 23 Aug 2026 (vz1.1). This used to assert the opposite: that a
# sender-named relay's socket was opened, used, and closed again. z9k now
# resolves every sender-named host and refuses it unless EVERY resolved address
# is public — and relay2.zap.test resolves to a Docker bridge address, as does
# every other name in a compose network. So no sender-named relay can be
# dialled in this stack at all any more, and that is z9k working, not a
# regression.
#
# The Wave 16 brief predicted relay2 would survive "under the configured-relay
# exemption". It is not configured — the zap request names it — so the exemption
# was never in play.
#
# Socket EVICTION, which the old criterion existed for, cannot be exercised here
# and this script no longer claims to: it is asserted in internal/nostr's
# lifecycle tests against a real websocket fleet, where a held publish makes the
# count exact. See regtest/README.md.
RELAY2_ADVERTISED="ws://relay2.zap.test:7777"
RELAY2_HOST="ws://localhost:${RELAY2_PORT:-7778}"
CONFIGURED=1

# Warm the pool first. The configured relay's socket is opened by a publish, so
# a process that has not published yet holds none — and the positive control
# below would then fire on a FRESH container rather than on a broken sidecar,
# which is a confusing way to fail and made `./e2e.sh 9` on its own impossible.
# The script claims to be self-contained; this is what makes that true here.
if [ "$(conns_to relay)" = "0" ]; then
  note "no socket to the configured relay yet — publishing one receipt to open it"
  W_ZR=$("$ZT" request "$RELAY_ADVERTISED" "$RECIPIENT" "$AMOUNT_MSAT" -content "warm the pool")
  W_PR=$(mint "$W_ZR"); W_PH=$(payment_hash_of "$W_PR")
  pay_and_settle "$W_PR" "$W_PH"; wait_credit "$W_PH"
  wait_receipt "$W_PR" 45 "$RELAY_HOST" >/dev/null \
    || die "the warm-up receipt never reached the configured relay"
fi

B_CFG=$(conns_to relay); B_SENDER=$(conns_to relay2)
note "before: $B_CFG to the configured relay, $B_SENDER to the sender-named one"
# The positive control, still load-bearing. conns_to ends in `grep -c … || true`,
# so a sidecar that fails to start yields a count of 0 and a success — which
# would make every "0" assertion below pass having observed nothing at all.
[ "$B_CFG" -ge 1 ] \
  || die "netstat sees 0 sockets to the CONFIGURED relay before the publish — the sidecar is not observing anything, so a 0 later would prove nothing"
[ "$B_SENDER" = "0" ] || die "the sender-named relay already has $B_SENDER sockets before the publish"

REFUSED_BEFORE=$(refused_lines)
SRV_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(docker compose ps -q brollyzapper)")
FROM_SERVER_BEFORE=$(relay2_connects "$SRV_IP")
FROM_ANY_BEFORE=$(relay2_connects "")

ZR=$("$ZT" request "$RELAY2_ADVERTISED" "$RECIPIENT" "$AMOUNT_MSAT" -content "sender-named LAN relay")
PR=$(mint "$ZR"); PH=$(payment_hash_of "$PR")
pay_and_settle "$PR" "$PH"; wait_credit "$PH"

# The receipt still gets published — to the OPERATOR's relay. A refusal that
# also lost the receipt would be a filter that broke the product.
GOT=$(wait_receipt "$PR" 45 "$RELAY_HOST") \
  || die "no receipt on the configured relay; the refusal took the whole publish with it"
ok "the receipt reached the operator's own relay — the refusal cost nothing else"

# And nothing arrived on the sender-named one. Bounded, because this is a
# negative: the receipt that WAS published is already in hand, so anything
# landing here would have to arrive after it.
#
# This probe also connects to relay2 FROM THE HOST, which is the positive
# control for the count below: one counter must move while the other must not.
if wait_receipt "$PR" 6 "$RELAY2_HOST" >/dev/null 2>&1; then
  die "the receipt arrived on the sender-named relay — something dialled it"
fi
ok "no receipt on the sender-named relay"

FROM_SERVER_AFTER=$(relay2_connects "$SRV_IP")
FROM_ANY_AFTER=$(relay2_connects "")
[ "$FROM_ANY_AFTER" -gt "$FROM_ANY_BEFORE" ] \
  || die "relay2 logged no new connection from anyone, not even this script's own receipt probe — it is not recording connections, so the count below would prove nothing"
[ "$FROM_SERVER_AFTER" = "$FROM_SERVER_BEFORE" ] \
  || die "relay2 accepted $((FROM_SERVER_AFTER - FROM_SERVER_BEFORE)) connection(s) from the app at $SRV_IP; a relay that resolves onto the LAN must never be dialled"
ok "relay2 accepted 0 connections from the app, while logging this script's own $((FROM_ANY_AFTER - FROM_ANY_BEFORE)) — the instrument was recording"

# The operator's evidence. Without this line the refusal is invisible: the relay
# is in invoices.zap_relays and simply never gets a receipt, which is the exact
# complaint zmn's logging exists to answer.
REFUSED_AFTER="$REFUSED_BEFORE"
for i in $(seq 1 20); do
  REFUSED_AFTER=$(refused_lines)
  [ "$REFUSED_AFTER" -gt "$REFUSED_BEFORE" ] && break
  sleep 1
done
[ "$REFUSED_AFTER" -gt "$REFUSED_BEFORE" ] \
  || die "the publish log line does not name relay2.zap.test in refused ($REFUSED_BEFORE -> $REFUSED_AFTER); an operator would have nothing to find"
ok "the pool's INFO line names it in refused — at the default log level"

A_CFG=$(conns_to relay)
[ "$A_CFG" = "$CONFIGURED" ] \
  && ok "the configured relay still has $A_CFG — the refusal did not touch the operator's own" \
  || die "the configured relay has $A_CFG sockets, want $CONFIGURED"
fi

# ===========================================================================
# 12. A neighbour's payment on the shared node is skipped, not fatal.
#
# Numbered 12, not 11: o34.7's criterion 11 is "runs without a human", which is
# this whole script, and 10 is the manual client check. This section belongs to
# vz1.8 rather than to o34.7 and takes the next free number.
# ===========================================================================
if run 12; then
say "12. an invoice this app did not create is skipped, and the stream survives"
# vz1.8, from the 0.1.7 box trip. Umbrel is a deliberately shared node — BTCPay,
# Alby Hub and LNDg all receive on the same LND — so a settlement for an invoice
# this app never minted is the NORMAL case there. It used to drop the
# subscription and force a reconnect that re-reads the credential and walks the
# resume path; the box saw it once in a quiet hour, and on a busy node it is
# continuous.
#
# The foreign invoice is minted with lncli DIRECTLY on the node, which is the
# only way to produce a settlement the app has no row for. It is paid BETWEEN
# two app-minted ones so the assertion is not merely "nothing broke" but "the
# two either side of it still credited".
DROPS_BEFORE=$(stream_drops)
IDX_BEFORE=$(settle_index)
note "before: settle_index $IDX_BEFORE, $DROPS_BEFORE stream drops"

ZR=$("$ZT" request "$RELAY_ADVERTISED" "$RECIPIENT" "$AMOUNT_MSAT" -content "before the neighbour")
PR_A=$(mint "$ZR"); PH_A=$(payment_hash_of "$PR_A")
pay_and_settle "$PR_A" "$PH_A"; wait_credit "$PH_A"
ok "the first app invoice credited"

# The neighbour. Not through the app: no callback, no invoices row, nothing this
# app has ever heard of.
FOREIGN=$(lncli_recv addinvoice --amt_msat 221000 --memo "another app on this node")
FOREIGN_PR=$(jq -r .payment_request <<<"$FOREIGN")
FOREIGN_PH=$(jq -r .r_hash <<<"$FOREIGN")
# Both halves, because an empty hash would make every "the app has no row for
# it" assertion below pass having looked up nothing.
[ -n "$FOREIGN_PR" ] && [ -n "$FOREIGN_PH" ] \
  || die "lncli did not mint the foreign invoice: $FOREIGN"
pay_and_settle "$FOREIGN_PR" "$FOREIGN_PH"
ok "a 221-sat invoice minted by lncli directly was paid and settled on the node"

ZR=$("$ZT" request "$RELAY_ADVERTISED" "$RECIPIENT" "$AMOUNT_MSAT" -content "after the neighbour")
PR_B=$(mint "$ZR"); PH_B=$(payment_hash_of "$PR_B")
pay_and_settle "$PR_B" "$PH_B"; wait_credit "$PH_B"
ok "the second app invoice credited — the settlement after the neighbour's was handled"

# The app must never have recorded the neighbour's money.
[ "$(txn_count "$FOREIGN_PH")" = "0" ] \
  || die "the app credited an invoice it did not mint"
ok "no txn for the neighbour's invoice — it was skipped, not credited"

# The resume point is past ALL THREE, so the skip advanced it rather than
# leaving the stream to re-read the same settlement forever.
FOREIGN_IDX=$(lncli_recv lookupinvoice --rhash "$FOREIGN_PH" | jq -r .settle_index)
IDX_AFTER=$(settle_index)
[ "$IDX_AFTER" -gt "$FOREIGN_IDX" ] \
  || die "the resume point is $IDX_AFTER, not past the neighbour's settle_index $FOREIGN_IDX — the skip did not advance it"
ok "resume point $IDX_BEFORE -> $IDX_AFTER, past the neighbour's index $FOREIGN_IDX"

DROPS_AFTER=$(stream_drops)
[ "$DROPS_AFTER" = "$DROPS_BEFORE" ] \
  || die "the invoice stream dropped $((DROPS_AFTER - DROPS_BEFORE)) time(s) across the neighbour's payment; on a shared node that is every neighbour, continuously"
ok "the stream never dropped ($DROPS_AFTER, unchanged)"
fi

# ===========================================================================
# 7. Relay down: credited, PENDING, queued, not abandoned. Relay up: published.
# ===========================================================================
if run 7; then
say "7. relay down, then up — the persisted retry"
ABANDONED_BEFORE=$(abandoned)
docker compose stop relay >/dev/null
ok "relay stopped"
ZR=$("$ZT" request "$RELAY_ADVERTISED" "$RECIPIENT" "$AMOUNT_MSAT" -content "relay down")
# A marker unique to this zap, carried as the LUD-12 comment, so the Wallet row
# can be found by identity rather than by counting rows.
MARK="relay-down-$(date -u +%s)"
PR=$(mint "$ZR" "$MARK"); PH=$(payment_hash_of "$PR")
pay_and_settle "$PR" "$PH"; wait_credit "$PH"
ok "settled and credited with no relay to publish to"
for i in $(seq 1 20); do [ "$(pending_rows "$PH")" = "1" ] && break; sleep 1; done
[ "$(pending_rows "$PH")" = "1" ] || die "no pending_zap_receipts row for $PH"
ok "pending_zap_receipts row exists"
[ "$(receipt_id "$PH")" = "" ] || die "a zap_receipt_id was recorded with the relay down"
# Scoped to THIS zap by its comment, not counted across the whole history: a
# count depends on the outcome of every earlier criterion and on nothing being
# left over from a previous run, so it fails for reasons that have nothing to do
# with what it tests. The row is found by the LUD-12 comment, which the template
# renders in the same cell as the receipt state.
PENDING_ROW=$(wallet_row "$MARK")
[ -n "$PENDING_ROW" ] || die "no Wallet history row carries this zap's marker $MARK"
echo "$PENDING_ROW" | grep -q 'receipt-pending' \
  || die "the Wallet row for this zap does not show the receipt as pending"
ok "the Wallet history shows THIS zap PENDING"
[ "$(abandoned)" = "$ABANDONED_BEFORE" ] \
  || die "zap.receipt.abandoned fired while the retry window was still open"
# …and the table is demonstrably live, so that flat count means something. The
# login at step 0 alone writes an auth.ok row.
LIVE=$(audit_events_since "$RUN_EPOCH")
[ "$LIVE" -ge 1 ] \
  || die "audit_events has gained 0 rows this run, so 'abandoned did not fire' is a statement about an inert table, not about the retry"
ok "zap.receipt.abandoned has NOT fired ($ABANDONED_BEFORE, unchanged) — and audit_events took $LIVE other rows this run, so the count is live"

docker compose start relay >/dev/null
ok "relay started"
R=$(wait_receipt "$PR" 90) || die "the receipt never arrived after the relay came back"
ok "receipt $(jq -r .id <<<"$R" | cut -c1-16)… arrived"
for i in $(seq 1 30); do [ "$(pending_rows "$PH")" = "0" ] && break; sleep 1; done
[ "$(pending_rows "$PH")" = "0" ] || die "the pending_zap_receipts row was not cleared"
ok "the pending row is gone"
RID=$(receipt_id "$PH")
[ -n "$RID" ] || die "no zap_receipt_id recorded on the txn"
[ "$RID" = "$(jq -r .id <<<"$R")" ] || die "recorded id $RID != the receipt on the relay"
PUBLISHED_ROW=$(wallet_row "$MARK")
echo "$PUBLISHED_ROW" | grep -qF "receipt published ${RID:0:8}" \
  && ok "the Wallet row for THIS zap shows PUBLISHED ${RID:0:8}" \
  || die "the Wallet row for this zap does not show the published receipt id"
fi

# ===========================================================================
# 8. The same, but the SERVER restarts while the relay is down. The retry must
#    resume from the store, not from memory.
# ===========================================================================
if run 8; then
say "8. relay down + SERVER RESTART — the retry resumes from the store"
ABANDONED_BEFORE=$(abandoned)
docker compose stop relay >/dev/null
ok "relay stopped"
ZR=$("$ZT" request "$RELAY_ADVERTISED" "$RECIPIENT" "$AMOUNT_MSAT" -content "restart while queued")
PR=$(mint "$ZR"); PH=$(payment_hash_of "$PR")
pay_and_settle "$PR" "$PH"; wait_credit "$PH"
for i in $(seq 1 20); do [ "$(pending_rows "$PH")" = "1" ] && break; sleep 1; done
[ "$(pending_rows "$PH")" = "1" ] || die "no pending_zap_receipts row to survive the restart"
ok "queued: pending_zap_receipts row exists"

restart_server
ok "server restarted — anything held only in memory is gone"
[ "$(pending_rows "$PH")" = "1" ] || die "the pending row did not survive the restart"
[ "$(receipt_id "$PH")" = "" ] || die "a receipt id appeared with the relay still down"

docker compose start relay >/dev/null
ok "relay started"
R=$(wait_receipt "$PR" 90) \
  || die "the receipt never arrived — the retry did not resume from the store, which is §7's 'reads as theft'"
ok "receipt $(jq -r .id <<<"$R" | cut -c1-16)… arrived AFTER a restart it had to survive"
for i in $(seq 1 30); do [ "$(pending_rows "$PH")" = "0" ] && break; sleep 1; done
[ "$(pending_rows "$PH")" = "0" ] || die "the pending row was not cleared"
[ -n "$(receipt_id "$PH")" ] || die "no zap_receipt_id recorded"
ok "the pending row is gone and the txn carries the id"
[ "$(abandoned)" = "$ABANDONED_BEFORE" ] || die "zap.receipt.abandoned fired during the window"
LIVE=$(audit_events_since "$RUN_EPOCH")
[ "$LIVE" -ge 1 ] \
  || die "audit_events gained 0 rows this run; the flat abandoned count says nothing"
ok "zap.receipt.abandoned still has not fired (audit_events is live: $LIVE rows this run)"
fi

# ===========================================================================
# 2. settle_index resume across a restart: three settlements, exactly three
#    credits, restart between the second and the third. The §6 off-by-one.
# ===========================================================================
if run 2; then
say "2. settle_index resume across a restart — three settled, three credited"
PRS=(); PHS=()
for n in 1 2 3; do
  ZR=$("$ZT" request "$RELAY_ADVERTISED" "$RECIPIENT" "$AMOUNT_MSAT" -content "resume $n")
  P=$(mint "$ZR"); PRS+=("$P"); PHS+=("$(payment_hash_of "$P")")
done
ok "three invoices minted"
BAL0=$(balance_msat)
IDX0=$(settle_index)

pay_and_settle "${PRS[0]}" "${PHS[0]}"; wait_credit "${PHS[0]}"
pay_and_settle "${PRS[1]}" "${PHS[1]}"; wait_credit "${PHS[1]}"
ok "two settled and credited (settle_index now $(settle_index))"

restart_server
ok "server restarted between the second and the third"

pay_and_settle "${PRS[2]}" "${PHS[2]}"; wait_credit "${PHS[2]}"
ok "the third settled after the restart and was credited"

for n in 0 1 2; do
  C=$(txn_count "${PHS[$n]}")
  [ "$C" = "1" ] || die "payment ${PHS[$n]} has $C txns rows, want exactly 1"
done
ok "exactly one txns row each — no gap, no double"
BAL1=$(balance_msat)
WANTED=$((BAL0 + 3 * AMOUNT_MSAT))
[ "$BAL1" = "$WANTED" ] \
  && ok "balance $BAL0 -> $BAL1 msat = exactly 3 x $AMOUNT_MSAT" \
  || die "balance $BAL0 -> $BAL1 msat, want $WANTED — a settlement was skipped or doubled"
note "settle_index $IDX0 -> $(settle_index)"
REPLAY_PR="${PRS[2]}"; REPLAY_PH="${PHS[2]}"
fi

# ===========================================================================
# 1. THE REPLAY (d46.13 criterion 7, carried since the P1 box trip).
#
#    Rewind the resume point below the last settlement and restart, so LND
#    re-delivers a settlement the server has already handled. The UNIQUE
#    constraint on txns.payment_hash is the mechanism; this proves the
#    settlement code actually takes that path against a real node.
# ===========================================================================
if run 1; then
say "1. a re-delivered settlement is a no-op"
if [ -z "${REPLAY_PH:-}" ]; then
  ZR=$("$ZT" request "$RELAY_ADVERTISED" "$RECIPIENT" "$AMOUNT_MSAT" -content "replay")
  REPLAY_PR=$(mint "$ZR"); REPLAY_PH=$(payment_hash_of "$REPLAY_PR")
  pay_and_settle "$REPLAY_PR" "$REPLAY_PH"; wait_credit "$REPLAY_PH"
fi
IDX=$(settle_index)
SETTLE_IDX=$(lncli_recv lookupinvoice --rhash "$REPLAY_PH" | jq -r .settle_index)
ok "the target settled at settle_index $SETTLE_IDX; the resume point is $IDX"
BAL0=$(balance_msat)
ENTRIES0=$(sql "SELECT COUNT(*) FROM balance_entries;")
LOGS0=$(settled_logs "$REPLAY_PH")
[ "$(txn_count "$REPLAY_PH")" = "1" ] || die "the target does not have exactly one txn to begin with"
[ "$LOGS0" = "1" ] || die "the server logged $LOGS0 completed credits for the target, want 1 to begin with"

docker compose stop brollyzapper >/dev/null
REWOUND=$((SETTLE_IDX - 1))
sqlw "UPDATE settings SET value='$REWOUND' WHERE key='last_settle_index';"
# Read it BACK. Without this the effect check below is satisfied trivially:
# if the rewind never happened the resume point is already at SETTLE_IDX, so
# "it advanced back to >= SETTLE_IDX" is true having tested nothing. Verified
# by planting exactly that — the criterion reported a pass with no replay.
BACK=$(settle_index)
[ "$BACK" = "$REWOUND" ] \
  || die "the resume point is $BACK after the rewind, want $REWOUND — nothing was rewound, so no replay can happen"
ok "resume point rewound to $REWOUND — LND will re-send settle_index $SETTLE_IDX"
docker compose start brollyzapper >/dev/null
wait_health; login
# Let the stream re-deliver and the handler take whatever path it takes.
sleep 8
NEWIDX=$(settle_index)
[ "$NEWIDX" -ge "$SETTLE_IDX" ] \
  || die "the resume point is $NEWIDX, still below $SETTLE_IDX; the settlement was never re-delivered, so nothing was tested"
ok "re-delivered: the resume point advanced from $REWOUND back to $NEWIDX"

C=$(txn_count "$REPLAY_PH")
[ "$C" = "1" ] || die "the replayed settlement created $C txns rows for $REPLAY_PH, want 1"
ok "still exactly one txns row for $REPLAY_PH"
BAL1=$(balance_msat)
[ "$BAL1" = "$BAL0" ] \
  && ok "balance unchanged at $BAL1 msat" \
  || die "balance moved $BAL0 -> $BAL1 msat on a replayed settlement"
ENTRIES1=$(sql "SELECT COUNT(*) FROM balance_entries;")
[ "$ENTRIES1" = "$ENTRIES0" ] \
  && ok "balance_entries unchanged at $ENTRIES1 rows — no orphan entry" \
  || die "balance_entries $ENTRIES0 -> $ENTRIES1 on a replayed settlement"

# The database looks the same whether the replay was handled as a no-op or
# never arrived at all. This is what tells them apart: main.go logs "invoice
# settled" only when CreditInvoice reports that THIS call did the crediting, so
# a second line would be a second credit and no second line — with the resume
# point proving the event WAS re-delivered — is the no-op path being taken.
LOGS1=$(settled_logs "$REPLAY_PH")
[ "$LOGS1" = "1" ] \
  && ok "the server logged the credit once, not twice — the handler ran and reported no-op" \
  || die "the server logged $LOGS1 completed credits for $REPLAY_PH, want exactly 1"
fi

printf '\n\033[32mE2E PASSED\033[0m — o34.7 criteria %s proven on the regtest stack.\n\n' \
  "$([ "$WANT" = "  " ] && echo "1-9 and 12 (10 is manual)" || echo "$WANT")"
