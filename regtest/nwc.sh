#!/usr/bin/env bash
# d24.3 — the NIP-47 wallet service, against a real relay.
#
# The unit tests prove the six-step sequence against fakes. This proves it over
# the wire: a real client encrypts a real request, a real relay carries it, the
# service answers, and the client can read the answer back. The client is a
# SEPARATE module speaking the protocol rather than calling our codec — two
# halves that share an implementation prove they agree with each other, not with
# NIP-47.
#
# Seeds a connection directly in the database. The admin UI is d24.5; §8's
# pairing URI is what it will produce, and this is the same row it will write.
set -euo pipefail
cd "$(dirname "$0")"

APP="${APP:-http://localhost:8080}"
DBVOL="${DBVOL:-brollyregtest_server-data}"
CRED_VOLUME="${CRED_VOLUME:-brollyregtest_credentials}"
RELAY_INTERNAL="${RELAY_INTERNAL:-ws://relay:7777}"
WORK=$(mktemp -d)

# The connections this run seeds are DELETED on the way out, and the app is
# restarted so their subscriptions go with them.
#
# Not tidiness: a live NWC subscription is a socket the app holds to that relay,
# and e2e.sh §9 asserts the sender-named relay has none before its publish. A
# connection left on relay2 fails a script that has nothing to do with NWC, in a
# later run, with a message about zap receipts. Every script here has to leave
# the stack as it found it, whatever order they run in.
cleanup() {
  if [ -n "${SEEDED:-}" ]; then
    sqlw "DELETE FROM nwc_connections WHERE name LIKE 'regtest-%';" >/dev/null 2>&1 || true
    # The rows the crash-recovery arc plants, and the txns that reference the
    # connections above. A dangling nwc_connection_id would outlive this run and
    # a later script would meet a payment whose connection no longer exists.
    sqlw "DELETE FROM balance_entries WHERE txn_id IN
            (SELECT id FROM txns WHERE note LIKE 'crash recovery probe%');" >/dev/null 2>&1 || true
    sqlw "DELETE FROM txns WHERE note LIKE 'crash recovery probe%';" >/dev/null 2>&1 || true
    # And sending goes back to how it was found. §2's posture is receive-only by
    # default, and a stack left able to pay is a stack whose next script runs
    # under a setting it did not choose.
    if [ -n "${SEND_WAS:-}" ] && [ "${SEND_WAS:-}" != "<absent>" ]; then
      sqlw "INSERT INTO settings (key, value) VALUES ('send_enabled', '$SEND_WAS')
              ON CONFLICT(key) DO UPDATE SET value = '$SEND_WAS';" >/dev/null 2>&1 || true
    else
      sqlw "DELETE FROM settings WHERE key = 'send_enabled';" >/dev/null 2>&1 || true
    fi
    docker compose restart brollyzapper >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m   %s\n' "$*"; }
note() { printf '   \033[90m..\033[0m   %s\n' "$*"; }
die()  { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

sql()  { docker run --rm -v "$DBVOL:/data" brollyregtest-sqlite -readonly /data/brollyzapper.db "$@"; }

# ensure_ledger — the app's own ceiling (§5), topped up if a payment would not
# fit under it. Called before every section that pays.
#
# The node's channel liquidity and the app's LEDGER run out independently, and
# only the first is obvious. §5 reserves amount + max_fee, and max_fee is
# max(10_000 msat floor, 1% of amount), so each 21000 msat probe here needs
# 31000 msat of ceiling and gives back only the unused fee on settle. A zap
# credits 21000 — the amount, with nothing left for the reserve — so the ledger
# is one payment short from the very first one, and short again after each.
#
# This is what made the section fail on a FRESH stack while passing on a stack
# carrying credits from an earlier script: exactly the order-dependence the
# cleanup at the top of this file exists to prevent, and invisible until the
# relay was fixed and these sections could be reached at all (BrollyZap-qnz).
#
# Topped up by zapping rather than by writing balance_entries, because a zap is
# the only way the app itself credits the ledger — §5 keeps that table
# append-only behind wallet.Spender, and a test that writes it directly is
# asserting against a state the app cannot reach.
ensure_ledger() {
  local need="${1:-40000}" ledger
  ledger=$(sql "SELECT COALESCE(SUM(amount_msat),0) FROM balance_entries;")
  for _ in 1 2 3; do
    [ "$ledger" -ge "$need" ] && break
    note "the wallet ledger holds $ledger msat, short of $need; zapping to top it up"
    ./smoke.sh >/dev/null 2>&1 || die "the smoke arc would not credit the wallet"
    ledger=$(sql "SELECT COALESCE(SUM(amount_msat),0) FROM balance_entries;")
  done
  [ "$ledger" -ge "$need" ] \
    || die "the wallet ledger is $ledger msat after three zaps, short of the $need a payment and its fee reserve need"
  ok "the wallet ledger holds $ledger msat, clear of the payment and its fee reserve"
}
lncli_payer() { docker compose exec -T lnd-payer lncli --network=regtest "$@"; }
lncli_recv()  { docker compose exec -T lnd lncli --network=regtest "$@"; }

# cred_read / cred_write — the credential volume, in spend.sh's shape. The
# round trip is hex so a macaroon survives a shell.
cred_read()  { docker run --rm -v "$CRED_VOLUME:/c" alpine:3.20 \
                 sh -c "od -An -v -tx1 /c/$1 | tr -d ' \n'" 2>/dev/null || true; }
cred_write() { docker run --rm -v "$CRED_VOLUME:/c" alpine:3.20 \
                 sh -c "printf '%s' '$2' | sed 's/../\\\\x&/g' | xargs -0 printf > /c/$1"; }

# guardctl <command> — the guard's socket, through the server's own client, the
# way spend.sh does it. Baking with lncli would prove something about lncli.
guardctl() {
  docker run --rm -v "$CRED_VOLUME:/credentials" -v "$WORK/guardctl:/guardctl:ro" \
    alpine:3.20 /guardctl "$@"
}

# GUARD_DATA_VOLUME is the guard's OWN volume — the one the server has no mount
# for. It is mounted into guardctl only for `read-code`, which is the OPERATOR's
# step of `06v`'s ceremony; everything else goes through the socket, as the
# server does.
GUARD_DATA_VOLUME="${GUARD_DATA_VOLUME:-brollyregtest_guard-data}"

# guardctl_op <command> — guardctl with the operator's reach as well as the
# server's. Separate from guardctl() on purpose: the split IS the security
# property, and a single helper that always mounted the guard's volume would
# make every call in this script look like something the server can do.
guardctl_op() {
  docker run --rm -v "$CRED_VOLUME:/credentials" -v "$GUARD_DATA_VOLUME:/guard:ro" \
    -v "$WORK/guardctl:/guardctl:ro" alpine:3.20 /guardctl "$@"
}

# permit_sending — the operator's ceremony (`06v`), through guardctl.
#
# One command rather than four steps here: this script's subject is something
# else, and three scripts each carrying their own copy of a protocol sequence had
# already drifted in the wording. The failure mode of a stale copy is a script
# that keeps passing because it stopped exercising the ceremony. regtest/authorise.sh
# deliberately keeps its steps written out — the ceremony IS its subject.
permit_sending() { guardctl_op permit-sending || die "the operator's ceremony failed"; }
sqlw() { docker run --rm -v "$DBVOL:/data" brollyregtest-sqlite /data/brollyzapper.db "$@"; }

# app_log_count <pattern> — how many app log lines match, e2e.sh's idiom.
#
# `grep -c` rather than `grep -q`: -q exits early, `docker compose logs` takes
# SIGPIPE, and under pipefail the pipeline reports failure for a match that WAS
# found. `|| true` because grep exits 1 on zero matches, which is an answer here
# and not an error.
app_log_count() { docker compose logs brollyzapper 2>&1 | grep -c "$1" || true; }

# nwc <args...> — run the client inside the app's network namespace, so it
# reaches the relay by its compose name exactly as the service does.
nwc() {
  docker run --rm --net="container:$(docker compose ps -q brollyzapper)" \
    -v "$WORK:/w" alpine:3.20 /w/nwctool "$@" 2>>"$WORK/client.err"
}

say "0. setup"
command -v docker >/dev/null || die "docker is not on PATH"
command -v jq >/dev/null || die "jq is not on PATH"
docker compose ps -q brollyzapper >/dev/null 2>&1 || die "the stack is not up"
docker build -q -t brollyregtest-sqlite tools/sqlite >/dev/null || die "could not build tools/sqlite"

case "$(docker run --rm alpine:3.20 uname -m)" in
  aarch64|arm64) GOARCH=arm64 ;;
  x86_64|amd64)  GOARCH=amd64 ;;
  *) die "cannot map the container architecture to a GOARCH" ;;
esac
( cd tools/nwctool && CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH go build -o "$WORK/nwctool" . ) \
  || die "could not build tools/nwctool"
# A host build of the same tool, for -genkey: the keys are minted here and only
# the request-sending build has to run in the container.
( cd tools/nwctool && CGO_ENABLED=0 go build -o "$WORK/keytool" . ) \
  || die "could not build tools/nwctool for the host"
CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH go build -o "$WORK/guardctl" ./tools/guardctl \
  || die "could not build tools/guardctl"
# zaptool signs the kind 9734 that section 14 hands to pay_invoice, built for the
# host the same way e2e.sh builds it.
( cd tools/zaptool && go build -o "$WORK/zaptool" . ) || die "could not build tools/zaptool"
ok "nwctool built (linux/$GOARCH, and for the host), guardctl and zaptool built"

# sha256_hex hashes stdin in a container rather than on the host, because the
# host tool is `shasum` on macOS and `sha256sum` on the CI runner and this has to
# give the same answer on both.
sha256_hex() { docker run --rm -i alpine:3.20 sha256sum | cut -d" " -f1; }

# A connection, as §8's pairing URI describes one. Two fresh keypairs: the
# service's (this connection's OWN, per NIP-47's privacy guidance) and the
# client's.
read -r SERVICE_SK SERVICE_PK < <("$WORK/keytool" -genkey)
read -r CLIENT_SK CLIENT_PK < <("$WORK/keytool" -genkey)
NAME="regtest-$(date +%s)"
# A LIST since d24.18 (migration 0012): the column is `relays`, a JSON array, in
# the order the pairing URI names them. One entry here — this run is about the
# protocol rather than about failover, and a single-relay pairing is still the
# shape a client that reads only the first relay parameter ends up with.
sqlw "INSERT INTO nwc_connections
        (name, service_privkey, service_pubkey, client_pubkey, client_secret, relays,
         permissions, created_at)
      VALUES ('$NAME', '$SERVICE_SK', '$SERVICE_PK', '$CLIENT_PK', '$CLIENT_SK',
              json_array('$RELAY_INTERNAL'),
              '[\"invoice\",\"lookup\",\"history\",\"balance\",\"info\"]',
              $(date +%s));" >/dev/null || die "could not seed the connection"
SEEDED=1
# Captured HERE rather than beside the change in section 9: a run that dies in
# between must still put back what it found.
SEND_WAS=$(sql "SELECT COALESCE((SELECT value FROM settings WHERE key = 'send_enabled'), '<absent>');")
UI_NAME="regtest-ui-$(date +%s)"
JAR="$WORK/cookies"
PASS="${ADMIN_PASSWORD:-regtest-admin}"
csrf() { grep -o 'name="csrf_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//'; }
ok "connection $NAME seeded on $RELAY_INTERNAL (sending was $SEND_WAS)"

# The service subscribes at startup, so it has to be restarted to pick this up.
# That is d24.5's job to do live; here a restart is honest and cheap.
docker compose restart brollyzapper >/dev/null 2>&1 || die "could not restart the app"
for i in $(seq 1 40); do
  curl -sf "$APP/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "$APP/health" >/dev/null || die "the app did not come back"
sleep 3   # the subscription is established a moment after /health answers
ok "the app restarted and is serving the connection"

# ---------------------------------------------------------------------------
say "1. an authorized request is answered"
BALANCE_MSAT=$(sql "SELECT COALESCE(SUM(amount_msat),0) FROM balance_entries;")
OUT=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -method get_balance) \
  || die "get_balance got no answer: $(tail -3 "$WORK/client.err")"
printf '%s' "$OUT" | jq -e '.result.balance != null' >/dev/null \
  || die "the response carries no balance: $OUT"
ok "get_balance answered: $(printf '%s' "$OUT" | jq -c .result)"

# §8: the CEILING, never the node's. The node has far more than the wallet does
# on this stack, so the two are distinguishable.
GOT=$(printf '%s' "$OUT" | jq -r .result.balance)
[ "$GOT" = "$BALANCE_MSAT" ] \
  || die "get_balance returned $GOT, want the wallet ceiling $BALANCE_MSAT — §8 is explicit that the node's balance is never reported"
ok "and it is the wallet ceiling ($GOT msat), not the node's balance"

# ---------------------------------------------------------------------------
say "2. a foreign pubkey is ignored, without decryption"
# A key the connection has never heard of. §8 step 1: refused BEFORE any crypto,
# and with no response at all — answering would tell a stranger the pubkey is live.
read -r STRANGER_SK _ < <("$WORK/keytool" -genkey)
if nwc -service "$SERVICE_PK" -secret "$STRANGER_SK" -method get_balance -timeout 8s >/dev/null 2>&1; then
  die "a stranger's request was answered; §8 says UNAUTHORIZED must never leak whether a connection exists"
fi
ok "no response event — the stranger learns nothing"
# The observable half of "without decryption": the service logs a decrypt failure
# when an AUTHORIZED client sends something it cannot read, and logs nothing of
# the kind here.
# grep -c, not grep -q — see app_log_count. As `-q` this assertion could not
# fail on a match at all: SIGPIPE plus pipefail made the `if` read "no match",
# so it had been asserting nothing. Found while fixing the same shape below.
if [ "$(docker compose logs --since=30s brollyzapper 2>&1 | grep -ci 'could not decrypt' || true)" != "0" ]; then
  die "the service tried to decrypt a stranger's payload; step 1 is before step 2"
fi
ok "and nothing was decrypted"

# ---------------------------------------------------------------------------
say "3. a replayed request returns the identical response"
# Saved, so the replay is the SAME EVENT rather than a second request asking the
# same thing — which is what a relay redelivering one actually produces.
OUT1=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -method make_invoice \
        -params '{"amount":21000,"description":"replay probe"}' -save /w/replay.json) \
  || die "make_invoice got no answer: $(tail -3 "$WORK/client.err")"
HASH1=$(printf '%s' "$OUT1" | jq -r .result.payment_hash)
[ -n "$HASH1" ] && [ "$HASH1" != "null" ] || die "make_invoice returned no payment hash: $OUT1"
INVOICES_BEFORE=$(sql "SELECT COUNT(*) FROM invoices;")

OUT2=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -resend /w/replay.json) \
  || die "the replay got no answer: $(tail -3 "$WORK/client.err")"
[ "$OUT1" = "$OUT2" ] \
  || die "the replay answered differently:\n first: $OUT1\nsecond: $OUT2"
INVOICES_AFTER=$(sql "SELECT COUNT(*) FROM invoices;")
[ "$INVOICES_BEFORE" = "$INVOICES_AFTER" ] \
  || die "the replay minted another invoice ($INVOICES_BEFORE -> $INVOICES_AFTER); a known request id must execute NOTHING (§8)"
ok "identical response, and no second invoice was minted"

# ---------------------------------------------------------------------------
say "4. a request outside the freshness window is refused and not cached"
# FIVE MINUTES INTO THE FUTURE, not into the past, and the reason is a real
# interaction between §8's two mechanisms rather than a convenience.
#
# The subscription filter carries `since: nwc_since`, which advances as requests
# are handled — so by now it is roughly "a moment ago". A BACKDATED request is
# therefore before `since` and the relay never delivers it at all: the service
# cannot answer a request it is never sent, and the assertion would be about the
# relay's filter rather than about §8 step 3.
#
# A future-dated one passes the filter and fails the window, which is the same
# branch: §8 says "more than 60 s FROM now", and the check is symmetric. The past
# direction is covered at unit level, where there is no relay in the way.
OUT=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -method get_balance -age -5m) \
  || die "the out-of-window request got no answer at all; §8 wants an error so the client stops waiting"
printf '%s' "$OUT" | jq -e '.error.code == "OTHER"' >/dev/null \
  || die "a request five minutes out of the window answered $OUT, want an OTHER/expired error"
ok "refused: $(printf '%s' "$OUT" | jq -c .error)"
STALE_ID=$(grep -o 'request id [0-9a-f]*' "$WORK/client.err" | tail -1 | awk '{print $3}')
[ "$(sql "SELECT COUNT(*) FROM nwc_handled_requests WHERE event_id='$STALE_ID';")" = "0" ] \
  || die "the out-of-window request was cached; a later retry of the same id would be told it expired for ever"
ok "and it is not in the replay cache"

# ---------------------------------------------------------------------------
say "5. d24.4: pay_invoice is not advertised to a connection that may not use it"
# The info event is what a wallet app builds its UI from, so a pay button it
# shows and then cannot use is a broken wallet. This connection has no `pay`
# group yet — section 9 grants it — so the capability must be absent.
OUT=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -method get_info) \
  || die "get_info got no answer"
if printf '%s' "$OUT" | jq -e '.result.methods | index("pay_invoice")' >/dev/null; then
  die "get_info advertises pay_invoice to a connection without the pay group: $OUT"
fi
ok "advertised methods: $(printf '%s' "$OUT" | jq -c '.result.methods')"

# ---------------------------------------------------------------------------
say "6. 9xg: a zap publish leaves the NWC subscription connected"
# The field half of the unit test. A receipt goes out to the operator's own
# relays while the connection's subscription is open; the connection must still
# answer afterwards.
before_ok=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -method get_info | jq -r '.result.alias // "?"')
./smoke.sh >/dev/null 2>&1 || die "the smoke arc (which publishes a zap receipt) failed"
OUT=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -method get_balance -timeout 15s) \
  || die "the connection stopped answering after a zap publish — 9xg: a receipt must not close the NWC subscription"
printf '%s' "$OUT" | jq -e '.result.balance != null' >/dev/null || die "the answer is malformed: $OUT"
ok "still answering after a zap receipt was published (alias before: $before_ok)"

# ---------------------------------------------------------------------------
say "7. a connection on a relay that is NOT in default_relays still works"
# The case vz1.4's exemption exists for, and the one the earlier version of this
# script could not see: sections 1-6 use ws://relay:7777, which is ALSO the
# operator's configured relay, so they would pass with no exemption at all.
#
# relay2 is on the same Docker bridge — a private address — and is not in
# default_relays. Nothing but the subscription's own exemption can get a dial to
# it past the address check, and §8 step 6 means the answer has to come back on
# THAT relay rather than on the operator's.
read -r SK2 PK2 < <("$WORK/keytool" -genkey)
read -r CSK2 CPK2 < <("$WORK/keytool" -genkey)
NAME2="regtest-lan-$(date +%s)"
sqlw "INSERT INTO nwc_connections
        (name, service_privkey, service_pubkey, client_pubkey, client_secret, relays,
         permissions, created_at)
      VALUES ('$NAME2', '$SK2', '$PK2', '$CPK2', '$CSK2', json_array('ws://relay2:7777'),
              '[\"balance\",\"info\"]', $(date +%s));" >/dev/null \
  || die "could not seed the second connection"
docker compose restart brollyzapper >/dev/null 2>&1 || die "could not restart the app"
for i in $(seq 1 40); do curl -sf "$APP/health" >/dev/null 2>&1 && break; sleep 1; done
curl -sf "$APP/health" >/dev/null || die "the app did not come back"
sleep 3
ok "connection $NAME2 seeded on ws://relay2:7777 (not an operator relay)"

OUT=$(nwc -relay ws://relay2:7777 -service "$PK2" -secret "$CSK2" -method get_balance) \
  || die "a connection on a relay outside default_relays got no answer: $(tail -3 "$WORK/client.err")"
printf '%s' "$OUT" | jq -e '.result.balance != null' >/dev/null \
  || die "the response is malformed: $OUT"
ok "answered on its own relay: $(printf '%s' "$OUT" | jq -c .result)"

# And the other half of §8 step 6: the answer went to THAT relay only. The
# operator's relay carries zap receipts; an NWC response there is a response the
# client is not listening for, and an info event there announces the pairing.
if [ "$(nwc -relay ws://relay:7777 -service "$PK2" -secret "$CSK2" -method get_balance -timeout 8s \
        >/dev/null 2>&1; echo $?)" = "0" ]; then
  die "the connection answered on the OPERATOR's relay too; §8 step 6 is the same relay, and an unencrypted info event there announces the pairing next to the operator's receipts"
fi
ok "and nothing was published to the operator's relay"

# ---------------------------------------------------------------------------
say "8. d24.4: a connection WITHOUT the pay group cannot pay"
# E8, and it is the default connection: §8 defaults `pay` off, deliberately
# unlike LNbits. Asserted BEFORE sending is even enabled, so a failure here
# cannot be blamed on the toggle.
PAYER_INVOICE=$(lncli_payer addinvoice --amt_msat 21000 --memo "nwc restricted probe" \
  | jq -r .payment_request) || die "the payer node would not mint an invoice"
OUT=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -method pay_invoice \
        -params "{\"invoice\":\"$PAYER_INVOICE\"}") \
  || die "pay_invoice got no answer"
printf '%s' "$OUT" | jq -e '.error.code == "RESTRICTED"' >/dev/null \
  || die "a connection without the pay group answered $OUT, want RESTRICTED — §8 step 1"
ok "RESTRICTED: $(printf '%s' "$OUT" | jq -c .error.code)"

# ---------------------------------------------------------------------------
say "9. d24.4: a connection WITH the pay group pays end to end"
# The whole ladder, over the wire: the group granted, sending enabled, a spend
# macaroon baked through the guard, and a real invoice on the payer node.
# Revoke first, then bake. `bake-spend` is deliberately a no-op when a valid
# credential is already on disk — it refuses rather than churning the root key —
# and a macaroon baked by an EARLIER build carries that build's permission list.
# d24.4 added DecodePayReq to it, so a stale one decodes nothing and this section
# would fail with "the invoice could not be read".
guardctl revoke-spend >/dev/null 2>&1 || true
# Revoking drops the operator's latch (`06v`, Ruling 1), so sending has to be
# permitted again before a bake — same as it is for an operator.
permit_sending
guardctl bake-spend >/dev/null 2>&1 || die "the guard refused to bake the spend macaroon"
docker run --rm -v "$CRED_VOLUME:/credentials" alpine:3.20 \
  test -s /credentials/spend.macaroon || die "no spend.macaroon appeared in the credential volume"
ok "a fresh spend macaroon was baked through the guard"

sqlw "INSERT INTO settings (key, value) VALUES ('send_enabled', 'true')
        ON CONFLICT(key) DO UPDATE SET value = 'true';" >/dev/null \
  || die "could not enable sending"
sqlw "UPDATE nwc_connections SET permissions = '[\"pay\",\"invoice\",\"lookup\",\"history\",\"balance\",\"info\"]',
        budget_msat = 1000000, budget_period = 'daily',
        budget_renews_at = $(( $(date +%s) + 86400 ))
      WHERE name = '$NAME';" >/dev/null || die "could not grant the pay group"
docker compose restart brollyzapper >/dev/null 2>&1 || die "could not restart the app"
for i in $(seq 1 40); do curl -sf "$APP/health" >/dev/null 2>&1 && break; sleep 1; done
curl -sf "$APP/health" >/dev/null || die "the app did not come back"
sleep 3
ok "the pay group granted, sending enabled, app restarted"

# The stack opens its channel with PUSH_SAT=0, so the app's node starts with no
# local balance and accumulates only what zaps pay in — a few hundred sats. A
# 5,000,000 sat channel reserves 1% (50,000 sats) that cannot be spent, so the
# node cannot send AT ALL until its local balance clears that. Nothing to do with
# the app: LND answers FAILURE_REASON_INSUFFICIENT_BALANCE and §8 reports it
# faithfully, which is how this was found.
#
# Topped up through the node directly rather than through the app, because this
# is the stack's liquidity and not the app's ledger — an invoice the app has no
# row for is one it correctly ignores.
LOCAL_MSAT=$(lncli_recv channelbalance | jq -r '.local_balance.msat')
if [ "$LOCAL_MSAT" -lt 200000000 ]; then
  note "the app's node holds $LOCAL_MSAT msat locally, below the channel reserve; topping up"
  TOPUP=$(lncli_recv addinvoice --amt 250000 --memo "regtest liquidity top-up" \
    | jq -r .payment_request) || die "could not mint a top-up invoice"
  lncli_payer payinvoice --force --pay_req "$TOPUP" --timeout 60s >/dev/null 2>&1 || true
  for i in $(seq 1 20); do
    LOCAL_MSAT=$(lncli_recv channelbalance | jq -r '.local_balance.msat')
    [ "$LOCAL_MSAT" -ge 200000000 ] && break
    sleep 1
  done
  [ "$LOCAL_MSAT" -ge 200000000 ] || die "the top-up did not settle; local balance is $LOCAL_MSAT msat"
fi
ok "the app's node holds $LOCAL_MSAT msat locally, clear of the channel reserve"

ensure_ledger
BALANCE_BEFORE=$(sql "SELECT COALESCE(SUM(amount_msat),0) FROM balance_entries;")
PAYER_INVOICE=$(lncli_payer addinvoice --amt_msat 21000 --memo "nwc pay probe" \
  | jq -r .payment_request) || die "the payer node would not mint an invoice"

OUT=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -method pay_invoice \
        -params "{\"invoice\":\"$PAYER_INVOICE\"}" -timeout 60s) \
  || die "pay_invoice got no answer: $(tail -3 "$WORK/client.err")"
printf '%s' "$OUT" | jq -e '.result.preimage != null and .result.preimage != ""' >/dev/null \
  || die "pay_invoice answered $OUT, want a preimage — it is the client's proof it paid"
ok "paid: fees_paid=$(printf '%s' "$OUT" | jq -r .result.fees_paid)"

# The payee agrees, which is the only assertion that proves money moved.
PAID=$(lncli_payer listinvoices | jq -r \
  '.invoices[] | select(.memo == "nwc pay probe") | .state' | tail -1)
[ "$PAID" = "SETTLED" ] || die "the payer node reports the invoice as $PAID, not SETTLED"
ok "the payee node reports the invoice SETTLED"

# §5: the ceiling fell by amount + the ACTUAL fee, not by the reserve.
BALANCE_AFTER=$(sql "SELECT COALESCE(SUM(amount_msat),0) FROM balance_entries;")
SPENT=$(( BALANCE_BEFORE - BALANCE_AFTER ))
[ "$SPENT" -ge 21000 ] || die "the wallet balance fell by $SPENT msat, want at least the 21000 paid"
ok "the wallet ceiling fell by $SPENT msat (21000 + the route's fee)"

# §8: budget_used corrected to actuals, not left at amount + max_fee.
USED=$(sql "SELECT budget_used_msat FROM nwc_connections WHERE name = '$NAME';")
[ "$USED" = "$SPENT" ] \
  || die "budget_used_msat is $USED but the payment cost $SPENT; §8 corrects the budget to the actual fee on settle"
ok "budget_used_msat = $USED, corrected to the actual fee"

# And the history shows it, through the method a wallet app would ask.
OUT=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -method list_transactions \
        -params '{"type":"outgoing","limit":5}') || die "list_transactions got no answer"
printf '%s' "$OUT" | jq -e '[.result.transactions[] | select(.type == "outgoing")] | length > 0' >/dev/null \
  || die "list_transactions type=outgoing returned $OUT, want the payment just made"
ok "list_transactions shows the outgoing payment"

# ---------------------------------------------------------------------------
say "10. d24.6: a credential the node has revoked refuses the payment"
# The bead in one arc. §11's Tier-2 checks have computed all four spend rows
# since P1, every one declaring Blocks: BlocksSending — and until d24.6 NOTHING
# CONSULTED THEM. The ladder asked whether the setting was on and whether a file
# existed, which is presence, not validity. So a macaroon the node had already
# revoked showed a red row on the Security page and paid anyway.
#
# Reproduced the way spend.sh reproduces revocation: keep a copy, revoke it
# node-side, and put the copy back. The FILE is then present and valid-looking
# while the node no longer lists its root key — exactly the state a stolen or
# stale credential is in, and the P3 release criterion's shape.
SPEND_COPY=$(cred_read spend.macaroon)
[ -n "$SPEND_COPY" ] || die "spend.macaroon is empty"

guardctl revoke-spend >/dev/null 2>&1 || die "the guard refused to revoke the spend macaroon"
cred_write spend.macaroon "$SPEND_COPY" || die "could not restore the revoked macaroon"

# BYTE-IDENTICAL, not merely non-empty. A mangled restore would still be
# refused — by the caveats row rather than the root-key one — and the arc would
# pass for the wrong reason, which is the failure shape this repo names.
RESTORED=$(cred_read spend.macaroon)
[ "$RESTORED" = "$SPEND_COPY" ] \
  || die "the restored macaroon differs from the one taken before revocation; this arc would prove the wrong thing"
ok "the SAME spend macaroon is back on disk, byte for byte; the node no longer lists its root key"

# NO RESTART. §11's report is computed fresh per request — its Inputs are
# functions precisely so it cannot cache into staleness — so the refusal takes
# effect the moment the node stops honouring the key.
OUT=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -method pay_invoice \
        -params "{\"invoice\":\"$PAYER_INVOICE\"}" -timeout 30s) \
  || die "pay_invoice got no answer"
printf '%s' "$OUT" | jq -e '.error.code == "RESTRICTED"' >/dev/null \
  || die "a payment with a REVOKED macaroon answered $OUT, want RESTRICTED — this is d24.6: a red row that blocks nothing is worse than no checklist (§11)"
ok "refused: $(printf '%s' "$OUT" | jq -c .error.code)"

# And the message names no internals (§11 ruling 3): the operator's diagnosis is
# the Security page's row, not the paired app's error string.
if printf '%s' "$OUT" | jq -r .error.message | grep -qiE 'macaroon|caveat|ipaddr|root key'; then
  die "the refusal names an internal control: $(printf '%s' "$OUT" | jq -r .error.message)"
fi
ok "and it names no internals"

# Reading is unaffected. §11 blocks SENDING; a receive-only install is the
# default and a revoked spend credential must not take the wallet offline.
OUT=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -method list_transactions \
        -params '{"limit":5}') || die "list_transactions got no answer"
printf '%s' "$OUT" | jq -e '.result.transactions != null' >/dev/null \
  || die "list_transactions answered $OUT while sending was blocked; only sending is blocked"
ok "list_transactions still answers — only sending is blocked"

# Put the stack back: a fresh bake, and the same payment path works again.
#
# The ceremony again, because the guard treated the node-side revocation above
# as the operator taking sending away and dropped the latch with it (`06v`,
# Ruling 1 + tna.5 G2). That is the intended reading: "self-heal may restore
# capability the operator never removed, and must never restore capability the
# operator removed" — so turning it back on is an operator's act, not a retry.
permit_sending
guardctl bake-spend >/dev/null 2>&1 || die "the guard refused to re-bake the spend macaroon"
ensure_ledger
PAYER_INVOICE=$(lncli_payer addinvoice --amt_msat 21000 --memo "nwc rebake probe" \
  | jq -r .payment_request) || die "the payer node would not mint an invoice"
OUT=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -method pay_invoice \
        -params "{\"invoice\":\"$PAYER_INVOICE\"}" -timeout 60s) \
  || die "pay_invoice got no answer after the re-bake"
printf '%s' "$OUT" | jq -e '.result.preimage != null and .result.preimage != ""' >/dev/null \
  || die "the re-baked credential did not restore sending: $OUT"
ok "a fresh bake restores sending, with no restart"

# ---------------------------------------------------------------------------
say "11. d24.5 + uhg: the page creates a connection, and it works with NO restart"
# THROUGH THE REAL ADMIN SURFACE, which is what makes this an arc rather than a
# store test: the operator's browser is curl here, but the route, the CSRF check,
# the form parsing, plk's defaults and uhg's reload are all the shipped ones.
#
# Nothing is restarted after this point. Everything below it is the running
# service noticing.
tok=$(curl -s -c "$JAR" "$APP/login" | csrf)
curl -s -b "$JAR" -c "$JAR" -X POST "$APP/login" \
  --data-urlencode "csrf_token=$tok" --data-urlencode "password=$PASS" -o /dev/null
curl -sf -b "$JAR" "$APP/connections" >/dev/null || die "the connections page did not render"
ok "logged in; the connections page renders"

tok=$(curl -s -b "$JAR" "$APP/connections" | csrf)
[ -n "$tok" ] || die "no CSRF token on the connections page"
curl -s -b "$JAR" -c "$JAR" -X POST "$APP/connections/create" \
  --data-urlencode "csrf_token=$tok" \
  --data-urlencode "name=$UI_NAME" \
  --data-urlencode "relays=$RELAY_INTERNAL" \
  --data-urlencode "group_info=on" --data-urlencode "group_balance=on" \
  --data-urlencode "group_pay=on" \
  -o /dev/null || die "the create form was refused"

# plk: blank limits mean "you did not say", and a connection that may pay is
# bounded anyway.
UI_ID=$(sql "SELECT id FROM nwc_connections WHERE name = '$UI_NAME';")
[ -n "$UI_ID" ] || die "the connection was not created"
UI_BUDGET=$(sql "SELECT COALESCE(budget_msat, 0) FROM nwc_connections WHERE id = $UI_ID;")
UI_CAP=$(sql "SELECT COALESCE(max_payment_msat, 0) FROM nwc_connections WHERE id = $UI_ID;")
[ "$UI_BUDGET" = "100000000" ] || die "a connection created with pay has budget $UI_BUDGET msat, want the 100000000 default (plk)"
[ "$UI_CAP" = "25000000" ] || die "a connection created with pay has cap $UI_CAP msat, want the 25000000 default (plk)"
ok "created through the form, bounded by default: $UI_BUDGET msat/day, $UI_CAP msat per payment"

# uhg: the service is still the one started in section 9. It must now be serving
# this connection — subscribed to its relay and answering — with no restart.
UI_SERVICE_PK=$(sql "SELECT service_pubkey FROM nwc_connections WHERE id = $UI_ID;")
UI_CLIENT_SK=$(sql "SELECT client_secret FROM nwc_connections WHERE id = $UI_ID;")
sleep 2
OUT=$(nwc -service "$UI_SERVICE_PK" -secret "$UI_CLIENT_SK" -method get_balance -timeout 20s) \
  || die "a connection created through the page was never served; uhg means no restart"
printf '%s' "$OUT" | jq -e '.result.balance != null' >/dev/null \
  || die "the new connection answered $OUT"
ok "the running service picked it up and answered — no restart"

# STEP 6 OF THE FIELD TRIP, FINALLY RUNNABLE (d24.17).
#
# The 0.1.9 trip could not run this: there was no update route, and the only way
# to change a limit was revoke plus re-pair. So the previous version of this arc
# tightened the cap with a direct UPDATE and then faked the signal with an
# unrelated POST. Now it is the real control — the operator's own form, through
# the real route, with the real CSRF check — and the running service is told the
# way production tells it.
#
# The per-payment cap rather than the budget, deliberately: the budget is
# compared inside the store's guarded UPDATE and was live before uhg, so it would
# prove less. The cap is read from the row the reload refreshed.
tok=$(curl -s -b "$JAR" "$APP/connections" | csrf)
curl -s -b "$JAR" -c "$JAR" -X POST "$APP/connections/update" \
  --data-urlencode "csrf_token=$tok" \
  --data-urlencode "id=$UI_ID" \
  --data-urlencode "group_info=on" --data-urlencode "group_balance=on" \
  --data-urlencode "group_pay=on" \
  --data-urlencode "budget_sats=100000" \
  --data-urlencode "max_payment_sats=1" \
  -o /dev/null || die "the update form was refused"
NEW_CAP=$(sql "SELECT COALESCE(max_payment_msat, 0) FROM nwc_connections WHERE id = $UI_ID;")
[ "$NEW_CAP" = "1000" ] \
  || die "the update form left the cap at $NEW_CAP msat, want 1000 — the operator's change did not land"
ok "the cap was lowered through the real update route: $NEW_CAP msat"
sleep 2
# Topped up so the refusal below is the CAP's, not the ledger's: an
# INSUFFICIENT_BALANCE here would fail this assertion for a reason that has
# nothing to do with the reload it exists to prove.
ensure_ledger
PAYER_INVOICE=$(lncli_payer addinvoice --amt_msat 21000 --memo "nwc reload probe" \
  | jq -r .payment_request) || die "the payer node would not mint an invoice"
OUT=$(nwc -service "$UI_SERVICE_PK" -secret "$UI_CLIENT_SK" -method pay_invoice \
        -params "{\"invoice\":\"$PAYER_INVOICE\"}" -timeout 30s) \
  || die "pay_invoice got no answer"
printf '%s' "$OUT" | jq -e '.error.code == "QUOTA_EXCEEDED"' >/dev/null \
  || die "a 21 sat payment against a 1 sat cap answered $OUT, want QUOTA_EXCEEDED — the reload did not refresh the row"
ok "the tightened cap took effect with no restart: $(printf '%s' "$OUT" | jq -c .error.code)"

# Revoking through the page stops it answering, immediately.
tok=$(curl -s -b "$JAR" "$APP/connections" | csrf)
curl -s -b "$JAR" -c "$JAR" -X POST "$APP/connections/revoke" \
  --data-urlencode "csrf_token=$tok" --data-urlencode "id=$UI_ID" \
  -o /dev/null || die "the revoke form was refused"
sleep 2
if nwc -service "$UI_SERVICE_PK" -secret "$UI_CLIENT_SK" -method get_balance -timeout 10s >/dev/null 2>&1; then
  die "a REVOKED connection still answered; revocation that waits for a restart is revocation that did nothing"
fi
ok "revoked through the page and silent immediately"

# And a revoke that revokes NOTHING says so, without writing an audit row that
# claims otherwise (§12). The same id again: the row is already revoked.
BEFORE=$(sql "SELECT COUNT(*) FROM audit_events WHERE event = 'connection.revoke';")
tok=$(curl -s -b "$JAR" "$APP/connections" | csrf)
curl -s -b "$JAR" -c "$JAR" -X POST "$APP/connections/revoke" \
  --data-urlencode "csrf_token=$tok" --data-urlencode "id=$UI_ID" \
  -o /dev/null || die "the revoke form errored"
AFTER=$(sql "SELECT COUNT(*) FROM audit_events WHERE event = 'connection.revoke';")
[ "$BEFORE" = "$AFTER" ] \
  || die "revoking an already-revoked connection wrote an audit row ($BEFORE -> $AFTER); the trail would record a revocation that did not happen"
ok "a revoke that changes nothing claims nothing: connection.revoke rows still $AFTER"

say "12. d24.14: the spend path SAYS what it did"
# The field trip's sharpest finding: at debug level a real payment produced zero
# log lines, eleven NWC requests produced zero, and a RESTRICTED refusal produced
# zero AND left no audit row. audit_events recorded every action the OPERATOR
# took and nothing a CONNECTION did, so someone probing a pairing left no trace.
#
# A connection created through the page WITHOUT the pay group is the boundary:
# it asks to spend, and it may not.
NOPAY_NAME="regtest-nopay-$$"
tok=$(curl -s -b "$JAR" "$APP/connections" | csrf)
curl -s -b "$JAR" -c "$JAR" -X POST "$APP/connections/create" \
  --data-urlencode "csrf_token=$tok" \
  --data-urlencode "name=$NOPAY_NAME" \
  --data-urlencode "relays=$RELAY_INTERNAL" \
  --data-urlencode "group_info=on" --data-urlencode "group_balance=on" \
  -o /dev/null || die "the create form was refused"
NOPAY_ID=$(sql "SELECT id FROM nwc_connections WHERE name = '$NOPAY_NAME';")
[ -n "$NOPAY_ID" ] || die "the no-pay connection was not created"
NOPAY_PK=$(sql "SELECT service_pubkey FROM nwc_connections WHERE id = $NOPAY_ID;")
NOPAY_SK=$(sql "SELECT client_secret FROM nwc_connections WHERE id = $NOPAY_ID;")
sleep 2

REFUSALS_BEFORE=$(sql "SELECT COUNT(*) FROM audit_events WHERE event = 'connection.refuse';")
REFUSE_INVOICE=$(lncli_payer addinvoice --amt_msat 21000 --memo "nwc refusal probe" \
  | jq -r .payment_request) || die "the payer node would not mint an invoice"
OUT=$(nwc -service "$NOPAY_PK" -secret "$NOPAY_SK" -method pay_invoice \
        -params "{\"invoice\":\"$REFUSE_INVOICE\"}" -timeout 20s) \
  || die "pay_invoice got no answer"
printf '%s' "$OUT" | jq -e '.error.code == "RESTRICTED"' >/dev/null \
  || die "a connection without the pay group answered $OUT, want RESTRICTED"
sleep 2
REFUSALS_AFTER=$(sql "SELECT COUNT(*) FROM audit_events WHERE event = 'connection.refuse';")
[ "$REFUSALS_AFTER" -gt "$REFUSALS_BEFORE" ] \
  || die "a RESTRICTED refusal left no audit row ($REFUSALS_BEFORE -> $REFUSALS_AFTER); someone probing a connection leaves no trace, which is §C of the field trip"
ok "a capability refusal is on the durable trail: connection.refuse rows $REFUSALS_BEFORE -> $REFUSALS_AFTER"

DETAIL=$(sql "SELECT COALESCE(detail, '') FROM audit_events WHERE event = 'connection.refuse' ORDER BY id DESC LIMIT 1;")
printf '%s' "$DETAIL" | grep -q 'pay_invoice' \
  || die "the audit row does not name the method: $DETAIL"
printf '%s' "$DETAIL" | grep -q 'RESTRICTED' \
  || die "the audit row does not name the code: $DETAIL"
ok "and it names the connection, the method and the code"

# The SETTLED payment logged at INFO. Section 9 made a real one; before d24.14 it
# produced no log line at all, at any level.
#
# grep -c, NOT grep -q, and it is not a style choice: `-q` exits on the first
# match, `docker compose logs` takes SIGPIPE, and under `set -o pipefail` the
# pipeline then reports FAILURE FOR A MATCH THAT WAS FOUND. This exact line
# failed that way on its first run — a filter that turns green into red, and in
# the preimage check below it would have turned red into green and asserted
# nothing for ever. `-c` reads its input to the end.
[ "$(app_log_count 'an NWC payment settled')" -gt 0 ] \
  || die "a real payment produced no INFO line; an operator asking 'did something pay from my node?' has only the ledger"
ok "a settled payment says so in the log"
# And never its proof. §12 lists preimages with the macaroons.
#
# The PREIMAGE ITSELF, not the word: grepping for "preimage" across the whole log
# fails the day any unrelated line mentions it, and passes for a preimage logged
# under another key — the same weakness review found in the unit test. This is the
# hex the node actually returned for the payment section 9 made.
PAID_PROOF=$(sql "SELECT COALESCE(preimage, '') FROM txns
                   WHERE kind = 'payment_out' AND state = 'settled'
                   ORDER BY id DESC LIMIT 1;")
[ -n "$PAID_PROOF" ] || die "no settled payment to check the log against"
[ "$(app_log_count "$PAID_PROOF")" = "0" ] \
  || die "a preimage reached the log (§11, §12)"
ok "and the preimage ${PAID_PROOF:0:8}… is nowhere in the log"

say "13. d24.16: the outgoing row carries its proof and its label"
# The field trip read this straight off Amethyst: outgoing rows came back with
# desc='' and no preimage while incoming rows carried the zap comment, and
# txns.preimage was NULL for both real payments though LND held them.
PAID_HASH=$(sql "SELECT COALESCE(payment_hash, '') FROM txns
                  WHERE kind = 'payment_out' AND state = 'settled'
                  ORDER BY id DESC LIMIT 1;")
[ -n "$PAID_HASH" ] || die "no settled payment_out row to check"
PAID_PREIMAGE=$(sql "SELECT COALESCE(preimage, '') FROM txns WHERE payment_hash = '$PAID_HASH' AND kind = 'payment_out';")
[ -n "$PAID_PREIMAGE" ] \
  || die "the settled payment kept no preimage; without it the row cannot later prove settlement to anyone, and this is not recoverable after the fact"
ok "the ledger holds the preimage: ${PAID_PREIMAGE:0:8}…"
PAID_DESC=$(sql "SELECT COALESCE(description, '') FROM txns WHERE payment_hash = '$PAID_HASH' AND kind = 'payment_out';")
[ -n "$PAID_DESC" ] \
  || die "the settled payment kept no description; the operator's history is a list of unlabelled debits"
ok "and its description: $PAID_DESC"

# And list_transactions returns both, which is the half a paired app renders.
OUT=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -method list_transactions \
        -params '{"type":"outgoing","limit":5}' -timeout 20s) \
  || die "list_transactions got no answer"
printf '%s' "$OUT" | jq -e '[.result.transactions[] | select(.preimage != "")] | length > 0' >/dev/null \
  || die "list_transactions returned no preimage on any outgoing row: $OUT"
printf '%s' "$OUT" | jq -e '[.result.transactions[] | select(.description != "")] | length > 0' >/dev/null \
  || die "list_transactions returned no description on any outgoing row: $OUT"
ok "list_transactions carries both, which is what the phone renders"

say "14. doy + y09: an outgoing zap says who it paid, and only when the invoice says so"
# Three wire claims land together here, and none of them had an assertion against
# a real relay and a real node until this section — which is the shape CLAUDE.md
# names as an untested seam and this project has shipped more than once.
#
#   metadata          the client's NWC-06 object comes back on list_transactions
#   description_hash  the invoice's own commitment comes back beside it
#   description       ABSENT on a row with no memo, not ""
#
# The third is the one that reaches clients which know nothing about any of this,
# so it is the compatibility claim rather than the feature.

# A signed kind 9734, exactly as a client builds one before fetching the invoice.
ZAP_PAYEE=$(printf 'c%.0s' $(seq 1 64))
ZAP_REQUEST=$("$WORK/zaptool" request "$RELAY_INTERNAL" "$ZAP_PAYEE" 21000 -content "regtest attribution") \
  || die "zaptool would not sign a zap request"
ZAP_HASH=$(printf '%s' "$ZAP_REQUEST" | sha256_hex)
[ ${#ZAP_HASH} = 64 ] || die "sha256_hex returned '$ZAP_HASH', not a 64-character hex digest"

# A ZAP invoice on the payer node: NIP-57 commits to sha256 of those exact bytes
# and carries no memo, which is why the description arrives empty and why the
# binding has something to check against.
# Section 13 drained the ceiling, and §5 reserves amount + max_fee — 31,000 msat
# for a 21,000 msat probe (BrollyZap-xs3). Both payments below need their own
# top-up; a no-op when the ledger is already clear.
ensure_ledger
ZAP_INVOICE=$(lncli_payer addinvoice --amt_msat 21000 --description_hash "$ZAP_HASH" \
  | jq -r .payment_request) || die "the payer node would not mint a zap invoice"
# The flag's format is asserted, not assumed. lncli takes hex today; if that ever
# changes, every assertion below would pass against an invoice committing to
# something else entirely.
DECODED_HASH=$(lncli_payer decodepayreq --pay_req "$ZAP_INVOICE" | jq -r '.description_hash')
[ "$DECODED_HASH" = "$ZAP_HASH" ] \
  || die "the invoice commits to $DECODED_HASH but the zap request hashes to $ZAP_HASH; lncli's --description_hash is not taking hex and this section would prove nothing"
ok "a zap invoice committing to ${ZAP_HASH:0:8}…"

# NWC-06's whole object: the event, the payee's address and the message. All
# three are stored; only the event is covered by the commitment.
ZAP_METADATA="{\"nostr\":$ZAP_REQUEST,\"recipient_data\":{\"identifier\":\"payee@regtest.example\"},\"comment\":\"regtest attribution\"}"
OUT=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -method pay_invoice \
        -params "{\"invoice\":\"$ZAP_INVOICE\",\"metadata\":$ZAP_METADATA}" -timeout 60s) \
  || die "pay_invoice got no answer: $(tail -3 "$WORK/client.err")"
printf '%s' "$OUT" | jq -e '.result.preimage != null and .result.preimage != ""' >/dev/null \
  || die "the zap payment answered $OUT, want a preimage"
ok "the zap paid"

ROW='.result.transactions[] | select(.payment_hash == $h)'
ZAP_PAYMENT_HASH=$(lncli_payer decodepayreq --pay_req "$ZAP_INVOICE" | jq -r .payment_hash)
OUT=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -method list_transactions \
        -params '{"type":"outgoing","limit":10}' -timeout 20s) \
  || die "list_transactions got no answer"
printf '%s' "$OUT" | jq -e --arg h "$ZAP_PAYMENT_HASH" "[$ROW] | length == 1" >/dev/null \
  || die "the zap payment is not in the history at all: $OUT"

# 1. The payee survives the round trip, and it is the p tag rather than the
#    address — the commitment covers the event and not its siblings.
GOT_PAYEE=$(printf '%s' "$OUT" | jq -r --arg h "$ZAP_PAYMENT_HASH" \
  "[$ROW | .metadata.nostr.tags[] | select(.[0] == \"p\") | .[1]] | first // \"\"")
[ "$GOT_PAYEE" = "$ZAP_PAYEE" ] \
  || die "metadata.nostr's p tag came back as '$GOT_PAYEE', want $ZAP_PAYEE — this is the whole of what an outgoing row can say"
ok "metadata.nostr names the payee"

# 2. And its siblings, which is why the column holds the object rather than the
#    event: a client's row renderer falls back to the address.
GOT_ID=$(printf '%s' "$OUT" | jq -r --arg h "$ZAP_PAYMENT_HASH" "$ROW | .metadata.recipient_data.identifier // \"\"")
[ "$GOT_ID" = "payee@regtest.example" ] \
  || die "recipient_data.identifier came back as '$GOT_ID'; a nostr-only round trip renders the row nameless until a profile resolves"
ok "recipient_data survives the round trip"

# 3. The commitment travels with the row, so a client can CHECK the attribution
#    rather than trust this node for it.
GOT_HASH=$(printf '%s' "$OUT" | jq -r --arg h "$ZAP_PAYMENT_HASH" "$ROW | .description_hash // \"\"")
[ "$GOT_HASH" = "$ZAP_HASH" ] \
  || die "description_hash came back as '$GOT_HASH', want $ZAP_HASH — without it a client has to take this node's word for the payee"
ok "description_hash is on the row"

# 4. THE COMPATIBILITY CLAIM. A zap invoice has no memo, so this row has nothing
#    to call itself — and the key must be ABSENT rather than "". A client that
#    falls back only on a missing field renders an empty string as an occupied
#    line showing nothing, which is the bug doy.1 fixed for every paired app.
printf '%s' "$OUT" | jq -e --arg h "$ZAP_PAYMENT_HASH" "[$ROW | has(\"description\")] | first == false" >/dev/null \
  || die "the row carries a description key on a payment with no memo: $(printf '%s' "$OUT" | jq -c --arg h "$ZAP_PAYMENT_HASH" "$ROW")"
ok "description is absent on a row with no memo, not empty"

# 5. AND AN EVENT THE INVOICE DOES NOT COMMIT TO IS DROPPED — while the money
#    still moves. Both halves matter: the first is what stops a paired app naming
#    any payee it likes on any payment, and the second is the rule that a
#    cosmetic field can never cost a payment.
OTHER_REQUEST=$("$WORK/zaptool" request "$RELAY_INTERNAL" "$(printf 'd%.0s' $(seq 1 64))" 21000 -content "not this payment") \
  || die "zaptool would not sign the second request"
ensure_ledger
PLAIN_INVOICE=$(lncli_payer addinvoice --amt_msat 21000 --memo "unbound probe" \
  | jq -r .payment_request) || die "the payer node would not mint a plain invoice"
PLAIN_HASH=$(lncli_payer decodepayreq --pay_req "$PLAIN_INVOICE" | jq -r .payment_hash)
OUT=$(nwc -service "$SERVICE_PK" -secret "$CLIENT_SK" -method pay_invoice \
        -params "{\"invoice\":\"$PLAIN_INVOICE\",\"metadata\":{\"nostr\":$OTHER_REQUEST}}" -timeout 60s) \
  || die "the unbound payment got no answer: $(tail -3 "$WORK/client.err")"
printf '%s' "$OUT" | jq -e '.result.preimage != null and .result.preimage != ""' >/dev/null \
  || die "a payment was REFUSED over its metadata: $OUT — the money must move whatever the client attached"
STORED=$(sql "SELECT COALESCE(out_metadata, '') FROM txns WHERE payment_hash = '$PLAIN_HASH' AND kind = 'payment_out';")
[ -z "$STORED" ] \
  || die "an event the invoice does not commit to was stored: $STORED"
ok "an unbound event is dropped and the payment still settles"

say "15. d24.15: a recovered payment's budget is corrected to what it SPENT"
# The trip measured this on the box: the wallet reconciled correctly and the
# CONNECTION BUDGET kept the whole fee reserve. Reproduced here without killing
# a container mid-flight — the row a crash leaves is written directly, against a
# payment LND really made, and the real startup resolver is what closes it.
#
# The row is what the ladder writes before it sends: pending, dispatched,
# charged amount + reserve on the connection, and debited amount + reserve on
# the ledger. Everything after that is production code.
RECOVER_NAME="regtest-recover-$$"
tok=$(curl -s -b "$JAR" "$APP/connections" | csrf)
curl -s -b "$JAR" -c "$JAR" -X POST "$APP/connections/create" \
  --data-urlencode "csrf_token=$tok" \
  --data-urlencode "name=$RECOVER_NAME" \
  --data-urlencode "relays=$RELAY_INTERNAL" \
  --data-urlencode "group_info=on" --data-urlencode "group_pay=on" \
  -o /dev/null || die "the create form was refused"
RECOVER_ID=$(sql "SELECT id FROM nwc_connections WHERE name = '$RECOVER_NAME';")
[ -n "$RECOVER_ID" ] || die "the recovery connection was not created"

# A payment LND really made, so TrackPayment answers SUCCEEDED with a real fee.
RECOVER_INVOICE=$(lncli_payer addinvoice --amt_msat 21000 --memo "crash recovery probe" \
  | jq -r .payment_request) || die "the payer node would not mint an invoice"
RECOVER_PAY=$(lncli_recv payinvoice --force --json "$RECOVER_INVOICE") \
  || die "the app's node would not pay the invoice"
RECOVER_HASH=$(printf '%s' "$RECOVER_PAY" | jq -r '.payment_hash')
RECOVER_FEE=$(printf '%s' "$RECOVER_PAY" | jq -r '.fee_msat // .payment_route.total_fees_msat // 0')
[ -n "$RECOVER_HASH" ] || die "no payment hash from the node: $RECOVER_PAY"
note "the node paid $RECOVER_HASH for a fee of $RECOVER_FEE msat"

# The crash's leftovers: a reservation charged 21000 + 10000 and never closed.
OLD=$(( $(date +%s) - 3600 ))
sqlw "INSERT INTO txns (kind, state, amount_msat, fee_reserved_msat, payment_hash, note,
                        description, nwc_connection_id, created_at, dispatched_at)
      VALUES ('payment_out', 'pending', 21000, 10000, '$RECOVER_HASH', 'crash recovery probe',
              'crash recovery probe', $RECOVER_ID, $OLD, $OLD);" >/dev/null \
  || die "could not write the crash-recovery row"
RECOVER_TXN=$(sql "SELECT id FROM txns WHERE payment_hash = '$RECOVER_HASH' AND kind = 'payment_out';")
sqlw "INSERT INTO balance_entries (txn_id, amount_msat, reason, created_at)
      VALUES ($RECOVER_TXN, -31000, 'reserve', $OLD);" >/dev/null \
  || die "could not write the crash-recovery balance entry"
sqlw "UPDATE nwc_connections SET budget_used_msat = 31000 WHERE id = $RECOVER_ID;" >/dev/null \
  || die "could not charge the connection budget"

docker compose restart brollyzapper >/dev/null 2>&1 || die "could not restart the app"
for i in $(seq 1 40); do curl -sf "$APP/health" >/dev/null 2>&1 && break; sleep 1; done
curl -sf "$APP/health" >/dev/null || die "the app did not come back"
sleep 3

RECOVER_STATE=$(sql "SELECT state FROM txns WHERE id = $RECOVER_TXN;")
[ "$RECOVER_STATE" = "settled" ] \
  || die "the resolver left the recovered payment $RECOVER_STATE, want settled"
BUDGET_USED=$(sql "SELECT budget_used_msat FROM nwc_connections WHERE id = $RECOVER_ID;")
WANT=$(( 21000 + RECOVER_FEE ))
[ "$BUDGET_USED" = "$WANT" ] \
  || die "budget_used is $BUDGET_USED msat, want $WANT (21000 + the route's actual $RECOVER_FEE). The reserve was never corrected — which is exactly the drift the field trip measured at 31000 where 23055 was right"
ok "the recovered payment charged the ACTUAL $BUDGET_USED msat, not the 31000 reserve"

printf '\n\033[32mNWC CHECK PASSED\033[0m — §8'"'"'s service answers over a real relay, idempotently.\n\n'
