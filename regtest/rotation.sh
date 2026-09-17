#!/usr/bin/env bash
# d46.22 — the guard's rotation-exit path, end to end.
#
# This is the one P1 behaviour that has never run outside a unit test, because
# the only way to trigger it is to rotate LND's macaroons.db, and on a live
# Umbrel box that takes BTCPay, albyhub, lndg and woofbot down with it. The
# regtest chain is a chain nobody cares about, so here it is just a file.
#
# §6's path, and every step of it is asserted rather than assumed:
#
#   LND's macaroons rotate
#     -> the guard's admin.macaroon is stale, and a single-file bind mount
#        follows the INODE, so no amount of retrying inside the process can
#        ever see the replacement
#     -> three consecutive rejections of the guard's own probes, each counted
#        only when LND's State service says the node is ready (dqd)
#     -> audit=macaroon.rotate, a 10s settling pause, exit non-zero
#     -> restart: on-failure brings it back and Docker re-resolves the mount
#     -> the guard re-copies tls.cert and re-bakes recv.macaroon on a new root key
#     -> the server, whose recv.macaroon LND no longer has a root key for, says
#        re-link while it waits — on the second refusal from a node reporting a
#        running stage, since the first cannot be told from LND shutting down (2f0)
#     -> the server, which never exited, recovers with no operator action
#
#   ./rotation.sh
#
# WHAT THE REJECTION IS DEPENDS ON THE PLATFORM, and on macOS it is not LND's
# (dqd, measured 16 Sep 2026):
#
#   macOS    Docker Desktop's file sharing makes the deleted host file read as
#            ABSENT inside the container, so the guard's own gRPC client fails to
#            read admin.macaroon and reports Unauthenticated before anything is
#            sent. LND logged no GetInfo from the guard in either run that day.
#            This script proves the exit-and-restart path; it does not prove the
#            guard recognises LND's answer.
#   Linux    the running container keeps the old file (§18: a file replaced by
#            rename is stale to it), so the guard sends the stale macaroon, and
#            LND answers a pre-rotation macaroon with code Unknown ("verification
#            failed: signature mismatch after caveat verification" — measured
#            with lncli, not yet through this script on Linux).
#
# ./wrongmount.sh is the proof of that shape on any platform: it plants readable
# rejected bytes in place, so this script does not plant them too.
#
# THE SERVER'S REJECTION IS LND'S ON EVERY PLATFORM. recv.macaroon lives in the
# credentials named volume, not a host bind mount, so the stale bytes reach the
# node, which answers code Unknown, "root key with id N doesn't exist" (measured
# 17 Sep 2026 with lncli). That is what makes section 3's re-link line provable
# on macOS.
#
# Afterwards the stack is left working. Nothing here is destructive beyond the
# regtest node's own macaroons, which it regenerates.
set -euo pipefail
cd "$(dirname "$0")"

# Default: tools/sqlite/Dockerfile's FROM, stated once (0vk.59; script_lint_test.go says why).
TOOL_IMAGE="${TOOL_IMAGE:-$(awk '$1 == "FROM" { print $2; exit }' tools/sqlite/Dockerfile 2>/dev/null || true)}"
[ -n "$TOOL_IMAGE" ] || { echo "FAIL could not read the tool image from tools/sqlite/Dockerfile's FROM line" >&2; exit 1; }
APP="http://localhost:${APP_PORT:-8080}"
NAME="${ADDRESS_NAME:-test}"
PASS="${ADMIN_PASSWORD:-regtest-admin}"
AMOUNT_MSAT="${AMOUNT_MSAT:-21000}"
LNDDIR="./data/lnd/data/chain/bitcoin/regtest"
# How long to wait for the detector to trip. The guard probes LND itself every
# guard.ProbeInterval once it has been rejected once, and trips on three
# consecutive rejections — so this bounds roughly three probe intervals plus the
# time LND takes to come back, with room to spare.
TRIP_TIMEOUT="${TRIP_TIMEOUT:-180}"
# POLL_NODE=0 is as0.8's criterion, and the removal IS the test.
#
# This script used to curl /node every five seconds while waiting for the guard
# to notice. Each render makes the server ask the guard, which asks LND — so the
# script was manufacturing the very samples it was measuring the guard's ability
# to gather. With the polling off, nothing but the guard's own probe loop can
# produce the second and third rejections.
# DEFAULT 0, because the unpolled shape is the one as0.8 is about and a
# criterion nobody runs by default is a criterion nobody runs. POLL_NODE=1 keeps
# the polled variant available; both must pass.
POLL_NODE="${POLL_NODE:-0}"

JAR=$(mktemp); WORK=$(mktemp -d)
HEALTH_LOG="$WORK/health.log"; EVENTS="$WORK/events.log"
# The two watchers are killed by PID and then WAITED on: killing a job by %1
# leaves the shell to announce "Terminated: 15" after the script's own success
# line, which reads like a failure at the end of a passing run.
HEALTH_PID=""; EVENTS_PID=""
cleanup() {
  local code=$?
  for pid in "$HEALTH_PID" "$EVENTS_PID"; do
    [ -n "$pid" ] || continue
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$JAR" "$WORK"
  return $code
}
trap cleanup EXIT

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m   %s\n' "$*"; }
note() { printf '   \033[90m..\033[0m   %s\n' "$*"; }
die()  { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }
csrf() { grep -o 'name="csrf_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//'; }
lncli_recv()  { docker compose exec -T lnd lncli --network=regtest "$@"; }
lncli_payer() { docker compose exec -T lnd-payer lncli --network=regtest "$@"; }

guard_id()   { docker compose ps -q guard; }
server_id()  { docker compose ps -q brollyzapper; }
inspect()    { docker inspect -f "$2" "$1"; }
cred_stat()  { docker run --rm -v brollyregtest_credentials:/c "$TOOL_IMAGE" stat -c '%s %Y %i' "/c/$1" 2>/dev/null || echo "missing"; }
root_ids()   { lncli_recv listmacaroonids | jq -r '.root_key_ids|sort|join(",")'; }
# Read from compose, not spelled again here: the ipaddr caveat has to match the
# address the server actually has, and lint_test.go already ties SERVER_IP to the
# static address. A second literal would be a third statement of one fact.
cred_server_ip() { awk -F': *' '/SERVER_IP:/ {print $2; exit}' docker-compose.yml; }

# wait_audit_row <event> <tries> — has this event reached the Security page?
#
# Read from the PAGE rather than the database, deliberately: that is the whole
# chain §12 promises — guard state file, socket, Auditor, audit_events, render —
# and any link breaking makes the operator's trail wrong. The /node poll is what
# makes the server collect, so it is done here too rather than waited for.
wait_audit_row() {
  local event="$1" tries="${2:-60}" i
  for i in $(seq 1 "$tries"); do
    # The /node poll is what makes the server collect the guard's events, so it
    # is done here rather than waited for.
    curl -s -b "$JAR" -o /dev/null "$APP/node" || true
    # Scoped to THIS run by timestamp. The Security page shows history, so a
    # bare grep for the event name passes on a previous run's row — the same
    # trap require_from_this_run exists for, one layer down.
    if [ "$(sql "SELECT COUNT(*) FROM audit_events WHERE event='$event' AND created_at >= $RUN_START_EPOCH;")" -gt 0 ]; then
      # …and it renders. The row existing and the operator being able to see it
      # are two different claims, and §12 makes both.
      # grep -c, not -q: -q exits at the first match, curl takes SIGPIPE with
      # the page unwritten, and pipefail then reports "not found" for a match
      # that WAS found — so this loop would spin to its timeout on success.
      [ "$(curl -s -b "$JAR" "$APP/security" | grep -c "$event" || true)" != "0" ] && return 0
    fi
    sleep 2
  done
  return 1
}

# Re-peer the two nodes and wait for the channel.
#
# This script restarts LND, and the payer does not re-dial on its own: after a
# restart listpeers is empty and the channel goes inactive, so step 5's payment
# times out with "the invoice never settled" — which reads exactly like the app
# failing to recover, and is not. scripts/init.sh does this once at stack-up and
# never runs again.
ensure_peered() {
  local recv i
  recv=$(lncli_recv getinfo | jq -r .identity_pubkey)
  # ONE interleaved loop, not connect-then-poll. The two-loop form stopped
  # re-dialling the moment listpeers was non-empty, so a peer that dropped again
  # afterwards left the second loop waiting 90s for a channel nothing was
  # reconnecting.
  for i in $(seq 1 45); do
    [ "$(lncli_recv listchannels | jq -r '[.channels[]|select(.active)]|length')" -gt 0 ] && return 0
    lncli_payer connect "$recv@lnd:9735" >/dev/null 2>&1 || true
    sleep 2
  done
  die "the channel never came back active after the LND restart; nothing can be paid"
}

login() {
  local tok
  tok=$(curl -s -c "$JAR" "$APP/login" | csrf)
  curl -s -b "$JAR" -c "$JAR" -X POST "$APP/login" \
    --data-urlencode "csrf_token=$tok" --data-urlencode "password=$PASS" -o /dev/null
}

# ---------------------------------------------------------------------------
# SQL against the server's data volume, and the image it needs.
#
# need_sqlite is not decoration: this script used to open-code the docker run
# without ever building brollyregtest-sqlite, so on a machine that had never run
# e2e.sh it died at step 5 — four minutes in, after every interesting assertion
# had already passed. The build is cached and costs about half a second.
DBVOL="${DBVOL:-brollyregtest_server-data}"
SQLITE_IMAGE=brollyregtest-sqlite
need_sqlite() {
  docker image inspect "$SQLITE_IMAGE" >/dev/null 2>&1 && return 0
  docker build -q -t "$SQLITE_IMAGE" tools/sqlite >/dev/null \
    || die "could not build tools/sqlite, which this script needs to read the server's database"
}
sql() { docker run --rm -v "$DBVOL:/data" "$SQLITE_IMAGE" -readonly /data/brollyzapper.db "$@"; }

say "0. baseline"
[ -d "$LNDDIR" ] || die "$LNDDIR is not here: this suite bind-mounts a host path under $(pwd)/data, so it must run from the tree the stack was brought up in"
# Every log search below is scoped to this run. The first version was not, and
# on the second run it matched the FIRST run's macaroon.rotate line, reported a
# pass, and then computed the settling delay from a timestamp minutes in the
# past. An assertion that history can satisfy is not an assertion.
# The trailing Z is load-bearing: `docker compose logs --since` reads a bare
# timestamp in the CLIENT'S LOCAL timezone, so a UTC stamp without it silently
# becomes "two hours ago" on this machine and filters nothing.
RUN_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
RUN_START_EPOCH=$(date -u +%s)
glog() { docker compose logs --since "$RUN_START" "$@" 2>&1; }

# When a log line was written, in epoch seconds. slog writes RFC3339 with
# NANOSECOND precision and datetime.fromisoformat takes at most microseconds,
# so the fraction is trimmed before parsing.
log_epoch() {
  echo "$1" | grep -o '"time":"[^"]*"' | head -1 | sed 's/.*"time":"//;s/"//' | python3 -c '
import sys, re, datetime
raw = sys.stdin.read().strip()
raw = re.sub(r"\.(\d{6})\d*", r".\1", raw).replace("Z", "+00:00")
print(int(datetime.datetime.fromisoformat(raw).timestamp()))'
}

# The belt to the --since braces. Two runs of this script against one stack is
# the normal case, and the first version matched the PREVIOUS run's rotate line
# and reported a pass having observed nothing. A filter bug can make that happen
# again; a timestamp comparison cannot.
require_from_this_run() {
  local when; when=$(log_epoch "$2")
  [ -n "$when" ] || die "could not read a timestamp out of the $1 line"
  [ "$when" -ge "$RUN_START_EPOCH" ] \
    || die "the $1 line was written $(( RUN_START_EPOCH - when ))s BEFORE this run started; it belongs to an earlier run, and this assertion would have passed on history"
}
GUARD=$(guard_id); SERVER=$(server_id)
[ -n "$GUARD" ] && [ -n "$SERVER" ] || die "the stack is not up"
need_sqlite
# zaptool too. It used to be built in step 5, three minutes into the run, so a
# build failure there wasted everything before it.
ZT="$WORK/zaptool"
( cd tools/zaptool && go build -o "$ZT" . ) || die "could not build tools/zaptool"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$APP/health")" = "200" ] || die "the app is not healthy to begin with"
login
G_RESTARTS_0=$(inspect "$GUARD" '{{.RestartCount}}')
G_STARTED_0=$(inspect "$GUARD" '{{.State.StartedAt}}')
S_STARTED_0=$(inspect "$SERVER" '{{.State.StartedAt}}')
IDS_0=$(root_ids)
RECV_0=$(cred_stat recv.macaroon)
TLS_0=$(cred_stat tls.cert)
ok "guard restarts=$G_RESTARTS_0 started=$G_STARTED_0"
ok "server started=$S_STARTED_0"
ok "node root key ids: $IDS_0"
ok "recv.macaroon: $RECV_0"

# The server must never exit (§11 has exactly one sanctioned crash-loop
# exception and it is the guard's). Sampling /health throughout is the only way
# to catch a bounce that a StartedAt comparison at the end would miss.
( while true; do
    printf '%s %s\n' "$(date +%s)" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$APP/health" || echo 000)" >> "$HEALTH_LOG"
    sleep 1
  done ) &
HEALTH_PID=$!
WATCH_FROM=$(date -u +%s)
# The die event carries the exit code. Reading it afterwards from
# .State.ExitCode does not work: once the container is running again that field
# is the CURRENT run's, and the failing code is gone.
# No subshell: $! must be the docker process itself, or cleanup's kill reaches a
# wrapper shell and leaves the thing actually writing the file running.
docker events --filter "container=$GUARD" --filter 'event=die' --format '{{.Time}} {{.Actor.Attributes.exitCode}}' >> "$EVENTS" &
EVENTS_PID=$!
sleep 2
ok "watching /health and the guard's die events"

# ---------------------------------------------------------------------------
say "1. rotate the node's macaroons"
# Deleting macaroons.db makes LND generate a new macaroon root key on the next
# start and write fresh macaroon files. The guard's bind mount still points at
# the OLD inode of admin.macaroon — which is precisely the situation §6 says no
# amount of in-process retrying can fix.
docker compose stop lnd >/dev/null
ls "$LNDDIR"/macaroons.db >/dev/null 2>&1 || die "$LNDDIR/macaroons.db is not where it was expected"
rm -f "$LNDDIR"/macaroons.db "$LNDDIR"/*.macaroon
ok "macaroons.db and every *.macaroon removed"
docker compose start lnd >/dev/null
LND_START_EPOCH=$(date -u +%s)
LND_ANSWERED_AFTER=""
for i in $(seq 1 90); do
  lncli_recv getinfo >/dev/null 2>&1 && break
  sleep 1
done
lncli_recv getinfo >/dev/null 2>&1 || die "LND did not come back"
# Section 3 reads this: past about a minute the server's retry gap has reached
# its ceiling, and the guard can re-bake before the server meets the stale
# macaroon at all. That is timing, not a defect, so section 3 says so and does
# not assert rather than failing a working system (2f0 go-review).
LND_ANSWERED_AFTER=$(( $(date -u +%s) - LND_START_EPOCH ))
note "LND answered ${LND_ANSWERED_AFTER}s after it was started"
for i in $(seq 1 30); do [ -f "$LNDDIR/admin.macaroon" ] && break; sleep 1; done
[ -f "$LNDDIR/admin.macaroon" ] || die "LND did not write a new admin.macaroon"
ensure_peered
IDS_1=$(root_ids)
ok "LND back up, channel active again; root key ids now: $IDS_1"
[ "$IDS_1" != "$IDS_0" ] || die "the root key ids did not change; nothing was rotated"

# ---------------------------------------------------------------------------
say "2. the guard notices, logs, settles, and exits"
# The guard's own probe loop produces the rejections that count (as0.8); the
# Node page poll runs only under POLL_NODE=1, the variant from before the loop.
TRIPPED=""
START=$(date +%s)
while [ $(( $(date +%s) - START )) -lt "$TRIP_TIMEOUT" ]; do
  [ "$POLL_NODE" = "1" ] && { curl -s -b "$JAR" -o /dev/null "$APP/node" || true; }
  if [ "$(glog guard | grep -c 'macaroon.rotate' || true)" != "0" ]; then TRIPPED=yes; break; fi
  sleep 5
done
TRIP_SECONDS=$(( $(date +%s) - START ))
[ -n "$TRIPPED" ] || die "the guard never logged macaroon.rotate within ${TRIP_TIMEOUT}s$([ "$POLL_NODE" = "1" ] || echo " with nothing polling it — as0.8's probe loop is not producing its own samples")"
note "time from rotation to the guard noticing: ${TRIP_SECONDS}s (POLL_NODE=$POLL_NODE)"
ROTATE_LINE=$(glog guard | grep 'macaroon.rotate' | tail -1)
require_from_this_run "macaroon.rotate" "$ROTATE_LINE"
ok "audit=macaroon.rotate logged, by THIS run"
# …and it reached the DURABLE trail, which is the half that was actually broken
# before. internal/guard/audit.go says so in as many words: "Before d46.18 only
# the log line existed, so audit_events held no macaroon.bake on a box where the
# guard had plainly logged one." The guard writes to its own state file, the
# server collects over the socket, the Auditor writes the row, the Security page
# renders it — greping the guard's stdout asserts the one link that was never
# the problem.
wait_audit_row macaroon.rotate 60 \
  || die "the guard logged macaroon.rotate but it never reached audit_events; §12's durable half (d46.18) is broken again"
ok "and it reached audit_events — log, socket, Auditor, Security page, all of it"
note "$(echo "$ROTATE_LINE" | sed 's/^guard-1 *| *//' | cut -c1-200)"
echo "$ROTATE_LINE" | grep -q '"audit":"macaroon.rotate"' \
  && ok "carried as an audit attribute, not a severity (§12)" \
  || die "the rotation was logged without an audit= attribute"

# The settling delay, observed. guard.RotationExitDelay is 10s and exists so
# restart: on-failure does not spin.
for i in $(seq 1 60); do [ -s "$EVENTS" ] && break; sleep 1; done
[ -s "$EVENTS" ] || die "the guard never exited after declaring rotation"
DIE_AT=$(awk 'END{print $1}' "$EVENTS")
EXIT_CODE=$(awk 'END{print $2}' "$EVENTS")
# Measured the hard way: the first run of this script died on this line, after
# the interesting half had already passed. See log_epoch for why.
ROTATE_AT=$(log_epoch "$ROTATE_LINE")
DELAY=$(( DIE_AT - ROTATE_AT ))
ok "guard exited $DELAY s after declaring rotation (RotationExitDelay is 10s)"
[ "$DELAY" -ge 8 ] && [ "$DELAY" -le 25 ] \
  || die "the settling delay was ${DELAY}s; §6 says ~10s and the point is that restart: on-failure does not spin"
# THREE specifically, not merely non-zero. cmd/brollyguard maps
# guard.ErrMacaroonRotated to exitRotation=3 and everything else that goes wrong
# to exitConfig=1. Both restart under restart: on-failure, so a "non-zero" test
# would pass just as happily on a guard that died of a bad config — which means
# something entirely different and would make the rest of this script nonsense.
[ "$EXIT_CODE" = "3" ] \
  && ok "exit code 3 — guard.exitRotation, and non-zero is what makes restart: on-failure fire" \
  || die "the guard exited $EXIT_CODE; §6's rotation exit is 3 (exitRotation). 1 is exitConfig, which would mean something else entirely"

# ---------------------------------------------------------------------------
say "3. the server stayed up throughout (§11)"
S_STARTED_1=$(inspect "$SERVER" '{{.State.StartedAt}}')
[ "$S_STARTED_1" = "$S_STARTED_0" ] \
  && ok "the server container never restarted (StartedAt unchanged)" \
  || die "the server restarted: $S_STARTED_0 -> $S_STARTED_1. §11's crash-loop exception is the guard's alone"
BAD=$(awk '$2 != "200"' "$HEALTH_LOG" | wc -l | tr -d ' ')
SAMPLES=$(wc -l < "$HEALTH_LOG" | tr -d ' ')
# The floor first, and it is proportional to how long the watcher has been
# running rather than a fixed number. If the watcher subshell never produced
# output the log is empty, BAD is 0, and section 3's headline claim — the server
# stayed up — would pass on zero observations. A FIXED floor is the wrong shape:
# the first version demanded 30 samples and failed a run that reached here in 28
# seconds, which was the script working faster, not the server misbehaving.
WATCHED=$(( $(date -u +%s) - WATCH_FROM ))
WANT_SAMPLES=$(( WATCHED / 3 ))
[ "$SAMPLES" -ge "$WANT_SAMPLES" ] && [ "$SAMPLES" -gt 5 ] \
  || die "only $SAMPLES /health samples across ${WATCHED}s of watching (want at least $WANT_SAMPLES at one a second); the watcher was not running, so 'always 200' is vacuous"
[ "$BAD" = "0" ] \
  && ok "/health answered 200 on all $SAMPLES samples across the rotation" \
  || { awk '$2 != "200"' "$HEALTH_LOG" | head -5; die "$BAD of $SAMPLES /health samples were not 200"; }
# A BEFORE/AFTER pair, not a substring match.
#
# The first version grepped for the word "re-link", which node.html renders
# unconditionally — so it matched on a healthy page and could not fail. The
# second guessed at markup for "the guard is down" and matched nothing, because
# by the time section 3 runs the guard has usually already restarted and its own
# view of LND is healthy again; what is still broken is the SERVER's connection,
# which is using a credential the node has forgotten.
#
# So: record the state here and assert in section 5 that it recovered. A page
# that always says the same thing fails the pair, whichever thing it says.
NODE_DURING=$(curl -s -b "$JAR" "$APP/node" | sed -n 's|.*<dt>Connection</dt><dd>\([a-z]*\)</dd>.*|\1|p' | head -1)
[ -n "$NODE_DURING" ] || die "the Node page did not render a Connection state at all"
[ "$NODE_DURING" != "ready" ] \
  && ok "the Node page shows the connection as \"$NODE_DURING\" while the credential is dead — a state, not a crash (§11)" \
  || die "the Node page says the connection is ready while the node is rejecting our macaroon"
# 2f0: the operator is TOLD. LND refuses the stale recv.macaroon with the code it
# also gives a starting node, so until 2f0 the server logged "re-bake in case the
# credential is stale" at INFO and the page said connecting, on every real
# rotation. The log line, not the page's relink state: the line is durable, and
# the page is racy against the guard's re-bake, which is already under way.
#
# Expected to be there already: the server's stream meets the stale macaroon
# within one backoff of LND coming up, and says re-link on the attempt after
# that — a refusal from a node reporting a running stage takes a second
# observation to confirm, and that one waits minBackoff rather than the grown
# delay (2f0). The guard spent at least its 30s rotation window and 10s
# settling delay before section 2 let us through. The
# short wait is for the log reaching docker, not for the server — once the
# guard's restart (already under way, restart: on-failure) re-bakes
# recv.macaroon, a line not yet written never will be.
RELINK_LINE=""
RELINK_DEADLINE=40
for i in $(seq 1 10); do
  # The LATEST: a line from LND's shutdown may precede the one this asserts.
  RELINK_LINE=$(glog brollyzapper | grep 'lnd rejected our macaroon; re-link needed' | tail -1 || true)
  [ -n "$RELINK_LINE" ] && break
  sleep 2
done
if [ -z "$RELINK_LINE" ] && [ "$LND_ANSWERED_AFTER" -ge "$RELINK_DEADLINE" ]; then
  # NOT ASSERTED, and said as plainly as an ok: LND took ${LND_ANSWERED_AFTER}s,
  # by which point the server's retry gap is at or near its 60s ceiling and the
  # guard (10s probe + 30s window + 10s exit + restart) can re-bake before the
  # server ever meets the stale macaroon. Deliberately not an ok line.
  printf '   \033[33m--\033[0m   NOT ASSERTED: the server re-link line, because LND took %ss to answer and the guard can re-bake before the server retries. Re-run on a warm machine to assert it.\n' "$LND_ANSWERED_AFTER"
else
  [ -n "$RELINK_LINE" ] || die "the server never logged \"lnd rejected our macaroon; re-link needed\" while LND refused its recv.macaroon, though LND answered in ${LND_ANSWERED_AFTER}s; the operator was told connecting (2f0)"
  require_from_this_run "server re-link" "$RELINK_LINE"
  # After LND was STARTED, not merely after the run began: section 1 stops LND
  # first, and a line written while it shut down would satisfy the run check
  # without the rotation path having done anything (2f0 go-review).
  RELINK_AT=$(log_epoch "$RELINK_LINE")
  [ "$RELINK_AT" -ge "$LND_START_EPOCH" ] \
    || die "the server's re-link line was written $(( LND_START_EPOCH - RELINK_AT ))s before LND was started again — during its shutdown, not after the rotation"
  ok "the server logged \"re-link needed\" after the rotated LND started — LND's Unknown, read by the node's stage, confirmed by a second refusal (2f0)"
fi

# ---------------------------------------------------------------------------
say "4. the guard came back and re-baked"
for i in $(seq 1 90); do
  [ "$(inspect "$GUARD" '{{.RestartCount}}')" -gt "$G_RESTARTS_0" ] && break
  sleep 1
done
G_RESTARTS_1=$(inspect "$GUARD" '{{.RestartCount}}')
[ "$G_RESTARTS_1" -gt "$G_RESTARTS_0" ] \
  && ok "restart: on-failure brought the guard back (RestartCount $G_RESTARTS_0 -> $G_RESTARTS_1)" \
  || die "the guard did not restart"
# Up to lnd.ReBakeInterval (1 minute) plus a bake, and often a full interval
# more: the server's FIRST re-bake request usually lands while LND is still
# starting up, fails for that reason, and burns the interval. Measured: 39s
# from the guard's restart to the bake on a warm machine. Waiting three minutes
# here is not slack, it is the actual shape of the recovery.
for i in $(seq 1 90); do
  RECV_1=$(cred_stat recv.macaroon)
  [ "$RECV_1" != "$RECV_0" ] && [ "$RECV_1" != "missing" ] && break
  sleep 2
done
[ "$RECV_1" != "$RECV_0" ] \
  && ok "recv.macaroon re-baked: $RECV_0 -> $RECV_1" \
  || die "recv.macaroon is unchanged; the guard did not re-bake after the restart"
BAKE=$(glog guard | grep '"audit":"macaroon.bake"' | head -1)
require_from_this_run "macaroon.bake" "$BAKE"
# as0.7 criterion 2: WHOSE decision was it?
#
# The guard records why it baked. "asked for" is the server's RequestReceiveBake
# arriving over the socket; anything else came from the guard's own startup
# check. Before as0.7 every post-rotation bake said "asked for", because the
# guard came back, said "already present and within policy" about a credential
# the node had forgotten, and waited 39 seconds for someone to ask. The FIRST
# bake of this run is the one that matters, hence head -1.
# POSITIVE, and extracted with jq rather than sed.
#
# This was a negative assertion — "the reason is not 'asked for'" — pulled out
# with sed, and it failed backwards two ways. sed leaves the line unchanged when
# it matches nothing, and a whole JSON line is not equal to "asked for", so a
# missing or renamed field reported OK. And any other guard-initiated reason,
# including "there is none" (a MISSING credential, which is a different bug),
# passed as as0.7 working.
BAKE_REASON=$(echo "$BAKE" | sed 's/^[^{]*//' | jq -r '.reason // "«no reason field»"')
[ "$BAKE_REASON" = "the node no longer lists the root key it was baked under" ] \
  && ok "the guard re-baked on its own decision: \"$BAKE_REASON\"" \
  || die "the first bake after the restart gives the reason \"$BAKE_REASON\"; as0.7 requires the guard to decide FOR ITSELF that the node has forgotten the key. \"asked for\" means the server asked and the guard merely obeyed."
wait_audit_row macaroon.bake 90 \
  || die "the guard logged macaroon.bake but it never reached audit_events (d46.18)"
ok "the bake reached audit_events too"
# The caveats FIELD, not a substring anywhere in the line — "ipaddr" appears in
# the guard's own prose too, so grepping the whole line proves less than it looks.
CAVEATS=$(echo "$BAKE" | sed 's/.*"caveats":"//;s/".*//')
case "$CAVEATS" in
  "time-before "*", ipaddr $(cred_server_ip)") ok "re-baked under §6 policy: $CAVEATS" ;;
  *) die "the re-baked macaroon's caveats are \"$CAVEATS\"; §6 requires time-before and ipaddr <SERVER_IP>" ;;
esac
# The COUNT is a number the guard printed about itself, so it cannot tell five
# right permissions from five wrong ones. It is kept as a cheap regression on the
# shape; what actually proves the credential is receive-capable and IP-bound is
# section 5, which mints and settles with it from the pinned address.
echo "$BAKE" | grep -q '"permissions":"5"' \
  && ok "five permissions — the receive-only count (§6); section 5 is what proves it works" \
  || die "the re-baked macaroon reports $(echo "$BAKE" | grep -o '\"permissions\":\"[^\"]*\"') permissions, want 5"
TLS_1=$(cred_stat tls.cert)
ok "tls.cert: $TLS_0 -> $TLS_1 (re-copied; unchanged content is expected — only macaroons rotated)"

IDS_2=$(root_ids)
ok "node root key ids now: $IDS_2"
NEW_ID=$( { comm -13 <(echo "$IDS_1" | tr ',' '\n' | sort) <(echo "$IDS_2" | tr ',' '\n' | sort) || true; } | tr '\n' ' ')
[ -n "$(echo "$NEW_ID" | tr -d ' ')" ] \
  && ok "a NEW root key id appeared after the re-bake:$NEW_ID" \
  || die "no new root key id; the guard did not bake against the rotated node"
# `|| true`, because grep exits 1 when nothing matches and this is an
# ASSIGNMENT, not a condition — so under set -e the success case (no
# pre-rotation key survived) killed the script one line before it could say so.
OLD_SURVIVOR=$( { comm -12 <(echo "$IDS_0" | tr ',' '\n' | sort) <(echo "$IDS_2" | tr ',' '\n' | sort) | grep -v '^0$' || true; } | tr '\n' ' ')
[ -z "$(echo "$OLD_SURVIVOR" | tr -d ' ')" ] \
  && ok "none of the pre-rotation root key ids survive (0 is LND's own default)" \
  || die "a pre-rotation root key id is still listed:$OLD_SURVIVOR"

# ---------------------------------------------------------------------------
say "5. the server recovers with NO operator action"
# Nothing below clicks Re-link. If the server needed a human, this is where it
# would show: the invoice stream would still be rejected and the zap would never
# credit.
RECOVERED=""
for i in $(seq 1 60); do
  DOC=$(curl -s "$APP/.well-known/lnurlp/$NAME")
  RECIPIENT=$(echo "$DOC" | jq -r '.nostrPubkey // empty')
  CALLBACK=$(echo "$DOC" | jq -r '.callback // empty')
  if [ -n "$RECIPIENT" ] && [ -n "$CALLBACK" ]; then
    ZR=$("$ZT" request wss://relay.invalid "$RECIPIENT" "$AMOUNT_MSAT" -content "post-rotation")
    PR=$(curl -s -G "$CALLBACK" --data-urlencode "amount=$AMOUNT_MSAT" --data-urlencode "nostr=$ZR" | jq -r '.pr // empty')
    [ -n "$PR" ] && { RECOVERED=yes; break; }
  fi
  sleep 5
done
[ -n "$RECOVERED" ] || die "the app could not mint an invoice after the rotation; the server did not self-heal"
ok "an invoice was minted with the re-baked credential — no operator action taken"

PH=$(lncli_recv decodepayreq --pay_req "$PR" | jq -r .payment_hash)
lncli_payer payinvoice --force --pay_req "$PR" --timeout 60s >/dev/null 2>&1 || true
for i in $(seq 1 40); do
  [ "$(lncli_recv lookupinvoice --rhash "$PH" | jq -r .state)" = "SETTLED" ] && break
  sleep 1
done
[ "$(lncli_recv lookupinvoice --rhash "$PH" | jq -r .state)" = "SETTLED" ] || die "the invoice never settled"
CREDITED=""
for i in $(seq 1 40); do
  C=$(sql "SELECT COUNT(*) FROM txns WHERE payment_hash='$PH';")
  [ "$C" = "1" ] && { CREDITED=yes; break; }
  sleep 2
done
[ -n "$CREDITED" ] \
  && ok "the settlement credited the wallet — the invoice STREAM re-authenticated too, not just the mint path" \
  || die "the invoice settled but never credited; the stream did not recover"

# The other half of the pair: the same field, after recovery.
NODE_AFTER=""
for i in $(seq 1 30); do
  NODE_AFTER=$(curl -s -b "$JAR" "$APP/node" | sed -n 's|.*<dt>Connection</dt><dd>\([a-z]*\)</dd>.*|\1|p' | head -1)
  [ "$NODE_AFTER" = "ready" ] && break
  sleep 2
done
[ "$NODE_AFTER" = "ready" ] \
  && ok "the Node page shows the connection back to \"ready\" ($NODE_DURING -> ready), with no operator action" \
  || die "the Node page still shows \"$NODE_AFTER\" after recovery; the state never came back"

BAD=$(awk '$2 != "200"' "$HEALTH_LOG" | wc -l | tr -d ' ')
SAMPLES=$(wc -l < "$HEALTH_LOG" | tr -d ' ')
WATCHED=$(( $(date -u +%s) - WATCH_FROM ))
[ "$SAMPLES" -ge $(( WATCHED / 3 )) ] \
  || die "only $SAMPLES /health samples across ${WATCHED}s; the watcher stopped, so this says nothing"
[ "$BAD" = "0" ] || die "the server bounced at some point during the run"
ok "/health still 200 on every sample ($SAMPLES across ${WATCHED}s)"

printf '\n\033[32mROTATION PASSED\033[0m — §6'"'"'s rotation-exit path proven end to end on a real node.\n\n'
