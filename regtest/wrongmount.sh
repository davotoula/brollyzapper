#!/usr/bin/env bash
# as0.10 — a PERMANENTLY wrong admin.macaroon: one rotation exit, then a
# diagnosis instead of a crash loop.
#
# rotation.sh proves the exit repairs a STALE mount. This proves the exit is
# taken ONCE when it cannot: before as0.10 a guard whose mounted admin.macaroon
# the node would never accept exited 3, restarted into the same bytes, was
# rejected again, and exited again — once a minute under restart: on-failure,
# for ever, with the guard down and the pages that would have said why dark.
#
#   the mounted file is overwritten IN PLACE with bytes the node rejects
#     -> the guard's probes trip; it records the exit and its file's hash; exit 3
#     -> the restart re-resolves the mount onto the SAME inode, the same bytes
#     -> the probes trip again; the guard stays up this time, says why once
#        (preflight.refuse), and the Security and Node pages show it
#     -> the real bytes go back in place, the guard is restarted, and it is well
#
#   ./wrongmount.sh      against the WORKING TREE's images:
#                        docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
#
# The wrong bytes are the PAYER node's admin.macaroon: root key 0 of another
# macaroons.db, which to the receiving node is exactly what a pre-rotation
# admin.macaroon is (rotation.sh's step 1 makes that one by deleting the db).
# Taken from the payer rather than made by rotating, so this script restarts no
# LND, re-peers nothing, and leaves every other credential on the stack alone.
#
# IN PLACE — `cat > file`, never `mv` or `cp` over it — because a single-file
# bind mount follows the inode: replacing the file would leave the guard's mount
# on the old inode, the restart would re-resolve onto the new one, and that is
# rotation.sh's scenario, not this one. The same inode is what makes the restart
# land on the same bad file, which is the production shape: the wrong file
# mounted, or LND_ADMIN_MACAROON pointing at one.
#
# Afterwards the stack is left working: the real bytes are restored in place and
# the guard restarted, from an EXIT trap if an assertion fires first.
set -euo pipefail
cd "$(dirname "$0")"

# Default: tools/sqlite/Dockerfile's FROM, stated once (0vk.59; script_lint_test.go says why).
TOOL_IMAGE="${TOOL_IMAGE:-$(awk '$1 == "FROM" { print $2; exit }' tools/sqlite/Dockerfile 2>/dev/null || true)}"
[ -n "$TOOL_IMAGE" ] || { echo "FAIL could not read the tool image from tools/sqlite/Dockerfile's FROM line" >&2; exit 1; }
APP="http://localhost:${APP_PORT:-8080}"
PASS="${ADMIN_PASSWORD:-regtest-admin}"
LNDDIR="./data/lnd/data/chain/bitcoin/regtest"
PAYERDIR="./data/lnd-payer/data/chain/bitcoin/regtest"
# How long to wait for each rejection run to trip. Three probes at the guard's
# ten-second ProbeInterval, the first up to one interval after the rejection
# that arms the loop, plus the restart — with room to spare.
TRIP_TIMEOUT="${TRIP_TIMEOUT:-180}"
# How long the degraded guard must stay up to count. A guard that was going to
# exit a second time does so within one probe of the transition plus
# RotationExitDelay (10 s); this is three probes plus that delay plus margin,
# which is the brief's "longer than three probes plus the settling delay".
# Would change with guard.ProbeInterval or guard.RotationExitDelay.
HOLD_SECONDS="${HOLD_SECONDS:-60}"
# The one sentence the degraded transition logs, as a fixed fragment: it is the
# guard's audit line, and a bake refusal is preflight.refuse too.
STILL_REJECTED='this is not a rotation'
SECURITY_TITLE='Your node accepts the admin macaroon mounted into the guard'

JAR=$(mktemp); WORK=$(mktemp -d)
EVENTS="$WORK/events.log"
REAL="$WORK/admin.macaroon.real"
EVENTS_PID=""
PLANTED=""; RESTORED=""
cleanup() {
  local code=$?
  if [ -n "$PLANTED" ] && [ -z "$RESTORED" ] && [ -s "$REAL" ]; then
    # In place, like the plant, so the guard's mount sees the real bytes again.
    cat "$REAL" > "$LNDDIR/admin.macaroon" || true
    docker compose restart guard >/dev/null 2>&1 || true
    printf '   \033[90m..\033[0m   restored the real admin.macaroon in place and restarted the guard\n'
  fi
  if [ -n "$EVENTS_PID" ]; then
    kill "$EVENTS_PID" 2>/dev/null || true
    wait "$EVENTS_PID" 2>/dev/null || true
  fi
  rm -rf "$JAR" "$WORK"
  return $code
}
trap cleanup EXIT

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m   %s\n' "$*"; }
note() { printf '   \033[90m..\033[0m   %s\n' "$*"; }
die()  { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

guard_id()  { docker compose ps -q guard; }
inspect()   { docker inspect -f "$2" "$1"; }
inode()     { ls -i "$1" | awk '{print $1}'; }
login() {
  local tok
  tok=$(curl -s -c "$JAR" "$APP/login" | grep -o 'name="csrf_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
  curl -s -b "$JAR" -c "$JAR" -X POST "$APP/login" \
    --data-urlencode "csrf_token=$tok" --data-urlencode "password=$PASS" -o /dev/null
}
page() { curl -s -b "$JAR" "$APP/$1"; }
# The guard's own state file, from its volume. Never printed: it holds the hash.
guard_state() { docker run --rm -v brollyregtest_guard-data:/g "$TOOL_IMAGE" cat /g/guard-state.json; }
# Whether that file holds a rotation exit: 1 or 0, or the script dies. Captured
# before it is searched, and counted with grep -c: a read that failed must not
# read as "no memory", and grep -q under pipefail can turn a match into SIGPIPE.
rotation_exit_recorded() {
  local state
  state=$(guard_state) || die "could not read guard-state.json from the guard's volume"
  [ -n "$state" ] || die "guard-state.json read back empty"
  if [ "$(printf '%s' "$state" | grep -c '"rotation_exit"' || true)" = "0" ]; then echo 0; else echo 1; fi
}
# The Node page's guard line, as the <dd> after its <dt>.
node_guard_line() { page node | sed -n 's|.*<dt>LND reachable from the guard</dt><dd>\([^<]*\)</dd>.*|\1|p' | head -1; }
# The Security row's verdict cell, for the row carrying the title.
security_verdict() {
  page security | python3 -c '
import sys, re
html, title = sys.stdin.read(), sys.argv[1]
for row in re.findall(r"<tr>(.*?)</tr>", html, re.S):
    if title in row:
        cells = re.findall(r"<td>(.*?)</td>", row, re.S)
        print(cells[0].strip() if cells else "")
        break' "$SECURITY_TITLE"
}

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
[ -f "$PAYERDIR/admin.macaroon" ] || die "$PAYERDIR/admin.macaroon is not here; the payer node supplies the bytes the receiving node rejects"
# Scoped to this run, both ways — see rotation.sh, which paid for each: --since
# with a trailing Z (a bare stamp is local time), and every matched line's own
# timestamp checked against the start.
RUN_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
RUN_START_EPOCH=$(date -u +%s)
glog() { docker compose logs --since "$RUN_START" "$@" 2>&1; }
log_epoch() {
  echo "$1" | grep -o '"time":"[^"]*"' | head -1 | sed 's/.*"time":"//;s/"//' | python3 -c '
import sys, re, datetime
raw = sys.stdin.read().strip()
raw = re.sub(r"\.(\d{6})\d*", r".\1", raw).replace("Z", "+00:00")
print(int(datetime.datetime.fromisoformat(raw).timestamp()))'
}
require_from_this_run() {
  local when; when=$(log_epoch "$2")
  [ -n "$when" ] || die "could not read a timestamp out of the $1 line"
  [ "$when" -ge "$RUN_START_EPOCH" ] \
    || die "the $1 line was written $(( RUN_START_EPOCH - when ))s BEFORE this run started; it belongs to an earlier run"
}
GUARD=$(guard_id)
[ -n "$GUARD" ] || die "the stack is not up"
need_sqlite
[ "$(curl -s -o /dev/null -w '%{http_code}' "$APP/health")" = "200" ] || die "the app is not healthy to begin with"
login
note "guard image: $(inspect "$GUARD" '{{.Config.Image}}')"
[ "$(node_guard_line)" = "yes" ] || die "the guard cannot reach LND before anything was planted: \"$(node_guard_line)\""
case "$(security_verdict)" in
  pass) ;;
  "") die "the Security page has no \"$SECURITY_TITLE\" row: this stack is not running a build with as0.10 (after 0.1.22, run it against docker-compose.build.yml)" ;;
  *) die "the Security row \"$SECURITY_TITLE\" is \"$(security_verdict)\" before anything was planted, want pass" ;;
esac
ok "the guard reaches LND, and the Security row passes"
# An ASSIGNMENT, so a die inside the substitution ends the script (set -e); in a
# test it would end only the subshell and read as an answer.
RECORDED=$(rotation_exit_recorded)
[ "$RECORDED" = "0" ] \
  || die "the guard's state already holds a rotation exit; a previous run did not finish, and this one would start degraded"
cp "$LNDDIR/admin.macaroon" "$REAL"
cmp -s "$REAL" "$PAYERDIR/admin.macaroon" && die "the payer's admin.macaroon is byte-identical to the receiver's; it cannot be the wrong file"
INODE_0=$(inode "$LNDDIR/admin.macaroon")
G_RESTARTS_0=$(inspect "$GUARD" '{{.RestartCount}}')
ok "real admin.macaroon kept aside (inode $INODE_0); guard restarts=$G_RESTARTS_0"
# The die event carries the exit code; .State.ExitCode is the CURRENT run's once
# the container is back (rotation.sh §2).
docker events --filter "container=$GUARD" --filter 'event=die' --format '{{.Time}} {{.Actor.Attributes.exitCode}}' >> "$EVENTS" &
EVENTS_PID=$!
sleep 2

# ---------------------------------------------------------------------------
say "1. mount the wrong admin.macaroon, in place"
PLANTED=yes
cat "$PAYERDIR/admin.macaroon" > "$LNDDIR/admin.macaroon"
[ "$(inode "$LNDDIR/admin.macaroon")" = "$INODE_0" ] \
  || die "the inode changed ($INODE_0 -> $(inode "$LNDDIR/admin.macaroon")); the plant must be in place, or this is rotation.sh"
cmp -s "$LNDDIR/admin.macaroon" "$PAYERDIR/admin.macaroon" || die "the plant did not write the payer's bytes"
ok "the mounted file now holds another node's admin.macaroon, same inode"

# ---------------------------------------------------------------------------
say "2. the first rejection run: one exit, code 3"
# ONE thing arms the loop from outside: a Node page render, which asks the guard
# for Status, whose GetInfo is rejected. It arms and never advances (as0.8); the
# three rejections that trip are the guard's own probes. The server's own
# five-minute guard poll would arm it too, only slower. Rendered again every 15s
# in case the first landed on the page's ten-second status cache.
START=$(date +%s)
while [ $(( $(date +%s) - START )) -lt "$TRIP_TIMEOUT" ]; do
  [ -s "$EVENTS" ] && break
  page node >/dev/null || true
  sleep 15
done
[ -s "$EVENTS" ] || die "the guard did not exit within ${TRIP_TIMEOUT}s of being handed a rejected admin.macaroon"
[ "$(wc -l < "$EVENTS" | tr -d ' ')" = "1" ] || die "the guard died $(wc -l < "$EVENTS" | tr -d ' ') times already: $(cat "$EVENTS")"
[ "$(awk 'END{print $2}' "$EVENTS")" = "3" ] \
  || die "the guard exited $(awk 'END{print $2}' "$EVENTS"); the rotation exit is 3 (exitRotation)"
ROTATE_LINE=$(glog guard | grep '"audit":"macaroon.rotate"' | tail -1)
[ -n "$ROTATE_LINE" ] || die "the guard exited 3 without logging macaroon.rotate"
require_from_this_run "macaroon.rotate" "$ROTATE_LINE"
ok "exit 3 once, after audit=macaroon.rotate from this run — the one exit §6 sanctions"

# ---------------------------------------------------------------------------
say "3. the restart over the same bytes: the guard stays up"
for i in $(seq 1 90); do
  [ "$(inspect "$GUARD" '{{.RestartCount}}')" -gt "$G_RESTARTS_0" ] && [ "$(inspect "$GUARD" '{{.State.Running}}')" = "true" ] && break
  sleep 1
done
G_RESTARTS_1=$(inspect "$GUARD" '{{.RestartCount}}')
[ "$G_RESTARTS_1" -gt "$G_RESTARTS_0" ] || die "restart: on-failure did not bring the guard back"
[ "$(inode "$LNDDIR/admin.macaroon")" = "$INODE_0" ] || die "the mount's inode moved during the restart"
G_STARTED_1=$(inspect "$GUARD" '{{.State.StartedAt}}')
ok "restarted (RestartCount $G_RESTARTS_0 -> $G_RESTARTS_1), onto the same inode and the same bytes"
# The restarted guard arms itself: its startup check asks the node for the
# receive credential's root key with the rejected admin.macaroon.
STILL=""
START=$(date +%s)
while [ $(( $(date +%s) - START )) -lt "$TRIP_TIMEOUT" ]; do
  page node >/dev/null || true   # arms only, as in step 2; the startup check usually has already
  STILL=$(glog guard | grep '"audit":"preflight.refuse"' | grep "$STILL_REJECTED" | tail -1 || true)
  [ -n "$STILL" ] && break
  [ "$(wc -l < "$EVENTS" | tr -d ' ')" = "1" ] \
    || die "the guard exited a SECOND time over the same bytes — the crash loop as0.10 exists to end (is this stack running the working tree?): $(tail -1 "$EVENTS")"
  sleep 5
done
[ -n "$STILL" ] || die "the restarted guard never logged preflight.refuse for the unchanged mount within ${TRIP_TIMEOUT}s"
require_from_this_run "preflight.refuse" "$STILL"
TRANSITION_AT=$(log_epoch "$STILL")
ok "the second rejection run reached the threshold and said so instead of exiting"
while [ $(( $(date -u +%s) - TRANSITION_AT )) -lt "$HOLD_SECONDS" ]; do sleep 5; done
[ "$(wc -l < "$EVENTS" | tr -d ' ')" = "1" ] || die "the guard exited again after the transition: $(tail -1 "$EVENTS")"
[ "$(inspect "$GUARD" '{{.State.StartedAt}}')" = "$G_STARTED_1" ] || die "the guard's StartedAt moved during the hold"
[ "$(inspect "$GUARD" '{{.RestartCount}}')" = "$G_RESTARTS_1" ] || die "the guard restarted during the hold"
ok "still up ${HOLD_SECONDS}s after the transition: StartedAt unchanged, restarts=$G_RESTARTS_1, one die event in the run"

# ---------------------------------------------------------------------------
say "4. said once, durably"
COUNT=$(glog guard | grep '"audit":"preflight.refuse"' | grep -c "$STILL_REJECTED" || true)
[ "$COUNT" = "1" ] || die "the unchanged-mount preflight.refuse was logged $COUNT times by this run, want exactly 1 — every probe after the transition is the same finding"
ok "audit=preflight.refuse logged once by this run, across $(( $(date -u +%s) - TRANSITION_AT ))s of probing"
ROWS=0
for i in $(seq 1 60); do
  page node >/dev/null || true   # a render is what makes the server collect the guard's events
  ROWS=$(sql "SELECT COUNT(*) FROM audit_events WHERE event='preflight.refuse' AND detail LIKE '%exited_for_rotation_at%' AND created_at >= $RUN_START_EPOCH;")
  [ "$ROWS" -gt 0 ] && break
  sleep 2
done
[ "$ROWS" = "1" ] || die "audit_events holds $ROWS unchanged-mount preflight.refuse rows from this run, want 1 (§12's durable half, d46.18)"
ok "and it reached audit_events, once"

# ---------------------------------------------------------------------------
say "5. the pages say what is wrong"
VERDICT=""; LINE=""
for i in $(seq 1 30); do
  VERDICT=$(security_verdict); LINE=$(node_guard_line)
  [ "$VERDICT" = "FAIL" ] && case "$LINE" in "no — your node rejects the admin macaroon"*) true ;; *) false ;; esac && break
  sleep 2
done
[ "$VERDICT" = "FAIL" ] || die "the Security row \"$SECURITY_TITLE\" is \"$VERDICT\", want FAIL"
ok "Security: \"$SECURITY_TITLE\" — FAIL"
case "$LINE" in
  "no — your node rejects the admin macaroon"*) ok "Node: LND reachable from the guard — $LINE" ;;
  *) die "the Node page's guard line is \"$LINE\"; want it to say no, and why" ;;
esac

# ---------------------------------------------------------------------------
say "6. the repair: the real bytes back in place, and a restart"
cat "$REAL" > "$LNDDIR/admin.macaroon"
RESTORED=yes
cmp -s "$LNDDIR/admin.macaroon" "$REAL" || die "the restore did not write the real bytes"
docker compose restart guard >/dev/null
ok "real admin.macaroon restored in place; guard restarted"
for i in $(seq 1 60); do
  [ "$(node_guard_line)" = "yes" ] && [ "$(security_verdict)" = "pass" ] && break
  sleep 2
done
[ "$(node_guard_line)" = "yes" ] || die "the Node page still says \"$(node_guard_line)\" after the repair"
[ "$(security_verdict)" = "pass" ] || die "the Security row is \"$(security_verdict)\" after the repair, want pass"
ok "the guard reaches LND again, and the Security row passes"
CHANGED=$(glog guard | grep 'has changed since the guard exited for rotation' | tail -1 || true)
[ -n "$CHANGED" ] || die "the restarted guard did not log that the mounted file had changed"
require_from_this_run "mount-changed" "$CHANGED"
ok "the guard noticed the file had changed"
RECORDED=$(rotation_exit_recorded)
[ "$RECORDED" = "0" ] || die "guard-state.json still holds the rotation exit after the repair"
ok "the memory is cleared"
# A bake, if the guard will make one. Inside MinBakeInterval (30 m) of the last
# receive bake it refuses a repeat by design (20i.3), and that refusal is not
# the admin macaroon's doing — so the half is skipped out loud rather than
# failed or faked.
# Nanoseconds trimmed to micro before parsing, as log_epoch does.
STATE=$(guard_state) || die "could not read guard-state.json from the guard's volume"
BAKED_AT=$(printf '%s' "$STATE" | python3 -c '
import sys, json, re, datetime
v = json.load(sys.stdin).get("receive_baked_at", "")
v = re.sub(r"\.(\d{6})\d*", r".\1", v).replace("Z", "+00:00")
print(int(datetime.datetime.fromisoformat(v).timestamp()) if v else 0)')
AGE=$(( $(date -u +%s) - BAKED_AT ))
if [ "$AGE" -ge 1800 ]; then
  TOK=$(page node | grep -o 'name="csrf_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
  FLASH=$(curl -s -b "$JAR" -o /dev/null -w '%{redirect_url}' -X POST "$APP/node/relink" --data-urlencode "csrf_token=$TOK")
  case "$FLASH" in
    *flash=saved*) ok "Re-link baked a receive macaroon with the restored admin.macaroon" ;;
    *) die "Re-link after the repair redirected to $FLASH, want flash=saved" ;;
  esac
  BAKE=$(glog guard | grep '"audit":"macaroon.bake"' | tail -1)
  [ -n "$BAKE" ] || die "Re-link said saved but the guard logged no macaroon.bake"
  require_from_this_run "macaroon.bake" "$BAKE"
  ok "audit=macaroon.bake from this run"
else
  note "SKIPPED the bake: the last receive bake was ${AGE}s ago, inside MinBakeInterval (1800s), where the guard refuses a repeat by design. Re-run later for that half"
fi
[ "$(curl -s -o /dev/null -w '%{http_code}' "$APP/health")" = "200" ] || die "the app is not healthy at the end"

printf '\n\033[32mWRONG MOUNT PASSED\033[0m — one rotation exit, then a diagnosis rather than a crash loop.\n\n'
