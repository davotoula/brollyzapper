#!/usr/bin/env bash
# `06v` — the operator's ceremony, against the real containers.
#
# The unit tests prove the guard refuses what it should. This proves the thing
# that cannot be proved in a process: that the CONTAINER BOUNDARY is where the
# code lives. The server's mounts are `data/server` and `data/credentials:ro`
# and nothing else, so a code written into `data/guard` is unreachable from the
# container the whole design defends against — and that is a fact about
# docker-compose.yml, not about Go.
#
# It also drives the ceremony end to end in the operator's own steps, which is
# the seam the wave brief names: the server relays a code it cannot mint, and
# the guard verifies it against state the server cannot read. Both ends have
# unit tests; the wire between them is what this runs.
#
# Bakes macaroons and revokes root keys. Regtest only, never a real node.
set -euo pipefail
cd "$(dirname "$0")"

TOOL_IMAGE="${TOOL_IMAGE:-alpine:3.20}"
CRED_VOLUME="${CRED_VOLUME:-brollyregtest_credentials}"
GUARD_DATA_VOLUME="${GUARD_DATA_VOLUME:-brollyregtest_guard-data}"
# The compose service, not the container: `brollyzapper` here, `server` on
# Umbrel. Named once, because `docker compose ps -q <wrong name>` prints an
# empty string and an assertion built on one inspects nothing.
SERVER_SERVICE="${SERVER_SERVICE:-brollyzapper}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m   %s\n' "$*"; }
note() { printf '   \033[90m..\033[0m   %s\n' "$*"; }
die()  { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

# guardctl <command> — what the SERVER can do: the socket, and nothing else.
guardctl() {
  docker run --rm -v "$CRED_VOLUME:/credentials" -v "$WORK/guardctl:/guardctl:ro" \
    "$TOOL_IMAGE" /guardctl "$@"
}

# guardctl_op <command> — what the OPERATOR can do: the same, plus the guard's
# own volume. The split is the whole subject of this script.
guardctl_op() {
  docker run --rm -v "$CRED_VOLUME:/credentials" -v "$GUARD_DATA_VOLUME:/guard:ro" \
    -v "$WORK/guardctl:/guardctl:ro" "$TOOL_IMAGE" /guardctl "$@"
}

latched()  { guardctl status | jq -r '.sending_latched // false'; }
pending()  { guardctl status | jq -r '.authorisation_pending // false'; }
window()   { guardctl status | jq -r '.spend_limit_msat // 0'; }

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

# A clean slate. Revoking drops the latch, which is what makes step 1 mean
# something — and it is the production path, not a state file edit.
guardctl revoke-spend >/dev/null 2>&1 || true
[ "$(latched)" = "false" ] || die "sending is still latched after a revoke; 'off must latch off' does not hold"
ok "starting from a receive-only install: the latch is off"

# ---------------------------------------------------------------------------
say "1. the SERVER alone cannot turn sending on"
# The path a compromised server has, in full: the socket, with no code. This is
# the assertion the whole wave exists for.
if guardctl apply sending on >/dev/null 2>&1; then
  die "sending was turned on over the socket with no authorisation; a compromised server can mint spend authority"
fi
if guardctl bake-spend >/dev/null 2>&1; then
  die "a spend macaroon was baked with the latch off"
fi
ok "the socket alone gets nowhere"

# ---------------------------------------------------------------------------
say "2. the guard writes the code where the SERVER cannot read it"
guardctl authorise sending on >/dev/null || die "the guard would not write an authorisation"
[ "$(pending)" = "true" ] || die "the guard says no authorisation is outstanding after writing one"

# THE CONTAINER BOUNDARY, asserted rather than assumed, and asserted through
# `docker inspect` rather than by trying to read the file from inside the
# server.
#
# THE OBVIOUS TEST HERE PASSES BACKWARDS. `docker compose exec -T server cat
# /guard/authorisation.txt` would fail on a correct stack AND on a broken one,
# because the server image is distroless/static and has no shell and no cat —
# the exec fails either way, the script sees a non-zero exit, and the assertion
# reports a pass having observed nothing. This asks the daemon what the
# container's mounts ARE, which is the fact the property rests on and is
# answerable without running anything inside it.
MOUNTS=$(docker inspect --format '{{range .Mounts}}{{.Destination}} {{end}}'   "$(docker compose ps -q "$SERVER_SERVICE")") || die "could not inspect the server container"
note "the server's mounts: $MOUNTS"
case " $MOUNTS " in
  *" /guard "*)
    die "the SERVER container mounts the guard's data directory. The code is the only thing standing between a compromised server and spend authority, and it is not out of reach" ;;
esac
# And the positive control: the guard DOES mount it, so a stack where nothing
# mounted it anywhere would fail here rather than reading as a pass.
GUARD_MOUNTS=$(docker inspect --format '{{range .Mounts}}{{.Destination}} {{end}}'   "$(docker compose ps -q guard)") || die "could not inspect the guard container"
case " $GUARD_MOUNTS " in
  *" /guard "*) : ;;
  *) die "the GUARD does not mount /guard either; this assertion is comparing two absences and proves nothing" ;;
esac
ok "the server container has no mount for the guard's data directory, and the guard does"

# And the operator can, through a mount only they have.
FILE=$(docker run --rm -v "$GUARD_DATA_VOLUME:/guard:ro" "$TOOL_IMAGE" cat /guard/authorisation.txt) \
  || die "the operator cannot read the authorisation file either; the ceremony has no first step"
case "$FILE" in
  *"TURN SENDING ON"*) : ;;
  *) die "the authorisation file does not say what is being authorised; it is the one account of the pending change the server did not write, and it is the only reason typing the code is safe" ;;
esac
ok "the operator can read it, and it says what is being authorised"

# ---------------------------------------------------------------------------
say "3. a wrong code changes nothing, and is bounded"
# Three, which is maxAuthorisationAttempts. The third spends the grant.
for attempt in 1 2 3; do
  if guardctl apply sending on "0000-0000" >/dev/null 2>&1; then
    die "attempt $attempt: a wrong code was accepted"
  fi
done
[ "$(latched)" = "false" ] || die "sending was latched by a run of wrong codes"
[ "$(pending)" = "false" ] || die "the grant survived the attempt bound; it stays a standing target for the one attacker with unlimited local tries"
ok "three wrong codes changed nothing and spent the grant"

# ---------------------------------------------------------------------------
say "4. the operator's code turns sending on"
guardctl authorise sending on >/dev/null || die "the guard would not write a second authorisation"
CODE=$(guardctl_op read-code) || die "no readable code"
[ -n "$CODE" ] || die "the authorisation file carries no code"
note "the operator read a code out of the guard's own file"
guardctl apply sending on "$CODE" || die "the guard refused the code it had just written"
[ "$(latched)" = "true" ] || die "the latch is still off after a completed ceremony"
[ "$(pending)" = "false" ] || die "the grant was not consumed on use; a captured code would work twice"
guardctl bake-spend || die "the bake was still refused after the ceremony"
ok "sending is on, and the spend macaroon is baked"

# ---------------------------------------------------------------------------
say "5. replaying the spent code does not re-mint after a revoke"
# The attack the one-time rule exists for: a server that captured a code waits
# for the operator to disable, then turns sending back on without them.
guardctl revoke-spend || die "the guard refused to revoke"
[ "$(latched)" = "false" ] || die "revoking left the latch on; 'off must latch off' does not hold"
if guardctl apply sending on "$CODE" >/dev/null 2>&1; then
  die "a spent authorisation code turned sending back on"
fi
ok "the spent code is dead"

# ---------------------------------------------------------------------------
say "6. tightening is free and loosening is not — on the CAPS"
# The larger exposure of the two (`06v`): a control that let a compromised
# server raise its own ceiling would harm every sending install, not only one
# that never enabled sending.
BEFORE=$(window)
[ "$BEFORE" -gt 0 ] || die "the window cap is $BEFORE msat; this stack sets one, so something is wrong before the assertion starts"
LOWER=$((BEFORE / 2))
guardctl apply spend_cap $((LOWER / 1000)) \
  || die "lowering the 24-hour limit was refused; tightening must cost the operator nothing"
[ "$(window)" = "$LOWER" ] || die "the window cap is $(window) msat after lowering it to $LOWER"
ok "the cap was lowered with no code"

if guardctl apply spend_cap $((BEFORE / 1000)) >/dev/null 2>&1; then
  die "the 24-hour limit was RAISED with no code; a compromised server can lift its own ceiling"
fi
[ "$(window)" = "$LOWER" ] || die "the cap moved on a refused raise"
ok "raising it needs the ceremony"

guardctl authorise spend_cap $((BEFORE / 1000)) >/dev/null || die "the guard would not authorise a raise"
CAP_CODE=$(guardctl_op read-code) || die "no readable code for the cap raise"
# BOUND TO THE CHANGE, value and all: a code issued for one number must not be
# spendable on another. This is the phishing shape — the operator reads one
# sentence and authorises something else.
if guardctl apply spend_cap $((BEFORE * 100 / 1000)) "$CAP_CODE" >/dev/null 2>&1; then
  die "a code issued to raise the limit to $BEFORE msat was spent raising it a hundredfold"
fi
ok "a code issued for one value cannot be spent on another"

# ---------------------------------------------------------------------------
say "7. put the stack back"
guardctl authorise spend_cap $((BEFORE / 1000)) >/dev/null || die "could not re-authorise"
RESTORE=$(guardctl_op read-code) || die "no code to restore the cap with"
guardctl apply spend_cap $((BEFORE / 1000)) "$RESTORE" || die "could not restore the cap"
[ "$(window)" = "$BEFORE" ] || die "the cap is $(window) msat, want the original $BEFORE"
guardctl revoke-spend >/dev/null 2>&1 || true
ok "the cap is back at $BEFORE msat and sending is off"

printf '\n\033[1;32m== all criteria passed\033[0m\n'
