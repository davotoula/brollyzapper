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
payment()  { guardctl status | jq -r '.max_payment_msat // 0'; }

# restore_cap <control> <sats> — the ceremony, for TEARDOWN only.
#
# §§1-7 write the three steps out on purpose: the ceremony is this script's
# subject and they assert between them. §8 asserts only the end state, and once
# it had two caps to put back it was carrying the triple twice.
restore_cap() {
  guardctl authorise "$1" "$2" >/dev/null || die "could not re-authorise $1 to $2 sats"
  local code
  code=$(guardctl_op read-code) || die "no code to restore $1 with"
  guardctl apply "$1" "$2" "$code" || die "could not restore $1 to $2 sats"
}

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
say "7. the two caps must stay consistent, and the refusal says which to move"
# `c8q`. The first full regtest run proved the ceremony and the spend paths and
# never once asked for a cap pair the guard must refuse — zero `limit first`
# lines across all seven suites — so `8vj`'s direction-aware remedy and `pou`'s
# request-time refusal had never crossed the container boundary. Both have unit
# tests; this is their twin with the operator's own tools.
#
# THE NUMBERS ARE DERIVED, not written down. §6 leaves the window halved, so a
# section that hardcoded the compose values would assert against a state the
# script itself had just changed — and would go quietly wrong the day §6 moves.
WINDOW_NOW=$(window)
PAYMENT_ORIGINAL=$(payment)
[ "$PAYMENT_ORIGINAL" -gt 0 ] || die "the per-payment cap is $PAYMENT_ORIGINAL msat; this stack sets one"
PAYMENT_SATS=$((PAYMENT_ORIGINAL / 1000))

# (1) TIGHTENING the window below the per-payment cap. Refused — and the remedy
# names the control the operator is NOT editing, which is the whole of `8vj`.
# The box priced the old wording at ten times the ceiling the operator wanted.
# HALF THE PER-PAYMENT CAP, derived rather than a constant: it must be BELOW the
# cap (or there is nothing to refuse) and below the CURRENT window (or the apply
# is a loosening, refused for want of a code, and the assertion below would fail
# on the wrong message). Halving satisfies both without a magic number.
BELOW=$((PAYMENT_SATS / 2))
# The floor claim 3 drops the per-payment cap to, named once because four lines
# and a comment read it — one of them used to premultiply it into msat by hand.
FLOOR=10000
[ "$BELOW" -gt 0 ] || die "the per-payment cap is only $PAYMENT_SATS sats; this claim needs room beneath it"
[ "$BELOW" -lt "$((WINDOW_NOW / 1000))" ] || die "the window is $((WINDOW_NOW / 1000)) sats and this claim needs to TIGHTEN it to $BELOW; a raise would be refused for want of a code, not by the cap pair"
# THE TEXT AND NOT THE EXIT, because the exit was already non-zero before `8vj`:
# that bead changed only what the operator READS, so an assertion on the status
# code would have passed against the bug it was written for. guardctl puts the
# guard's error on stderr and nothing on stdout, so 2>&1 loses nothing — the
# shape spend.sh and ipaddr.sh already use.
TIGHTEN_ERR=$(guardctl apply spend_cap "$BELOW" 2>&1) \
  && die "lowering the 24-hour limit to $BELOW sats was ACCEPTED, leaving a per-payment limit of $PAYMENT_SATS sats that can never be reached"
case "$TIGHTEN_ERR" in
  *"a per-payment limit of $PAYMENT_SATS sats is above the 24-hour limit of $BELOW sats"*) ;;
  *) die "the refusal does not name both caps in sats: $TIGHTEN_ERR" ;;
esac
case "$TIGHTEN_ERR" in
  *"lower the per-payment limit first") ;;
  *) die "an operator TIGHTENING the window was told to move the wrong control (8vj): $TIGHTEN_ERR" ;;
esac
[ "$(window)" = "$WINDOW_NOW" ] || die "the window moved on a refused tightening: $(window) msat, want $WINDOW_NOW"
ok "tightening the window below the per-payment cap is refused, and names the per-payment cap"

# (2) LOOSENING the per-payment cap above the window, refused AT THE REQUEST.
# `pou`: the operator is not sent to read a code for a change that could never
# be applied. Three separate costs to three separate people, so three
# assertions — no code, nothing outstanding, no ceremony spent.
ABOVE=$((WINDOW_NOW / 1000 + 50000))
# THE FILE IS ABSENT BEFORE, TOO, and saying so is what stops the assertion below
# from passing vacuously. "No file after the refusal" is only evidence if a file
# could have appeared. It is §6 that leaves it absent, not §4 — §6 asks for one
# more grant and then offers the code against a DIFFERENT value, which the guard
# discards outright (`grant.Change != change` -> discardAuthorisation, which
# clears the file). Asserted rather than assumed: that is two sections away and
# one edit from being untrue.
if guardctl_op read-code >/dev/null 2>&1; then
  die "an authorisation file exists before the refused request; the no-file assertion below would prove nothing"
fi
# THE COMMAND IS THE ASSERTION. It must be `authorise`, not `apply`: before `pou`
# the guard checked the cap pair only at ApplyChange, so this REQUEST succeeded,
# wrote the file and spent the audit budget, and the operator learnt the ordering
# rule at the most expensive moment. A version of this section pointed at `apply`
# passes every line below — measured, on this stack — because an apply-time
# refusal leaves nothing pending and no file either. Those three lines record the
# COSTS; this one line is what tells request-time from apply-time.
LOOSEN_ERR=$(guardctl authorise payment_cap "$ABOVE" 2>&1) \
  && die "the guard AUTHORISED a per-payment cap of $ABOVE sats above a $((WINDOW_NOW / 1000))-sat window; pou refuses this at the request"
case "$LOOSEN_ERR" in
  *"raise the 24-hour limit first") ;;
  *) die "an operator RAISING the per-payment cap was told to move the wrong control (8vj): $LOOSEN_ERR" ;;
esac
[ "$(pending)" = "false" ] || die "a refused request left an authorisation outstanding; there is nothing for the operator to redeem"
if guardctl_op read-code >/dev/null 2>&1; then
  die "a refused request wrote an authorisation file; the operator was sent to read a code for a change that can never be applied"
fi
ok "the loosening is refused at the request: no file, nothing pending, and the remedy names the window"

# (3) THE RIGHT ORDER WORKS, which is what makes the refusal a remedy rather
# than a wall: do what the message said, and the change goes through.
guardctl apply payment_cap "$FLOOR" \
  || die "lowering the per-payment cap to $FLOOR sats was refused; tightening must cost nothing"
[ "$(payment)" = "$((FLOOR * 1000))" ] || die "the per-payment cap is $(payment) msat after lowering it to $FLOOR sats"
guardctl apply spend_cap "$BELOW" \
  || die "the window would not go to $BELOW sats even after the per-payment cap was lowered out of its way"
[ "$(window)" = "$((BELOW * 1000))" ] || die "the window is $(window) msat, want $((BELOW * 1000))"
ok "doing what the remedy says works: lower the per-payment limit, then the window"

# AND THE REFUSAL SPENT NO CEREMONY BUDGET. `pou` returns before
# auditAuthorisation precisely so a refused request cannot exhaust a bound an
# attacker never held a code for; a valid request afterwards proves it, and the
# two tightenings in between cost no ceremony, so nothing has consumed the budget
# except — if the bug were back — the refusal itself.
#
# IT RUNS HERE, AFTER CLAIM 3, AND NOT DIRECTLY AFTER THE REFUSAL, because it
# needs headroom the cap pair allows: a request for the CURRENT value is refused
# as "not a loosening" (`loosens` is checked before checkCapPair, so it would
# pass for the wrong reason), and a request above the window is refused as the
# pair. Claim 3 has just left the per-payment cap at the floor beneath a
# $BELOW-sat window, so a raise between the two is valid by construction. An
# earlier version derived it from the cap alone and died whenever an aborted run
# had left the window low — measured, twice, while planting.
NUDGE=$(( FLOOR + (BELOW - FLOOR) / 2 ))
guardctl authorise payment_cap "$NUDGE" >/dev/null \
  || die "a valid request for $NUDGE sats was refused after an invalid one; the refusal spent ceremony budget it must not touch"
NUDGE_CODE=$(guardctl_op read-code) || die "no readable code for the valid request after the refusal"
guardctl apply payment_cap "$NUDGE" "$NUDGE_CODE" \
  || die "the code for the valid request would not apply"
[ "$(payment)" = "$((NUDGE * 1000))" ] || die "the per-payment cap is $(payment) msat, want $((NUDGE * 1000))"
ok "a valid request afterwards still gets a code, and it redeems: the refusal spent no budget"

# ---------------------------------------------------------------------------
say "8. put the stack back"
# THE WINDOW FIRST, AND THE ORDER IS LOAD-BEARING: §7 left the per-payment cap
# beneath the window, and raising it back while the window is still low is the
# very pair the guard refuses. Restoring in the other order would fail on the
# rule this script just spent a section proving.
restore_cap spend_cap $((BEFORE / 1000))
[ "$(window)" = "$BEFORE" ] || die "the cap is $(window) msat, want the original $BEFORE"

# THEN THE PER-PAYMENT CAP, which is a loosening too and so is its own ceremony.
#
# cap.sh IS THE SUITE THAT DEPENDS ON THIS, and the dependency is exact: it pays
# AMOUNT_SATS=20000 against the window it reads from status, so a per-payment cap
# left at §7's NUDGE refuses its FIRST attempt and it dies saying that proves
# nothing about the window. NOT nwc.sh — its max_payment_msat is a column on
# nwc_connections, the per-connection cap, with no bearing on the guard's. A
# suite that leaves the caps where it found them is the only kind that can be run
# in any order.
restore_cap payment_cap $((PAYMENT_ORIGINAL / 1000))
[ "$(payment)" = "$PAYMENT_ORIGINAL" ] || die "the per-payment cap is $(payment) msat, want the original $PAYMENT_ORIGINAL"
[ "$(pending)" = "false" ] || die "an authorisation is still outstanding; the next suite would find the stack mid-ceremony"
guardctl revoke-spend >/dev/null 2>&1 || true
ok "both caps are back — $BEFORE msat window, $PAYMENT_ORIGINAL msat per payment — nothing pending, and sending is off"

printf '\n\033[1;32m== all criteria passed\033[0m\n'
