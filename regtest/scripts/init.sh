#!/bin/sh
# Mines, funds, opens a channel, and refuses to exit until the guard's two
# credential files exist. Everything criterion 1 calls "no manual steps".
#
# Runs in the LND image: lncli, wget, jq and sh are what is available here.
set -eu

CHANNEL_SAT="${CHANNEL_SAT:-5000000}"
PUSH_SAT="${PUSH_SAT:-0}"
FUND_BTC="${FUND_BTC:-0.5}"

MACAROON=/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon
TLSCERT=/root/.lnd/tls.cert

say() { echo "[init] $*"; }

# bitcoind JSON-RPC. Credentials in the URL because busybox wget has no
# --http-user, and this is a throwaway regtest chain.
btc() {
  m="$1"; p="${2:-[]}"
  wget -q -O - --header='Content-Type: application/json' \
    --post-data="{\"jsonrpc\":\"1.0\",\"id\":\"init\",\"method\":\"$m\",\"params\":$p}" \
    "http://regtest:regtest@bitcoind:18443/" | jq -r '.result'
}
btcw() { # same, against the named wallet
  m="$1"; p="${2:-[]}"
  wget -q -O - --header='Content-Type: application/json' \
    --post-data="{\"jsonrpc\":\"1.0\",\"id\":\"init\",\"method\":\"$m\",\"params\":$p}" \
    "http://regtest:regtest@bitcoind:18443/wallet/regtest" | jq -r '.result'
}

# Both nodes are remote from this container, so both need an explicit
# --rpcserver: lncli defaults to 127.0.0.1:10009, which here is init itself.
# LND's cert carries --tlsextradomain for each service name, so dialling by
# name verifies.
recv() { lncli --network=regtest --rpcserver=lnd:10009 "$@"; }
payer() { lncli --network=regtest --lnddir=/payer/.lnd --rpcserver=lnd-payer:10009 "$@"; }

retry() { # retry <tries> <sleep> <description> <cmd...>
  n="$1"; s="$2"; what="$3"; shift 3
  i=0
  while [ "$i" -lt "$n" ]; do
    if "$@" >/dev/null 2>&1; then return 0; fi
    i=$((i+1)); sleep "$s"
  done
  say "GAVE UP waiting for: $what"; return 1
}

say "bitcoind wallet"
btc createwallet '["regtest"]' >/dev/null 2>&1 || btc loadwallet '["regtest"]' >/dev/null 2>&1 || true

MINER=$(btcw getnewaddress '[]')
say "miner address $MINER"

BLOCKS=$(btc getblockcount '[]')
if [ "$BLOCKS" -lt 101 ]; then
  say "mining $((101 - BLOCKS)) blocks for coinbase maturity"
  btc generatetoaddress "[$((101 - BLOCKS)), \"$MINER\"]" >/dev/null
fi
say "height $(btc getblockcount '[]')"

say "funding the payer on-chain"
PAYER_ADDR=$(payer newaddress p2wkh | jq -r '.address')
say "payer address $PAYER_ADDR"
btcw sendtoaddress "[\"$PAYER_ADDR\", $FUND_BTC]" >/dev/null
btc generatetoaddress "[6, \"$MINER\"]" >/dev/null

retry 40 2 "payer confirmed balance" sh -c \
  'test "$(lncli --network=regtest --lnddir=/payer/.lnd --rpcserver=lnd-payer:10009 walletbalance | jq -r .confirmed_balance)" -gt 0'
say "payer confirmed balance $(payer walletbalance | jq -r .confirmed_balance) sat"

RECV_PUBKEY=$(recv getinfo | jq -r '.identity_pubkey')
say "receiver pubkey $RECV_PUBKEY"

if payer listpeers | jq -e --arg k "$RECV_PUBKEY" '.peers[]?|select(.pub_key==$k)' >/dev/null 2>&1; then
  say "already peered"
else
  say "connecting payer -> receiver"
  # Retry the CONNECT itself, not just a poll of listpeers. LND answers getinfo
  # (so the healthcheck is green) before its P2P listener is accepting, and a
  # single connect fired into that window fails silently — after which polling
  # listpeers forever cannot recover, because nothing ever dials again.
  connected=no
  i=0
  while [ "$i" -lt 30 ]; do
    payer connect "$RECV_PUBKEY@lnd:9735" >/dev/null 2>&1 || true
    if payer listpeers | jq -e '.peers|length>0' >/dev/null 2>&1; then connected=yes; break; fi
    i=$((i+1)); sleep 2
  done
  [ "$connected" = yes ] || { say "FATAL: payer never peered with the receiver"; exit 1; }
fi

OPEN=$(payer listchannels | jq -r --arg k "$RECV_PUBKEY" '[.channels[]?|select(.remote_pubkey==$k)]|length')
if [ "$OPEN" -gt 0 ]; then
  say "channel already open"
else
  say "opening a ${CHANNEL_SAT} sat channel payer -> receiver"
  payer openchannel --node_key="$RECV_PUBKEY" --local_amt="$CHANNEL_SAT" --push_amt="$PUSH_SAT" >/dev/null
  sleep 2
  btc generatetoaddress "[6, \"$MINER\"]" >/dev/null
fi

retry 60 2 "channel active on the receiving side" sh -c \
  "lncli --network=regtest --rpcserver=lnd:10009 listchannels | jq -e '[.channels[]?|select(.active)]|length>0'"

say "channel up:"
recv listchannels | jq -r '.channels[]|"  capacity=\(.capacity) local=\(.local_balance) remote=\(.remote_balance) active=\(.active)"'

# The guard mounts these two as SINGLE FILES. If either is missing when the
# guard starts, Docker creates a directory at the path and the container dies
# at exit 127 — measured on the box (d46.12). Refusing to exit until they exist
# is what makes that unreachable here.
for f in "$TLSCERT" "$MACAROON"; do
  [ -f "$f" ] || { say "FATAL: $f is missing; the guard would get a directory mount"; exit 1; }
  say "credential present: $f ($(wc -c < "$f") bytes)"
done

say "ready — LND synced, channel open, credentials present"
