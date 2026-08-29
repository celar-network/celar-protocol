#!/usr/bin/env bash
# Celar devnet generator — N validators, 9-dec ncelar. Idempotent.
# Usage: [N=k] [EVM_CHAIN_ID=n] make-devnet.sh [root]
set -euo pipefail
CHAIN_ID="celar-devnet-1"; DENOM="ncelar"; N="${N:-3}"; BIN="celard"; KEYRING="test"
EVM_CHAIN_ID="${EVM_CHAIN_ID:-23529}"
ROOT="${1:-$HOME/celar-devnet}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH="$SCRIPT_DIR/patch-genesis.sh"
BAL="1000000000000000${DENOM}"; DEL="100000000000000${DENOM}"
N0="$ROOT/node0"
rm -rf "$ROOT"; mkdir -p "$ROOT/gentxs"

echo "1) init $N node homes (EVM chain-id $EVM_CHAIN_ID)"
for i in $(seq 0 $((N-1))); do
  $BIN init "celar-node$i" --chain-id "$CHAIN_ID" --home "$ROOT/node$i" >/dev/null
  sed -i 's/type = "flood"/type = "app"/' "$ROOT/node$i/config/config.toml"           # EVM mempool needs type=app
  # CometBFT 0.39 ships an experimental go-libp2p transport (QUIC, WebTransport,
  # WebRTC + STUN NAT traversal), linked into the binary and off by default. Pin it
  # off explicitly: a default that happens to be right is not a setting we chose,
  # and this is the D1.4 shape — there, disabling the ICS20 precompile did not
  # disable the IBC transfer module, and only pinning both at generation time made
  # every devnet inherit the intent.
  sed -i -E '/^\[p2p\.libp2p\]/,/^\[/ s/^([[:space:]]*enabled[[:space:]]*=).*/\1 false/' \
    "$ROOT/node$i/config/config.toml"
  APP="$ROOT/node$i/config/app.toml"
  sed -i -E "s/^([[:space:]]*evm-chain-id[[:space:]]*=).*/\\1 $EVM_CHAIN_ID/" "$APP"    # EVM chain-id (MetaMask)
  sed -i -E 's/^(minimum-gas-prices[[:space:]]*=).*/\1 "0ncelar"/' "$APP"               # zero-fee devnet
done

echo "2) create ALL validator keys in node0's keyring"
for i in $(seq 0 $((N-1))); do $BIN keys add "val$i" --keyring-backend "$KEYRING" --home "$N0" --output json > "$ROOT/val$i.info.json"; done

echo "3) patch node0 genesis to 9-dec ncelar/acelar/CELAR"
"$PATCH" "$N0/config/genesis.json"

echo "4) fund all validator accounts in node0 genesis"
for i in $(seq 0 $((N-1))); do
  ADDR=$($BIN keys show "val$i" -a --keyring-backend "$KEYRING" --home "$N0")
  $BIN genesis add-genesis-account "$ADDR" "$BAL" --home "$N0"
done
echo "   funded accounts = $(jq '.app_state.auth.accounts | length' "$N0/config/genesis.json") (expect $N)"

echo "5) gentx each validator"
for i in $(seq 0 $((N-1))); do
  PK=$($BIN comet show-validator --home "$ROOT/node$i" 2>/dev/null || $BIN tendermint show-validator --home "$ROOT/node$i")
  $BIN genesis gentx "val$i" "$DEL" --pubkey "$PK" --moniker "celar-node$i" \
      --chain-id "$CHAIN_ID" --keyring-backend "$KEYRING" --home "$N0" \
      --output-document "$ROOT/gentxs/gentx-val$i.json" >/dev/null
done

echo "6) collect gentxs"; $BIN genesis collect-gentxs --home "$N0" --gentx-dir "$ROOT/gentxs" >/dev/null
echo "7) validate";       $BIN genesis validate --home "$N0"
echo "8) distribute";     for i in $(seq 1 $((N-1))); do cp "$N0/config/genesis.json" "$ROOT/node$i/config/genesis.json"; done
echo "DONE — gentxs in genesis: $(jq '.app_state.genutil.gen_txs | length' "$N0/config/genesis.json")"
