#!/usr/bin/env bash
# Start all N validators of a Celar devnet on one host
# (port offsets + persistent peers). Usage: run-3node.sh [root]
set -euo pipefail
ROOT="${1:-$HOME/celar-devnet}"
BIN="celard"
CHAIN_ID="celar-devnet-1"

N=$(ls -d "$ROOT"/node[0-9]* 2>/dev/null | wc -l)
if [ "$N" -lt 2 ]; then
  echo "need >=2 node homes in $ROOT — run: N=3 make-devnet.sh $ROOT"
  exit 1
fi
echo "starting $N nodes from $ROOT"
pkill -f "celard start" 2>/dev/null || true
sleep 1

declare -a IDS
for i in $(seq 0 $((N - 1))); do
  IDS[$i]=$($BIN comet show-node-id --home "$ROOT/node$i")
done

for i in $(seq 0 $((N - 1))); do
  O=$((i * 100))
  CFG="$ROOT/node$i/config/config.toml"
  APP="$ROOT/node$i/config/app.toml"

  sed -i "s#:26656\"#:$((26656 + O))\"#" "$CFG"
  sed -i "s#:26657\"#:$((26657 + O))\"#" "$CFG"
  sed -i "s#:26658\"#:$((26658 + O))\"#" "$CFG"
  sed -i "s#localhost:6060#localhost:$((6060 + i))#" "$CFG"

  sed -i 's/^allow_duplicate_ip = false/allow_duplicate_ip = true/' "$CFG"
  sed -i 's/^addr_book_strict = true/addr_book_strict = false/' "$CFG"

  peers=""
  for j in $(seq 0 $((N - 1))); do
    [ "$j" = "$i" ] && continue
    peers="$peers,${IDS[$j]}@127.0.0.1:$((26656 + j * 100))"
  done
  sed -i "s#^persistent_peers = .*#persistent_peers = \"${peers#,}\"#" "$CFG"

  sed -i "s#:9090\"#:$((9090 + O))\"#" "$APP"
  sed -i "s#:1317\"#:$((1317 + O))\"#" "$APP"
  sed -i "s#:8545\"#:$((8545 + O))\"#" "$APP"
  sed -i "s#:8546\"#:$((8546 + O))\"#" "$APP"
done

for i in $(seq 0 $((N - 1))); do
  H="$ROOT/node$i"
  O=$((i * 100))
  # The addresses are offset above, but app.toml ships with the
  # JSON-RPC server disabled, so without this flag nothing binds and
  # every eth_* call silently fails to connect.
  nohup $BIN start --home "$H" \
    --chain-id "$CHAIN_ID" \
    --minimum-gas-prices 0ncelar \
    --json-rpc.enable \
    > "$H/node.log" 2>&1 &
  echo "node$i pid $! : rpc $((26657 + O)) p2p $((26656 + O)) json-rpc $((8545 + O))"
done

echo "waiting 15s for peering + consensus..."
sleep 15

echo "=== node0 status ==="
curl -s http://127.0.0.1:26657/status \
  | jq '{height: .result.sync_info.latest_block_height,
         catching_up: .result.sync_info.catching_up}'

echo "node0 peers:       $(curl -s http://127.0.0.1:26657/net_info | jq -r '.result.n_peers')"
echo "active validators: $(curl -s http://127.0.0.1:26657/validators | jq -r '.result.total')"
