#!/usr/bin/env bash
# Start a Celar devnet node in the background with the flags celard needs.
# Usage: run-node.sh [home]   (default: ~/celar-solo/node0)
set -euo pipefail
HOME_DIR="${1:-$HOME/celar-solo/node0}"
CHAIN_ID="celar-devnet-1"
LOG="$HOME_DIR/node.log"

pkill -f "celard start" 2>/dev/null || true; sleep 1
nohup celard start --home "$HOME_DIR" --chain-id "$CHAIN_ID" \
  --minimum-gas-prices 0ncelar --json-rpc.enable \
  > "$LOG" 2>&1 &
echo "started celard (pid $!)  home=$HOME_DIR  log=$LOG"
sleep 10
echo "height: $(curl -s http://127.0.0.1:26657/status | jq -r '.result.sync_info.latest_block_height')"
echo "eth_chainId: $(curl -s -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' | jq -r '.result')"
echo "stop with: pkill -f 'celard start'"
