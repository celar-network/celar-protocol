#!/usr/bin/env bash
# One-command Celar devnet bootstrap for contributors.
# Checks prerequisites, builds celard, generates a solo devnet, and starts it.
# Usage: ./bootstrap.sh [validators]   (default 1)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
N_VAL="${1:-1}"
NET="$HOME/celar-solo"

echo "==> checking prerequisites"
command -v go >/dev/null || { echo "ERROR: Go not found (need >= 1.25.9)"; exit 1; }
command -v jq >/dev/null || { echo "ERROR: jq not found (install jq)"; exit 1; }
GOVER=$(go version | grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | sed 's/go//')
echo "    Go $GOVER, jq $(jq --version)"

echo "==> building celard (fetches cosmos/evm v0.7.0 on first build; may take a few minutes)"
( cd "$HERE/celard" && go build -o "$(go env GOPATH)/bin/celard" ./cmd/evmd )
command -v celard >/dev/null || { echo "ERROR: celard not on PATH — add \$(go env GOPATH)/bin to PATH"; exit 1; }
echo "    built: $(command -v celard)"

echo "==> generating a ${N_VAL}-validator devnet at $NET"
N="$N_VAL" "$HERE/devnet/make-devnet.sh" "$NET"

echo "==> starting node0"
"$HERE/devnet/run-node.sh" "$NET/node0"

echo
echo "Celar devnet is up. RPC: http://127.0.0.1:26657 · EVM JSON-RPC: http://127.0.0.1:8545 (chain-id 23529)"
echo "Stop with: pkill -f 'celard start'"
