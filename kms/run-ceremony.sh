#!/usr/bin/env bash
# Launch a full local DKG ceremony: all n nodes + collect, one command.
# Usage: ./run-ceremony.sh [dir] [parties]     (defaults: ceremony-b6, 4)
#
# Exists because two ceremony attempts failed to operator error (stale
# fragments from a prior run; a node never launched). This script clears old
# outputs, starts EVERY node near-simultaneously, waits for all of them, then
# collects — or reports which node died.
set -euo pipefail
DIR="${1:-ceremony-b6}"
N="${2:-4}"
BIN=./target/release/celar_kms_node
export RUST_LOG="${RUST_LOG:-info}"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"

[ -x "$BIN" ] || { echo "ERROR: $BIN not built (cargo build --release)"; exit 1; }
for i in $(seq 1 "$N"); do
  cfg=$(printf '%s/node_%03d.json' "$DIR" "$i")
  [ -f "$cfg" ] || { echo "ERROR: missing $cfg"; exit 1; }
done

echo "==> clearing previous ceremony outputs in $DIR"
rm -f "$DIR"/fragment_*.json "$DIR"/party_*.share.bin "$DIR"/pk_g*.bin

echo "==> launching $N nodes (RUST_LOG=$RUST_LOG RAYON_NUM_THREADS=$RAYON_NUM_THREADS)"
mkdir -p "$DIR/logs"
PIDS=()
for i in $(seq 1 "$N"); do
  cfg=$(printf '%s/node_%03d.json' "$DIR" "$i")
  log=$(printf '%s/logs/node_%03d.log' "$DIR" "$i")
  "$BIN" run --config "$cfg" >"$log" 2>&1 &
  PIDS+=($!)
  echo "    node $i pid ${PIDS[-1]} log $log"
done

FAIL=0
for i in $(seq 1 "$N"); do
  if ! wait "${PIDS[$((i-1))]}"; then
    echo "ERROR: node $i FAILED — tail of its log:"
    tail -20 "$(printf '%s/logs/node_%03d.log' "$DIR" "$i")"
    FAIL=1
  fi
done
[ "$FAIL" -eq 0 ] || { echo "ceremony FAILED — full logs in $DIR/logs/"; exit 1; }

grep -h "corrupt set\|CANARY\|PK-COMPONENTS" "$DIR"/logs/node_*.log | sort || true
echo "==> all $N nodes done; collecting"
"$BIN" collect --dir "$DIR"
