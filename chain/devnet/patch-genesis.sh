#!/usr/bin/env bash
# Celar devnet genesis patch — 9-dec ncelar (bank) / 18-dec acelar (EVM) / CELAR (display).
# Idempotent. Usage: patch-genesis.sh <genesis.json>
set -euo pipefail
GENESIS="${1:?usage: patch-genesis.sh <genesis.json>}"
BASE="ncelar"; EXT="acelar"; DISP="CELAR"
tmp="$(mktemp)"
jq --arg base "$BASE" --arg ext "$EXT" --arg disp "$DISP" '
  # 1) every denom currently "stake" -> ncelar (bond, mint, evm_denom, gov deposit, ...)
  walk(if type=="string" and .=="stake" then $base else . end)
  # 2) EVM extended denom = distinct 18-dec acelar (precisebank presents this to MetaMask)
  | .app_state.evm.params.extended_denom_options.extended_denom = $ext
  # 3) bank denom metadata so the EVM derives decimals=9 and display=CELAR
  | .app_state.bank.denom_metadata = [{
      description: "Celar native staking and gas token",
      denom_units: [
        {denom:$base, exponent:0, aliases:["nanocelar"]},
        {denom:$disp, exponent:9}
      ],
      base:$base, display:$disp, name:"Celar", symbol:$disp
    }]
  # 4) keep ICS20 precompile disabled (G7): active_static_precompiles stays empty
  | .app_state.evm.params.active_static_precompiles = []
' "$GENESIS" > "$tmp" && mv "$tmp" "$GENESIS"
echo "patched $GENESIS -> base=$BASE ext=$EXT display=$DISP"
