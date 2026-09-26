#!/usr/bin/env bash
# Create and start a single-validator devnet.
#
# This exists because the previous devnet was built by hand and the procedure
# lived in one person's shell history. It then ran a binary that predated five
# weeks of work, and the mismatch was diagnosed as a protocol defect for a day.
# A devnet nobody can rebuild is a devnet nobody can check.
#
# Nothing in the app defaults to this chain's denom: `celard init` gives `stake`
# with no bank metadata, while app.go wires precisebank to give the EVM 18-dec
# acelar over a 9-dec ncelar bank denom. So the denom is set at init time.
#
# It is set at init time, not patched afterwards, because a gentx is a SIGNED
# transaction embedded in genesis: renaming a denom inside it invalidates it,
# and the node then panics in DeliverTx during InitChain.
#
# Usage:  scripts/devnet.sh [home-dir] [chain-id]
set -euo pipefail

HOME_DIR=${1:-$HOME/celar-devnet-solo}
CHAIN_ID=${2:-celar-devnet-2}
DENOM=ncelar
FHE_PRECOMPILE=0x0000000000000000000000000000000000000900
KB="--keyring-backend test"

command -v celard >/dev/null || { echo "celard not on PATH"; exit 1; }

# Refuse an unstamped binary: an empty commit is what let a stale node pass for
# the working tree for five weeks.
COMMIT=$(celard version --long 2>/dev/null | awk '/^commit:/{print $2}')
[ -n "$COMMIT" ] || { echo "celard has no commit stamp; build with -ldflags -X .../version.Commit=..."; exit 1; }
echo "binary commit: $COMMIT"

[ -e "$HOME_DIR" ] && { echo "$HOME_DIR exists; move or remove it first"; exit 1; }

celard init node0 --home "$HOME_DIR" --chain-id "$CHAIN_ID" \
  --default-denom "$DENOM" >/dev/null 2>&1

for name in validator account0 account1; do
  celard keys add "$name" $KB --home "$HOME_DIR" --algo eth_secp256k1 >/dev/null 2>&1
  celard genesis add-genesis-account "$name" "100000000000000000$DENOM" \
    $KB --home "$HOME_DIR"
done

celard genesis gentx validator "1000000000000000$DENOM" \
  --chain-id "$CHAIN_ID" $KB --home "$HOME_DIR" >/dev/null 2>&1
celard genesis collect-gentxs --home "$HOME_DIR" >/dev/null 2>&1

# Params only, after the gentx is collected. Nothing below touches a signed
# payload, which is why this order matters.
python3 - "$HOME_DIR/config/genesis.json" "$FHE_PRECOMPILE" "$DENOM" <<'PY'
import json, sys

path, precompile, denom = sys.argv[1], sys.argv[2], sys.argv[3]
g = json.load(open(path))
app = g["app_state"]

# The module key was renamed upstream: older chains have `evm`, current builds
# have `vm`. Accept either rather than assume.
key = "vm" if "vm" in app else "evm"
params = app[key]["params"]

# `--default-denom` covers staking, gov, mint and crisis. It does not reach the
# EVM's own denom, which stays `stake` and makes the node panic at InitChain
# about missing metadata.
params["evm_denom"] = denom

# THE setting. app.go registers the precompile, making it available; this makes
# it active. Inactive, every call to the address returns empty AND reports
# success, and any contract decoding that result reverts. The op stream does not
# exist without this line.
active = params.get("active_static_precompiles") or []
if precompile not in active:
    params["active_static_precompiles"] = sorted(active + [precompile])

# `celard init` writes no bank metadata at all, and the EVM refuses to start
# without metadata for its own denom.
app["bank"]["denom_metadata"] = [{
    "description": "Celar native staking and gas token",
    "denom_units": [
        {"denom": denom, "exponent": 0, "aliases": ["nanocelar"]},
        {"denom": "CELAR", "exponent": 9, "aliases": []},
    ],
    "base": denom, "display": "CELAR",
    "name": "Celar", "symbol": "CELAR", "uri": "", "uri_hash": "",
}]

# No base fee on a devnet: otherwise a contract creation costs more than a
# funded account holds, and the failure reads as a funding problem.
fm = app["feemarket"]["params"]
fm["no_base_fee"] = True
fm["base_fee"] = "0.000000000000000000"
fm["min_gas_price"] = "0.000000000000000000"

assert params["evm_denom"] == denom
assert denom in [m["base"] for m in app["bank"]["denom_metadata"]]
assert app["staking"]["params"]["bond_denom"] == denom
assert precompile in params["active_static_precompiles"]
for mod in ("fraudevidence", "epochcommit"):
    assert mod in app, f"{mod} missing from genesis; binary predates the module"

json.dump(g, open(path, "w"), indent=2)
print(f"genesis: {key}.evm_denom = {denom}, metadata present")
print(f"genesis: {key}.active_static_precompiles = {params['active_static_precompiles']}")
print("genesis: feemarket no_base_fee = true")
print("genesis: fraudevidence and epochcommit present")
PY

celard genesis validate --home "$HOME_DIR" >/dev/null && echo "genesis: valid"

python3 - "$HOME_DIR/config/config.toml" <<'PY'
import re, sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
head, sep, tail = s.partition("[mempool]")
assert sep, "no [mempool] section"
# v0.7.3 refuses to start with the EVM mempool enabled and CometBFT set to
# flood. The error names app.toml; the setting is here.
tail, n = re.subn(r'(?m)^type\s*=\s*".*"', 'type = "app"', tail, count=1)
assert n == 1
p.write_text(head + sep + tail)
print("config.toml: mempool.type = app")
PY

python3 - "$HOME_DIR/config/app.toml" <<'PY'
import re, sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
head, sep, tail = s.partition("[json-rpc]")
assert sep, "no [json-rpc] section"
tail, n = re.subn(r'(?m)^enable\s*=\s*.*', 'enable = true', tail, count=1)
assert n == 1
p.write_text(head + sep + tail)
print("app.toml: json-rpc enabled")
PY

cat <<EOM

devnet ready at $HOME_DIR

  start:   celard start --home $HOME_DIR --chain-id $CHAIN_ID \\
             --minimum-gas-prices 0$DENOM --json-rpc.enable
  keys:    celard keys list --keyring-backend test --home $HOME_DIR
  key:     celard keys unsafe-export-eth-key account0 --keyring-backend test --home $HOME_DIR
  stream:  curl -s -X POST -H 'Content-Type: application/json' \\
             --data '{"jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[{"fromBlock":"0x1","toBlock":"latest","address":"$FHE_PRECOMPILE"}]}' \\
             http://localhost:8545

EOM
