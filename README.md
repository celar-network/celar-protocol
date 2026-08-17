# Celar Protocol — monorepo

Standalone confidential smart-contract L1: threshold FHE (Zama TFHE-rs), a
79-of-100 KMS committee, stealth addresses, and a ZK shielded pool, built on
Cosmos SDK + Cosmos EVM. The layout maps to the whitepaper (v0.9.11) and the
implementation plan. The backend (FHE) was decided via bake-off; the
precompile ABI in `fhe/backend-adapter` is held fixed and backend-agnostic.

## Layout

| Dir | Workstream |
|-----|-----------|
| `chain/`     | core — consensus, EVM, fees, ordering |
| `fhe/`       | precompiles + coprocessor             |
| `kms/`       | threshold KMS + committee             |
| `pool/`      | shielded pool + circuit               |
| `bridge/`    | bridge                                |
| `wallet/`    | wallet / SDK / client                 |
| `economics/` | economics, staking, governance        |
| `security/`  | security, ceremonies, ops             |

Validation models (committee capture, economics) live in `../sim/`. Live
programme state and the build log are in `../doc/`.

## Chain — `celard`

`chain/celard` is Celar's node — a fork of the Cosmos EVM reference app (`evmd`)
that wires the `precisebank` module so the native token **CELAR** runs at
**9 decimals** on-chain while presenting the EVM/MetaMask-standard 18 decimals.
It builds **portably** against `cosmos/evm` **v0.7.0** (pinned in `go.mod`,
fetched from GitHub — no local checkout required).

### Denominations

| Role | Denom | Decimals | Where |
|------|-------|----------|-------|
| Integer bank denom (gas, staking) | `ncelar` | 9 | `x/bank` |
| Extended denom (EVM / MetaMask)   | `acelar` | 18 | via `precisebank` |
| Display                            | `CELAR` | — | metadata |

1 CELAR = 10⁹ ncelar = 10¹⁸ acelar. The 9↔18 reconciliation is handled by
`precisebank` (conversion factor `10^9`), whose keeper is handed to the EVM-side
consumers in place of the base bank keeper; Cosmos-native modules (staking,
distribution, gov, mint) keep base bank.

### Quick start

Prerequisites: **Go ≥ 1.25.9** and **jq**.

```bash
cd chain
./bootstrap.sh          # builds celard, generates a solo devnet, and starts it
```

Or step by step:

```bash
# build
cd chain/celard && go build -o "$(go env GOPATH)/bin/celard" ./cmd/evmd

# generate a devnet (default 3 validators; N=1 for a single-validator solo net)
N=1 chain/devnet/make-devnet.sh ~/celar-solo

# start node0 (prints height + eth_chainId; logs to <home>/node.log)
chain/devnet/run-node.sh ~/celar-solo/node0
```

`make-devnet.sh` also accepts `EVM_CHAIN_ID=<n>` (default `23529`). Stop the node
with `pkill -f "celard start"`.

### Verify it's alive

```bash
curl -s http://127.0.0.1:26657/status | jq '.result.sync_info.latest_block_height'   # climbing
V=$(celard keys show val0 -a --keyring-backend test --home ~/celar-solo/node0)
celard query bank balances "$V" --home ~/celar-solo/node0                             # 9-dec ncelar
curl -s -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'               # 0x5be9 = 23529
```

### Add to MetaMask

- Network name: Celar Devnet
- RPC URL: `http://127.0.0.1:8545`
- Chain ID: `23529`
- Currency symbol: `CELAR`

The same seed works in both MetaMask (`0x…`) and the `celard` keyring (`celar1…`)
— `celard` uses eth_secp256k1 keys / BIP-44 coin type 60, so it's one account,
two address encodings, one balance.
