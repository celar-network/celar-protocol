# Celar Protocol — monorepo

Standalone confidential smart-contract L1: threshold FHE (Zama TFHE-rs), a
79-of-100 KMS committee, stealth addresses, and a ZK shielded pool, built on
Cosmos SDK + Cosmos EVM. The layout maps to the whitepaper (v0.9.8) and the
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

## Chain build — `celard`

`chain/celard` is a fork of the upstream `evmd` example app. It depends on a
pinned checkout of `cosmos/evm` **v0.7.0** (`f4ab9a3…`) via a `go.mod` replace
pointing at `~/Documents/Project/celar-build/cosmos-evm` — update that path if
the clone moves, or switch to the `v0.7.0` tag for a portable build.

Native-token denominations:

| Role | Denom | Decimals | Where |
|------|-------|----------|-------|
| Integer bank denom (gas, staking) | `ncelar` | 9 | `x/bank` |
| Extended denom (EVM / MetaMask)   | `acelar` | 18 | via `precisebank` |
| Display                            | `CELAR` | — | metadata |

The 9↔18 reconciliation is handled by `precisebank` (conversion factor `10^9`),
whose keeper is handed to the EVM-side consumers in place of the base bank
keeper; Cosmos-native modules (staking, distribution, gov, mint) keep base bank.

### Prerequisites
- Go ≥ 1.25.9
- the pinned `cosmos/evm` clone at the path in `chain/celard/go.mod`
- `jq`

### Build
```bash
cd chain/celard
go build -o "$(go env GOPATH)/bin/celard" ./cmd/evmd
```

### Devnet genesis
`chain/devnet/patch-genesis.sh` rewrites a stock `celard` genesis into the 9-dec
`ncelar`/`acelar`/`CELAR` config (unifies all denoms to `ncelar`, sets the
extended denom to `acelar`, writes the bank `denom_metadata`, and keeps the
ICS20 precompile disabled). Apply it to a generated genesis:
```bash
celard init <moniker> --chain-id celar-devnet-1 --home <home>
chain/devnet/patch-genesis.sh <home>/config/genesis.json
celard genesis validate --home <home>
```
The full 3-node flow (init ×3 → patch → genesis accounts → `gentx` →
`collect-gentxs` → peers → `start`) is documented in the build notes under
`../doc/`.

> Note: `celard` still carries the upstream internal name `evmd` and default home
> `~/.evmd` — cosmetic leftovers from the fork, to be rebranded later. Always
> pass an explicit `--home`.
