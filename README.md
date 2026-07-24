# Celar Protocol — monorepo

Standalone confidential smart-contract L1. Layout maps to the whitepaper
(v0.9.5) and implementation plan. Backend (FHE) decided at M1 via bake-off;
the precompile ABI in fhe/backend-adapter is held fixed and backend-agnostic.

| Dir | Workstream | Whitepaper |
|-----|-----------|-----------|
| chain/    | W1 core (consensus, EVM, fees, ordering) | §1-2, §9, §13 |
| fhe/      | W2 precompiles + coprocessor            | §3, §5, §6, §8, §16 |
| kms/      | W3 threshold KMS + committee            | §7 |
| pool/     | W4 shielded pool + circuit              | §11 |
| bridge/   | W5 bridge                               | §12 |
| wallet/   | W6 wallet / SDK / client                | §3.2, §4, §11.4 |
| economics/| W7 economics, staking, governance       | §13, §14 |
| security/ | W8 security, ceremonies, ops            | Security Roadmap |
| sim/      | validation models (committee, economics) | — |

Status: Phase 0. See docs/celar-implementation-plan.md for gates.
