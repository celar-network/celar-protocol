# Accepted / deferred advisories (`cargo audit`)

`cargo audit` warnings that are knowingly deferred, with the reason and the
trigger to revisit. Fixed advisories are not listed here — they are simply
patched in `Cargo.lock`. Review this list whenever `cargo audit` output changes.

Last reviewed: 2026-09-13.

## Deferred — no fix available yet

- **`anyhow` — RUSTSEC-2026-0190** (unsound: `Error::downcast_mut()`). A direct
  dependency, but the advisory has no patched release: the latest published 1.x
  is the flagged version (`cargo update -p anyhow` moves nothing). It is an
  unsoundness warning, not a remotely exploitable bug, and the crate is used
  only for local error handling. **Trigger:** bump as soon as a fixed `anyhow`
  is published.

## Deferred — unmaintained, transitive or fork-owned

These are "no longer maintained" advisories (informational), not exploitable
defects. Each is pulled in transitively; removing it means changing a
dependency we do not own here.

- **`backoff` — RUSTSEC-2025-0012** and its **`instant` — RUSTSEC-2024-0384**:
  come from the upstream `threshold-*` networking fork's retry/backoff path.
  **Trigger:** the fork migrating off `backoff` (tracked with the fork), or a
  re-pin that drops it.
- **`bincode` — RUSTSEC-2025-0141**: used directly (1.3) for transcript/share
  serialization, and also pulled transitively (2.0). No drop-in maintained
  replacement with a compatible wire format; a swap is a deliberate migration,
  not a hygiene bump. **Trigger:** a planned serialization-format review.
- **`paste` — RUSTSEC-2024-0436**, **`serde_cbor` — RUSTSEC-2021-0127**:
  transitive (proc-macro / serialization behind other crates). Removed only
  when their parents drop them. **Trigger:** they disappear from
  `cargo tree --invert <crate>` after a routine dependency update.

## Patched in this pass (for the record)

- `h2` 0.4.15 → 0.4.19 — RUSTSEC-2026-0258 (DoS via unbounded empty DATA frames).
- `chacha20` 0.10.1 → 0.10.2 — 0.10.1 was yanked.
