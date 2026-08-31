// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./TFHE.sol";

/// Exists only to test one property of the op-stream: that a reverted call
/// frame leaves no stream events behind.
///
/// The token contract cannot exercise this. Every revert in it is a guard —
/// provenance, operator, zero-check — and all of them fire BEFORE any FHE
/// operation runs, so a reverted token call never had stream events to lose.
/// The interesting case is the opposite order: real encrypted work, emitted,
/// and then a revert that must take those events with it.
///
/// The stream carrying work from a reverted frame would be worse than a
/// missing event: coprocessors would execute and attest to operations the
/// chain disowned, and the fraud game has no way to tell that apart from a
/// coprocessor inventing work.
contract StreamRevertProbe {
    error Deliberate();

    /// Does genuine FHE work — enough to emit several stream events — and
    /// then reverts unconditionally.
    function workThenRevert() external {
        euint64 a = TFHE.asEuint64(7);
        euint64 b = TFHE.asEuint64(5);
        euint64 sum = TFHE.add(a, b);
        ebool fits = TFHE.le(b, sum);
        euint64 picked = TFHE.select(fits, b, a);
        TFHE.sub(sum, picked);
        revert Deliberate();
    }

    /// The control: the same work, committed. Without it, a test asserting
    /// "no events after revert" cannot distinguish the revert working from
    /// the contract never having emitted anything.
    function workAndKeep() external returns (bytes32) {
        euint64 a = TFHE.asEuint64(7);
        euint64 b = TFHE.asEuint64(5);
        euint64 sum = TFHE.add(a, b);
        ebool fits = TFHE.le(b, sum);
        euint64 picked = TFHE.select(fits, b, a);
        return euint64.unwrap(TFHE.sub(sum, picked));
    }
}
