// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @dev Encrypted 64-bit unsigned integer. The value is a 32-byte
/// handle: an opaque reference to ciphertext held off-chain.
/// The distinct type is deliberate — it stops an encrypted
/// boolean being used where a number is meant, which the backend
/// also enforces and which has caught real bugs there.
type euint64 is bytes32;

/// @dev Encrypted boolean, produced by comparisons and boolean
/// combinators. Never branch on one — see `select` below.
type ebool is bytes32;

/// @title TFHE — Solidity surface for confidential operations
///
/// Calls compile to invocations of the FHE precompile. Contracts
/// manipulate handles; ciphertext material lives in the FHE data
/// plane and is never touched here.
///
/// ## Why nothing here is `view`
///
/// Every operation that produces a handle also records who owns
/// it, which is a state write. A `view` function would be reached
/// by `staticcall`, the precompile would take its read-only path,
/// and the handle would return unregistered — so a later `allow`
/// would reject it as unknown. Creating an encrypted value is a
/// state change, and the types say so.
///
/// ## The branchless rule
///
/// No `require`, `revert` or `if` may depend on an encrypted
/// predicate. Comparison results flow only into `select`.
/// Breaking this turns confidential state into a public oracle:
/// an observer learns the predicate from whether the transaction
/// reverted. The reverts below are on *plaintext* conditions —
/// malformed input, unknown handle, missing permission — and leak
/// nothing about encrypted values.
library TFHE {
    address internal constant PRECOMPILE = 0x0000000000000000000000000000000000000900;

    /// `compute` lets a grantee operate on a handle without
    /// reading it; `reencryptToSelf` lets exactly one address read
    /// it privately; `reveal` makes it public permanently.
    uint8 internal constant PERM_COMPUTE = 0;
    uint8 internal constant PERM_REENCRYPT_TO_SELF = 1;
    uint8 internal constant PERM_REVEAL = 2;

    error PrecompileFailed(bytes reason);

    // ---- input admission --------------------------------------

    /// Public constant to encrypted value. Carries no secrecy —
    /// the value is public by definition — and is the right tool
    /// for literals such as zero.
    function asEuint64(uint64 value) internal returns (euint64) {
        bytes32 r = _call(abi.encodeWithSignature("trivialEncrypt(uint64,uint8)", value, uint8(64)));
        return euint64.wrap(r);
    }

    /// Admit a client ciphertext with its input proof.
    function fromExternal(bytes memory ct, bytes memory proof) internal returns (euint64) {
        bytes32 r = _call(abi.encodeWithSignature("verifyInput(bytes,bytes)", ct, proof));
        return euint64.wrap(r);
    }

    // ---- arithmetic -------------------------------------------

    function add(euint64 a, euint64 b) internal returns (euint64) {
        return euint64.wrap(_bin2("add(bytes32,bytes32)", a, b));
    }

    function sub(euint64 a, euint64 b) internal returns (euint64) {
        return euint64.wrap(_bin2("sub(bytes32,bytes32)", a, b));
    }

    // ---- comparison (yields ebool) ----------------------------

    function le(euint64 a, euint64 b) internal returns (ebool) {
        return ebool.wrap(_bin2("le(bytes32,bytes32)", a, b));
    }

    function lt(euint64 a, euint64 b) internal returns (ebool) {
        return ebool.wrap(_bin2("lt(bytes32,bytes32)", a, b));
    }

    function eq(euint64 a, euint64 b) internal returns (ebool) {
        return ebool.wrap(_bin2("eq(bytes32,bytes32)", a, b));
    }

    // ---- boolean combinators ----------------------------------

    function and(ebool a, ebool b) internal returns (ebool) {
        bytes32 r = _bin("and(bytes32,bytes32)", ebool.unwrap(a), ebool.unwrap(b));
        return ebool.wrap(r);
    }

    function or(ebool a, ebool b) internal returns (ebool) {
        bytes32 r = _bin("or(bytes32,bytes32)", ebool.unwrap(a), ebool.unwrap(b));
        return ebool.wrap(r);
    }

    function not(ebool a) internal returns (ebool) {
        bytes32 r = _call(abi.encodeWithSignature("not(bytes32)", ebool.unwrap(a)));
        return ebool.wrap(r);
    }

    // ---- the branchless primitive -----------------------------

    /// The only path an encrypted predicate may take. Both
    /// branches are evaluated and the result chosen
    /// arithmetically, so nothing about the condition is
    /// observable — not in control flow, not in gas, not in
    /// emitted events.
    function select(ebool cond, euint64 a, euint64 b) internal returns (euint64) {
        bytes32 r = _call(
            abi.encodeWithSignature(
                "select(bytes32,bytes32,bytes32)", ebool.unwrap(cond), euint64.unwrap(a), euint64.unwrap(b)
            )
        );
        return euint64.wrap(r);
    }

    /// Narrow to `k` bits, wrapping silently.
    function narrow(euint64 a, uint8 k) internal returns (euint64) {
        bytes32 r = _call(abi.encodeWithSignature("cast(bytes32,uint8)", euint64.unwrap(a), k));
        return euint64.wrap(r);
    }

    // ---- access control ---------------------------------------

    /// Grant `account` a permission on `handle`. Only the handle's
    /// owner may do this; the precompile enforces it, and the
    /// resulting entry is the sole authorization the key
    /// committee honours.
    function allow(euint64 handle, address account, uint8 perm) internal {
        _grant(euint64.unwrap(handle), account, perm);
    }

    function allowBool(ebool handle, address account, uint8 perm) internal {
        _grant(ebool.unwrap(handle), account, perm);
    }

    // ---- committee gateway ------------------------------------

    /// Ask the committee to re-encrypt toward `pubKey`. Servable
    /// for the owner or a reencrypt-to-self grantee.
    function requestReencrypt(euint64 handle, bytes memory pubKey) internal returns (bytes32) {
        return _call(abi.encodeWithSignature("requestReencrypt(bytes32,bytes)", euint64.unwrap(handle), pubKey));
    }

    /// Ask the committee to make a value public. Requires an
    /// explicit per-handle reveal grant — no wildcards.
    function requestReveal(euint64 handle) internal returns (bytes32) {
        return _call(abi.encodeWithSignature("requestReveal(bytes32)", euint64.unwrap(handle)));
    }

    // ---- plumbing ---------------------------------------------

    function _bin2(string memory sig, euint64 a, euint64 b) private returns (bytes32) {
        return _bin(sig, euint64.unwrap(a), euint64.unwrap(b));
    }

    function _bin(string memory sig, bytes32 a, bytes32 b) private returns (bytes32) {
        return _call(abi.encodeWithSignature(sig, a, b));
    }

    function _grant(bytes32 h, address account, uint8 perm) private {
        _raw(abi.encodeWithSignature("allow(bytes32,address,uint8)", h, account, perm));
    }

    function _call(bytes memory data) private returns (bytes32) {
        return abi.decode(_raw(data), (bytes32));
    }

    function _raw(bytes memory data) private returns (bytes memory) {
        (bool ok, bytes memory ret) = PRECOMPILE.call(data);
        if (!ok) revert PrecompileFailed(ret);
        return ret;
    }
}
