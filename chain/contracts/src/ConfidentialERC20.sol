// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {TFHE, euint64, ebool} from "./TFHE.sol";

/// @title ConfidentialERC20 — interface-aligned w/ ERC-7984
///
/// Balances are handles; amounts are never observable
/// on-chain. The standard is still Draft, and several
/// MUST items are deliberately absent, so this is
/// **interface-aligned, not conformant** — a project
/// rule, not a hedge, until those items land.
///
/// ## The branchless rule
///
/// A transfer of more than the sender holds does not
/// revert. It moves zero. Reverting would publish the
/// comparison: an observer learns whether balance >=
/// amount from whether the tx succeeded, turning
/// confidential state into an oracle. The standard's
/// "return the actual amount" convention is the same
/// idea arrived at independently.
///
/// ## Deferred by design (tracked as E8)
///
/// Time-boxed operators, confidentialTransferFrom, and
/// the AndCall family are not implemented. AndCall is a
/// reentrancy surface that interacts with first-writer-
/// wins registration and wants review, not addition.
///
/// ## Known-unsound dependency
///
/// transferFromExternal admits a ciphertext through the
/// input-proof path, which verifies nothing beyond non-
/// emptiness (Track C / C1). Until C1 lands, an observer
/// can replay an admitted ciphertext. Do not present
/// this path as confidential in a demo.
///
/// ## Shared-zero exposure — no contract-side defence
///
/// TFHE.asEuint64(0) derives the same handle for every
/// caller on the chain, trivialEncrypt skips the
/// compute-access check because it takes no handle
/// operands, and registration is first-writer-wins with no
/// revocation. So any account can register the shared
/// encrypted zero to itself for one call, after which this
/// contract cannot grant on it and _ensure re-derives the
/// same foreign-owned handle forever: deployment or every
/// mint and transfer fails permanently.
///
/// This contract cannot defend itself. A per-contract salt
/// only moves the target, since CREATE addresses are
/// predictable. The fix is the submitter entering the
/// handle preimage — the change scoped for C1, which
/// closes this and input-admission front-running together.
/// Documented rather than mitigated, because a mitigation
/// that reads like protection and isn't is worse than a
/// stated exposure.
contract ConfidentialERC20 {
    // ---- metadata ----------------------------------

    string public name;
    string public symbol;

    /// Token *display* scale. Unrelated to the chain's
    /// 9-decimal coin — euint64 caps near 18.45e18.
    uint8 public constant decimals = 6;

    string private _contractURI;

    // ---- state -------------------------------------

    mapping(address => euint64) private _balances;

    /// Which account each handle was issued to. The
    /// precompile authorizes the *caller*, which for any
    /// contract call is this contract — and this contract
    /// owns every handle it created, so its ACL check
    /// cannot tell whether the person behind the call has
    /// any claim to the handle they named. Balance handles
    /// are public through the getter, so without this the
    /// token computes on a victim's balance and grants the
    /// attacker read access to the result.
    mapping(bytes32 => address) private _issuedTo;

    error HandleNotIssuedToCaller(bytes32 handle);
    error TransferToZero();

    /// Supply aggregates are public by design, so this
    /// is a handle to a trivially-encrypted public
    /// number, not a secret. Stored rather than made on
    /// read, because creating a handle is a state write
    /// and this getter must stay `view`.
    euint64 private _totalSupply;
    /// The supply in plaintext. Aggregates are public by
    /// design, and this value already sat readable in
    /// storage — exposing it makes the claim honest
    /// rather than changing what is disclosed.
    uint64 public totalSupplyPlain;

    address public immutable minter;

    // ---- events ------------------------------------

    /// All three indexed, matching the EIP exactly —
    /// indexers filter on topics, and a non-indexed
    /// amount would make Celar transfers invisible.
    event ConfidentialTransfer(address indexed from, address indexed to, bytes32 indexed amount);

    /// SHOULD in the EIP; emitted on the reveal path.
    event AmountDisclosed(bytes32 indexed handle, uint64 amount);

    error NotMinter();

    constructor(string memory name_, string memory symbol_, string memory uri_) {
        name = name_;
        symbol = symbol_;
        _contractURI = uri_;
        minter = msg.sender;
        _totalSupply = TFHE.asEuint64(0);
        // Owning the handle is not sufficient to reveal
        // it — the committee serves reveal only against an
        // explicit per-handle grant. Supply is public by
        // design, so the grant is issued at creation.
        TFHE.allow(_totalSupply, address(this), TFHE.PERM_REVEAL);
    }

    // ---- ERC-165 -----------------------------------

    /// Deliberately does NOT claim the ERC-7984 id
    /// (0x4958f2a4) while the operator model,
    /// confidentialTransferFrom and the AndCall family are
    /// absent. Claiming it would make integrators call
    /// functions that do not exist — the on-chain form of
    /// the same over-claim the project's copy rules
    /// forbid. Restore it when those land.
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x01ffc9a7;
    }

    function contractURI() external view returns (string memory) {
        return _contractURI;
    }

    // ---- views -------------------------------------

    /// A zero handle means no balance was ever recorded
    /// — not an encrypted zero. An encrypted zero is a
    /// registered handle the committee can serve; a
    /// zero handle is nothing at all.
    function confidentialBalanceOf(address account) external view returns (bytes32) {
        return euint64.unwrap(_balances[account]);
    }

    function confidentialTotalSupply() external view returns (bytes32) {
        return euint64.unwrap(_totalSupply);
    }

    /// Ask the committee to publish the supply handle.
    /// Callable by anyone: the value is public by design,
    /// and the contract owns the handle, so it is the
    /// party entitled to request. Without this the handle
    /// returned by confidentialTotalSupply is unreadable
    /// by everyone including the minter — the ACL has no
    /// wildcard, so "public" needed a mechanism, not just
    /// a comment.
    function revealTotalSupply() external returns (bytes32) {
        return TFHE.requestReveal(_totalSupply);
    }

    // ---- transfers ---------------------------------

    function confidentialTransfer(address to, bytes32 amount) external returns (bytes32) {
        if (_issuedTo[amount] != msg.sender) {
            revert HandleNotIssuedToCaller(amount);
        }
        return _transfer(msg.sender, to, euint64.wrap(amount));
    }

    /// Admits a fresh client ciphertext, then transfers
    /// it. See the known-unsound note above.
    function transferFromExternal(address to, bytes calldata ct, bytes calldata inputProof) external returns (bytes32) {
        euint64 amount = TFHE.fromExternal(ct, inputProof);
        _record(amount, msg.sender);
        return _transfer(msg.sender, to, amount);
    }

    function mint(address to, uint64 amount) external {
        if (msg.sender != minter) revert NotMinter();

        euint64 minted = TFHE.asEuint64(amount);
        _balances[to] = TFHE.add(_ensure(to), minted);
        _grantRead(_balances[to], to);
        _record(_balances[to], to);
        totalSupplyPlain += amount;
        _totalSupply = TFHE.asEuint64(totalSupplyPlain);
        // Owning the handle is not sufficient to reveal
        // it — the committee serves reveal only against an
        // explicit per-handle grant. Supply is public by
        // design, so the grant is issued at creation.
        TFHE.allow(_totalSupply, address(this), TFHE.PERM_REVEAL);

        // from = 0x0 on mint, per the EIP's SHOULD.
        emit ConfidentialTransfer(address(0), to, euint64.unwrap(minted));
    }

    // ---- internals ---------------------------------

    function _transfer(address from, address to, euint64 amount) private returns (bytes32) {
        if (to == address(0)) revert TransferToZero();
        euint64 fromBal = _ensure(from);
        _ensure(to);

        ebool ok = TFHE.le(amount, fromBal);
        euint64 actual = TFHE.select(ok, amount, TFHE.asEuint64(0));

        _balances[from] = TFHE.sub(fromBal, actual);

        // Re-read rather than reuse a cached handle: when
        // from == to, the credit must apply to the debited
        // balance, not to the value read before the debit.
        // Caching both operands up front made a
        // self-transfer overwrite the debit with the
        // credit, so the balance grew by the amount sent —
        // repeatable, and invisible off-chain because no
        // plaintext is ever exposed.
        //
        // Deliberately no `if (from == to)`: a plaintext
        // branch would give a self-transfer a different
        // gas profile and a different emitted handle,
        // which is a distinguisher an observer can use.
        // The re-read costs one SLOAD in every case.
        _balances[to] = TFHE.add(_balances[to], actual);

        _grantRead(_balances[from], from);
        _grantRead(_balances[to], to);

        // Both parties may read what actually moved;
        // neither learns the other's balance.
        _grantRead(actual, from);
        _grantRead(actual, to);
        _record(_balances[from], from);
        _record(_balances[to], to);
        // The recipient may forward what they received.
        _record(actual, to);

        // Fires unconditionally, including when `actual`
        // is an encrypted zero — the EIP requires
        // emission on zero-value transfers, and
        // suppressing it would leak the predicate
        // through log presence.
        emit ConfidentialTransfer(from, to, euint64.unwrap(actual));
        return euint64.unwrap(actual);
    }

    /// Lazily registers an encrypted zero so arithmetic
    /// never touches an unregistered handle, which the
    /// precompile refuses.
    function _ensure(address account) private returns (euint64) {
        euint64 h = _balances[account];
        if (euint64.unwrap(h) == bytes32(0)) {
            h = TFHE.asEuint64(0);
            _balances[account] = h;
        }
        _record(h, account);
        return h;
    }

    /// First write wins, mirroring the precompile's own
    /// registration semantics. Re-recording would let a
    /// later path silently reassign a handle's claimant.
    function _record(euint64 h, address account) private {
        bytes32 raw = euint64.unwrap(h);
        if (_issuedTo[raw] == address(0)) {
            _issuedTo[raw] = account;
        }
    }

    function _grantRead(euint64 handle, address account) private {
        TFHE.allow(handle, account, TFHE.PERM_REENCRYPT_TO_SELF);
    }
}
