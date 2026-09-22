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
/// ## Deferred by design — now empty
///
/// The AndCall family was deferred as a reentrancy
/// surface wanting review rather than addition. The
/// review is done (verdict: safe with a guard, not
/// provisional) and the owner decided to ship it, so it
/// is implemented below. Time-boxed operators and
/// confidentialTransferFrom were deferred here too and
/// landed earlier.
///
/// ## The refund is best-effort, and that is inherited
///
/// A receiver may shrink its own balance during the
/// callback, return false, and the refund then moves
/// zero — the sender's tokens stay with the recipient.
/// This is the reference standard's behaviour, not
/// something added here, and it is asserted by a test
/// rather than left as a caveat nobody reads.
///
/// ## Known-unsound dependency
///
/// transferFromExternal admits a ciphertext through the
/// input-proof path, which verifies nothing beyond non-
/// emptiness. Until input admission is made sound, an
/// observer can replay an admitted ciphertext. Do not
/// present this path as confidential in a demo.
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
/// handle preimage — the change that closes this and
/// input-admission front-running together.
/// Documented rather than mitigated, because a mitigation
/// that reads like protection and isn't is worse than a
/// stated exposure.
/// Receiver hook for the AndCall family.
///
/// Returning false asks for a refund. Reverting is NOT
/// the same thing: a revert bubbles and undoes the whole
/// transfer, which is the receiver's right and needs no
/// refund path. Only an explicit false triggers one.
interface IConfidentialTransferReceiver {
    function onConfidentialTransferReceived(
        address operator,
        address from,
        euint64 amount,
        bytes calldata data
    ) external returns (bool);
}

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
    mapping(bytes32 => mapping(address => bool)) private _issuedTo;

    /// Depth of the callback path only — deliberately NOT a
    /// global reentrancy lock.
    ///
    /// A receiver making an ordinary transfer during its
    /// callback is legitimate and must keep working; the
    /// review's finding is that such a call is harmless by
    /// construction, because _record is an additive
    /// idempotent set insertion and cannot displace a
    /// claimant. A blanket guard would break that
    /// legitimate case AND hide the property, leaving a
    /// test that passes for the wrong reason. What this
    /// blocks is a nested AndCall, where two refund paths
    /// could interleave over one amount.
    uint256 private _inCallback;

    error ReentrantCallback();
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

    /// SHOULD in the EIP. Emitted on the supply reveal, and
    /// ONLY there — which needs explaining, because the
    /// obvious reading is that every disclosure emits one.
    ///
    /// A user amount is disclosed by the committee, off
    /// chain, after a request. The plaintext never returns
    /// to this contract: revealTotalSupply hands back a
    /// request id, not a value, and no callback path exists
    /// to carry one. So for user amounts this event is not
    /// merely unimplemented, it is unemittable as the system
    /// is built — a contract cannot announce a number it
    /// never learns.
    ///
    /// The supply is the one case where it holds both sides.
    /// Aggregates are public by design, so the plaintext
    /// sits in totalSupplyPlain beside the handle, and the
    /// event can state the binding truthfully.
    event AmountDisclosed(bytes32 indexed handle, uint64 amount);

    error NotMinter();

    /// Time-boxed, per the standard — deliberately not an
    /// ERC-20 allowance. An expiry matters more here than
    /// on a transparent token: a standing permission over
    /// confidential balances is one the holder cannot
    /// audit, because they cannot see what was moved.
    mapping(address => mapping(address => uint48)) private _operatorUntil;

    event OperatorSet(address indexed holder, address indexed operator, uint48 until);

    error NotAnOperator(address holder, address caller);

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
    /// forbid.
    ///
    /// Restore it only when EVERY must-row in the
    /// conformance matrix is closed — a stricter condition
    /// than the three items named above, which have landed.
    /// Note that confidentialTotalSupply may require a
    /// design decision first: supply aggregates are public
    /// by design (G5), so a handle-typed total supply is
    /// not merely unimplemented.
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
        // Announced here rather than at mint: this is the
        // call that makes the handle readable, so it is the
        // moment a disclosure actually occurs. Emitting at
        // mint would claim a disclosure nobody requested.
        emit AmountDisclosed(euint64.unwrap(_totalSupply), totalSupplyPlain);
        return TFHE.requestReveal(_totalSupply);
    }

    // ---- transfers ---------------------------------

    function confidentialTransfer(address to, bytes32 amount) external returns (bytes32) {
        if (!_issuedTo[amount][msg.sender]) {
            revert HandleNotIssuedToCaller(amount);
        }
        return _transfer(msg.sender, to, euint64.wrap(amount));
    }

    /// Transfer, then notify the recipient in one call.
    ///
    /// The callback fires AFTER every state write in
    /// _transfer — balances, grants, provenance and the
    /// event. That ordering is a requirement, not a
    /// preference: the self-transfer fix re-reads
    /// _balances[to] after the debit and assumes nothing
    /// interleaves between the two writes.
    function confidentialTransferAndCall(address to, bytes32 amount, bytes calldata data)
        external
        returns (bytes32)
    {
        if (!_issuedTo[amount][msg.sender]) {
            revert HandleNotIssuedToCaller(amount);
        }
        bytes32 moved = _transfer(msg.sender, to, euint64.wrap(amount));
        _notify(msg.sender, msg.sender, to, euint64.wrap(moved), data);
        return moved;
    }

    /// The delegated form. Both plaintext checks are the
    /// delegated path's, unchanged — see
    /// confidentialTransferFrom for why the second one is
    /// not ceremony.
    function confidentialTransferFromAndCall(address from, address to, bytes32 amount, bytes calldata data)
        external
        returns (bytes32)
    {
        if (msg.sender != from && !isOperator(from, msg.sender)) {
            revert NotAnOperator(from, msg.sender);
        }
        if (!_issuedTo[amount][from] && !_issuedTo[amount][msg.sender]) {
            revert HandleNotIssuedToCaller(amount);
        }
        bytes32 moved = _transfer(from, to, euint64.wrap(amount));
        _notify(msg.sender, from, to, euint64.wrap(moved), data);
        return moved;
    }

    /// Calls the receiver hook and refunds on refusal.
    ///
    /// An EOA recipient has no hook, so there is nothing to
    /// call and nothing to refuse. Skipping the call for
    /// code-less accounts is not an optimisation: calling a
    /// plain address returns success with empty returndata,
    /// which would decode as a refusal and refund every
    /// transfer to an EOA.
    function _notify(address operator, address from, address to, euint64 amount, bytes calldata data) private {
        if (to.code.length == 0) return;
        if (_inCallback != 0) revert ReentrantCallback();
        _inCallback = 1;
        bool accepted = IConfidentialTransferReceiver(to).onConfidentialTransferReceived(operator, from, amount, data);
        _inCallback = 0;

        if (!accepted) {
            // The refund is an ordinary transfer back, so it
            // emits its own ConfidentialTransfer and an
            // indexer can tell it from the original by
            // direction. It is best-effort by construction:
            // if the receiver spent what it was sent, the
            // branchless rule moves zero rather than
            // reverting, and the tokens stay put.
            _transfer(to, from, amount);
        }
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

    /// Provenance is a SET, not a single claimant. Handles are
    /// deterministic, so two honest accounts minted the same
    /// amount derive the same balance handle; under the previous
    /// first-write-wins rule the second was locked out of its own
    /// balance. Recording is therefore additive and idempotent,
    /// and the transfer paths test membership, not identity.
    ///
    /// INTERIM. This makes the collision survivable; it does not
    /// address the root cause, which is that the handle preimage
    /// omits the submitter, so identical operations by different
    /// callers derive identical handles. Whether a shared handle
    /// denotes one underlying balance or two is not yet settled.
    function _record(euint64 h, address account) private {
        _issuedTo[euint64.unwrap(h)][account] = true; // idempotent
    }

    function _grantRead(euint64 handle, address account) private {
        TFHE.allow(handle, account, TFHE.PERM_REENCRYPT_TO_SELF);
    }

    // ---- operators ---------------------------------

    /// Setting `until` to a past value revokes: there is
    /// no separate revoke call, and none is needed.
    function setOperator(address operator, uint48 until) external {
        _operatorUntil[msg.sender][operator] = until;
        emit OperatorSet(msg.sender, operator, until);
    }

    function isOperator(address holder, address spender) public view returns (bool) {
        // block.timestamp is the right primitive here and the
        // linter's warning does not apply: the standard specifies a
        // uint48 *timestamp* expiry, and block numbers would make a
        // "30 day" grant drift as block time varies. Validator
        // influence over the timestamp is seconds, against a
        // permission measured in days. Timestamp dependence is
        // dangerous when it gates a race; this gates a duration.
        return _operatorUntil[holder][spender] >= block.timestamp;
    }

    /// Move `amount` from `from`, as `from` or as their
    /// operator.
    ///
    /// Two plaintext checks, so neither leaks: the caller
    /// must be authorised, and the amount handle must have
    /// been issued to the holder or to the caller.
    ///
    /// That second check is not ceremony. Without it an
    /// operator could name a third party's balance handle
    /// as the amount, send to themselves, and collect the
    /// read grant on what actually moved — the same
    /// confused-deputy attack the direct path already
    /// refuses, arriving through delegation.
    function confidentialTransferFrom(address from, address to, bytes32 amount) external returns (bytes32) {
        if (msg.sender != from && !isOperator(from, msg.sender)) {
            revert NotAnOperator(from, msg.sender);
        }
        if (!_issuedTo[amount][from] && !_issuedTo[amount][msg.sender]) {
            revert HandleNotIssuedToCaller(amount);
        }
        return _transfer(from, to, euint64.wrap(amount));
    }
}
