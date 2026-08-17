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

    /// Supply aggregates are public by design, so this
    /// is a handle to a trivially-encrypted public
    /// number, not a secret. Stored rather than made on
    /// read, because creating a handle is a state write
    /// and this getter must stay `view`.
    euint64 private _totalSupply;
    uint64 private _totalSupplyPlain;

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
    }

    // ---- ERC-165 -----------------------------------

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x4958f2a4 || interfaceId == 0x01ffc9a7;
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

    // ---- transfers ---------------------------------

    function confidentialTransfer(address to, bytes32 amount) external returns (bytes32) {
        return _transfer(msg.sender, to, euint64.wrap(amount));
    }

    /// Admits a fresh client ciphertext, then transfers
    /// it. See the known-unsound note above.
    function transferFromExternal(address to, bytes calldata ct, bytes calldata inputProof) external returns (bytes32) {
        euint64 amount = TFHE.fromExternal(ct, inputProof);
        return _transfer(msg.sender, to, amount);
    }

    function mint(address to, uint64 amount) external {
        if (msg.sender != minter) revert NotMinter();

        euint64 minted = TFHE.asEuint64(amount);
        _balances[to] = TFHE.add(_ensure(to), minted);
        _grantRead(_balances[to], to);

        _totalSupplyPlain += amount;
        _totalSupply = TFHE.asEuint64(_totalSupplyPlain);

        // from = 0x0 on mint, per the EIP's SHOULD.
        emit ConfidentialTransfer(address(0), to, euint64.unwrap(minted));
    }

    // ---- internals ---------------------------------

    function _transfer(address from, address to, euint64 amount) private returns (bytes32) {
        euint64 fromBal = _ensure(from);
        euint64 toBal = _ensure(to);

        // The whole authorization decision, expressed
        // arithmetically.
        ebool ok = TFHE.le(amount, fromBal);
        euint64 actual = TFHE.select(ok, amount, TFHE.asEuint64(0));

        _balances[from] = TFHE.sub(fromBal, actual);
        _balances[to] = TFHE.add(toBal, actual);

        _grantRead(_balances[from], from);
        _grantRead(_balances[to], to);

        // Both parties may read what actually moved;
        // neither learns the other's balance.
        _grantRead(actual, from);
        _grantRead(actual, to);

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
        return h;
    }

    function _grantRead(euint64 handle, address account) private {
        TFHE.allow(handle, account, TFHE.PERM_REENCRYPT_TO_SELF);
    }
}
