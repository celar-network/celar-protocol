// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {euint64} from "./TFHE.sol";

/// Test receivers for the AndCall family. Each one exists
/// to make a single pre-specified property observable;
/// none is a template for a real integrator.

interface IConfidentialToken {
    function confidentialTransfer(address to, bytes32 amount) external returns (bytes32);
    function confidentialBalanceOf(address who) external view returns (bytes32);
}

/// Accepts, and records what it could see at callback time.
///
/// `seenBalance` is read DURING the callback, so comparing
/// it afterwards to the settled balance is what
/// demonstrates the callback fires after the credit rather
/// than between the debit and the credit.
contract AcceptingReceiver {
    address public token;
    address public lastOperator;
    address public lastFrom;
    bytes32 public lastAmount;
    bytes32 public seenBalance;

    constructor(address t) { token = t; }

    function onConfidentialTransferReceived(address operator, address from, euint64 amount, bytes calldata)
        external
        returns (bool)
    {
        lastOperator = operator;
        lastFrom = from;
        lastAmount = euint64.unwrap(amount);
        seenBalance = IConfidentialToken(token).confidentialBalanceOf(address(this));
        return true;
    }
}

/// Refuses. The plain refund case.
contract RefusingReceiver {
    function onConfidentialTransferReceived(address, address, euint64, bytes calldata)
        external
        pure
        returns (bool)
    {
        return false;
    }
}

/// Spends what it was just sent, THEN refuses.
///
/// This is the inherited best-effort-refund caveat made
/// executable: the refund is an ordinary transfer back, so
/// against a drained balance the branchless rule moves zero
/// and the tokens stay gone. A test asserts this rather
/// than a comment claiming it.
contract SpendthriftReceiver {
    address public token;
    address public sink;

    constructor(address t, address s) { token = t; sink = s; }

    function onConfidentialTransferReceived(address, address, euint64 amount, bytes calldata)
        external
        returns (bool)
    {
        IConfidentialToken(token).confidentialTransfer(sink, euint64.unwrap(amount));
        return false;
    }
}

/// Makes an ordinary transfer during the callback.
///
/// Legitimate behaviour, and the reason the guard is scoped
/// to the callback path rather than to all entry. The
/// property under test is that this cannot DISPLACE a
/// claimant of a shared handle — not that it is refused.
contract ReentrantReceiver {
    address public token;
    address public sink;
    bool public reentered;

    constructor(address t, address s) { token = t; sink = s; }

    function onConfidentialTransferReceived(address, address, euint64 amount, bytes calldata)
        external
        returns (bool)
    {
        reentered = true;
        IConfidentialToken(token).confidentialTransfer(sink, euint64.unwrap(amount));
        return true;
    }
}
