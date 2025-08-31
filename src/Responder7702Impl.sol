// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Code that your EOA temporarily executes via EIP-7702.
contract Responder7702Impl {
    /// Challenge pings msg.sender with selector 0x0e8c21a3 expecting a `bool true`.
    fallback() external payable {
        if (msg.sig == 0x0e8c21a3) {
            assembly { mstore(0x00, 1) return(0x00, 0x20) } // encode(bool true)
        }
        revert("bad selector");
    }

    /// When your EOA is temporarily “codeful”, call the challenge (empty calldata)
    /// so its fallback runs and sets flag = msg.sender (your EOA).
    function capture(address target) external payable {
        (bool ok, ) = target.call("");
        require(ok, "call failed");
    }

    receive() external payable {}
}
