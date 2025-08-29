// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

interface IChallenge {
    function flag() external view returns (address);
}

/// Minimal harness that reproduces the challenge's behavior:
/// - fallback pings msg.sender with selector 0x0e8c21a3
/// - expects abi.encode(true) back
/// - if ok, sets flag = msg.sender
contract ChallengeLike {
    address public flag;

    fallback() external payable {
        (bool ok, bytes memory out) = msg.sender.call(hex"0e8c21a3");
        require(ok, "Call failed");
        require(out.length >= 32 && abi.decode(out, (bool)), "Wrong answer");
        flag = msg.sender;
    }
}

contract EOAFlagCaptureTest is Test {
    // Derived from your env PRIVATE_KEY
    address me;
    uint256 pk;

    function setUp() public {
        // Pull your private key from env (0x-prefixed hex)
        bytes32 pkBytes = vm.envBytes32("PRIVATE_KEY");
        pk = uint256(pkBytes);
        me = vm.addr(pk);                // derive EOA from the private key
        vm.deal(me, 1 ether);            // give the EOA gas for txs
    }

    /// --- Local test (no forking) -----------------------------------------

    function test_EOA_CapturesFlag_Locally() public {
        // Deploy local harness
        ChallengeLike challenge = new ChallengeLike();

        // Mock the probe the challenge makes to msg.sender:
        // when the challenge calls `me` with selector 0x0e8c21a3,
        // return abi.encode(true) so the check passes.
        vm.mockCall(
            me,
            abi.encodeWithSelector(bytes4(0x0e8c21a3)),
            abi.encode(true)
        );

        // Send a tx from your EOA to trigger fallback
        vm.prank(me);
        (bool ok, ) = address(challenge).call("");
        assertTrue(ok, "fallback tx failed");

        // Your EOA becomes the flag holder
        assertEq(challenge.flag(), me, "flag not set to EOA");
    }

    /// --- Sepolia fork test (uses ADDR + ETH_RPC_URL) ----------------------

    function test_EOA_CapturesFlag_OnFork() public {
        // Select Sepolia fork
        vm.createSelectFork(vm.envString("ETH_RPC_URL"));

        // Real deployed challenge address (env: ADDR)
        IChallenge c = IChallenge(vm.envAddress("ADDR"));

        // Sanity: read old flag (often zero)
        address beforeFlag = c.flag();

        // Mock the in-tx callback to your EOA
        vm.mockCall(
            me,
            abi.encodeWithSelector(bytes4(0x0e8c21a3)),
            abi.encode(true)
        );

        // Trigger fallback from your EOA on-chain (fork)
        vm.prank(me);
        (bool ok, ) = address(c).call("");
        assertTrue(ok, "fallback tx reverted on fork");

        // Now flag should be your EOA
        assertEq(c.flag(), me, "flag not set to EOA on fork");
        assertTrue(c.flag() != beforeFlag, "flag unchanged");
    }
}
