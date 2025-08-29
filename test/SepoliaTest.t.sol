// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

interface IChallenge {
    function flag() external view returns (address);
}

/// @dev Responds `true` when probed with selector 0x0e8c21a3 (as the challenge expects)
contract ResponderTrue {
    fallback(bytes calldata) external payable returns (bytes memory out) {
        if (msg.sig == 0x0e8c21a3) {
            out = abi.encode(true);
        } else {
            revert("bad selector");
        }
    }

    /// @dev Triggers target's fallback by sending empty calldata.
    function go(address target) external {
        (bool ok, ) = target.call("");
        require(ok, "target reverted");
    }
}

contract SepoliaCaptureTest is Test {
    IChallenge private challenge;
    ResponderTrue private responder;

    function setUp() public {
        // 1) Fork Sepolia from env
        vm.createSelectFork(vm.envString("ETH_RPC_URL"));

        // 2) Challenge address from env: export ADDR=0x...
        address target = vm.envAddress("ADDR");
        require(target != address(0), "ADDR not set");

        challenge = IChallenge(target);

        // 3) Deploy responder (the account that will be set as flag)
        responder = new ResponderTrue();

        // (optional) fund responder for clarity; not strictly required
        vm.deal(address(responder), 0.01 ether);
    }

    function test_CaptureOnFork() public {
        address beforeFlag = challenge.flag();

        // Trigger target.fallback() FROM responder (msg.sender == responder)
        responder.go(address(challenge));

        // After: flag should be responder
        address afterFlag = challenge.flag();
        assertEq(afterFlag, address(responder), "flag not set to responder");
        assertTrue(afterFlag != beforeFlag, "flag unchanged");

        // Log the result so you can see it in -vv output
        emit log_named_address("flag()", afterFlag);
    }
}
