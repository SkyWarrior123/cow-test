// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";

interface IChallenge {
    function flag() external view returns (address);
}

interface IResponder7702 {
    function capture(address target) external payable;
}

contract CaptureWith7702Script is Script {
    // uses Foundry's 7702 cheatcode to sign & attach delegation for the next tx
    function run(address target, address impl) external {
        uint256 pk = vm.envUint("PK_UINT"); // same key as PRIVATE_KEY, but uint form
        address me = vm.addr(pk);

        console2.log("EOA:", me);
        console2.log("Target:", target);
        console2.log("Impl:", impl);

        // attach 7702 delegation (authorizationList) to the next tx
        vm.signAndAttachDelegation(impl, pk);

        // broadcast as the EOA: calling *our own EOA* as if it had `impl` code
        vm.startBroadcast(pk);
        IResponder7702(me).capture(target);
        vm.stopBroadcast();

        // verify
        address f = IChallenge(target).flag();
        console2.log("flag() =", f);
        require(f == me, "flag not captured by EOA");
    }
}
