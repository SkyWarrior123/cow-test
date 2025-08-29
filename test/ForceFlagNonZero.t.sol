// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

interface IChallengeLike {
    function flag() external view returns (address);
}

/// @dev Minimal shape of the challenge: an address at storage slot 0 and a flag() view.
///      We ignore fallback here since the goal is just "flag != address(0)" in a mock.
contract ChallengeShape is IChallengeLike {
    address internal _flag; // <== lives at slot 0
    function flag() external view returns (address) { return _flag; }
}


contract ForceFlagNonZeroTest is Test {
    ChallengeShape internal challenge;

    function setUp() public {
        challenge = new ChallengeShape();
    }

    /// @dev Pack an address like Solidity does into a bytes32 storage word.
    function _asWord(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    /// @notice Force flag to an arbitrary EOA (non-zero).
    function test_ForceFlagToEOA() public {
        address eoa = makeAddr("my-eoa");
        vm.store(address(challenge), bytes32(uint256(0)), _asWord(eoa));
        assertEq(IChallengeLike(address(challenge)).flag(), eoa, "flag should equal EOA");
        assertTrue(IChallengeLike(address(challenge)).flag() != address(0), "flag must be non-zero");
    }

    /// @notice Force flag to a contract address (this test contract).
    function test_ForceFlagToContract() public {
        address ctr = address(this);
        vm.store(address(challenge), bytes32(uint256(0)), _asWord(ctr));
        assertEq(IChallengeLike(address(challenge)).flag(), ctr, "flag should equal contract");
    }

    /// @notice Force flag to tx.origin (for completeness; in Foundry this defaults to address(this) unless pranked).
    function test_ForceFlagToTxOrigin() public {
        // If you want tx.origin to be a distinct EOA, uncomment:
        // address originEOA = makeAddr("origin");
        // vm.startPrank(originEOA, originEOA);
        // ... do your writes/calls ...
        // vm.stopPrank();

        address originNow = tx.origin; // likely address(this) unless pranked
        vm.store(address(challenge), bytes32(uint256(0)), _asWord(originNow));
        assertEq(IChallengeLike(address(challenge)).flag(), originNow, "flag should equal tx.origin");
    }
}
