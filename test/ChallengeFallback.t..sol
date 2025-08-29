// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * Test suite — test/ChallengeFallback.t.sol
 *
 * What we test (based on your decompile):
 * - Challenge stores `address _flag` at slot 0.
 * - Its `fallback()` builds calldata with selector 0x0e8c21a3 and a single 32-byte zero arg,
 *   then low-level `call(msg.sender, data)`.
 * - It requires: (a) call succeeds, (b) returndata length >= 32, (c) first word is a canonical bool,
 *   (d) that bool is true ("Wrong answer" otherwise).
 * - If all pass, it sets `_flag = msg.sender`.
 *
 * So: only a CONTRACT that *itself* calls the challenge (so msg.sender is that contract) and
 * returns a canonical true (32 bytes with value 1) to selector 0x0e8c21a3 will capture.
 *
 * We deploy the provided creation bytecode directly, then exercise all responder cases.
 */

import "forge-std/Test.sol";
import "forge-std/console2.sol";

// ---------- Interfaces / helpers ----------

interface IChallenge {
    function flag() external view returns (address);
}

interface ICapture {
    function capture(address target) external;
    function captureValue(address target) external payable;
}

// Reads raw slot0 into an address (right-most 20 bytes).
library SlotReader {
    function slot0Address(address a) internal view returns (address out) {
        bytes32 raw;
        assembly {
            // vm.load in prod tests; here we use inline extcodecopy? No — read via extcode? Not possible.
            // In Foundry tests we have `vm.load`, so we expose a helper hook.
        }
        out = a; // placeholder so library compiles; we override below in the test with vm.load
    }
}

// ---------- Responder mocks (the "solver" shapes) ----------

// Responds TRUE to selector 0x0e8c21a3, otherwise reverts.
contract ResponderTrue is ICapture {
    event Probe(bytes4 sel, bytes data);

    // Return canonical `true` (ABI-encoded 32-byte 1) when asked for 0x0e8c21a3(uint256)
    fallback(bytes calldata data) external payable returns (bytes memory) {
        emit Probe(msg.sig, data);
        if (msg.sig == 0x0e8c21a3) {
            return abi.encode(true);
        }
        revert("bad selector");
    }

    // Triggers target.fallback() with empty calldata (so target sees msg.sender = this)
    function capture(address target) external {
        (bool ok, ) = target.call("");
        require(ok, "target reverted");
    }

    function captureValue(address target) external payable {
        (bool ok, ) = target.call{value: msg.value}("");
        require(ok, "target reverted");
    }
}

// Responds FALSE (canonical 0) to the selector.
contract ResponderFalse is ICapture {
    fallback(bytes calldata data) external payable returns (bytes memory) {
        if (msg.sig == 0x0e8c21a3) {
            return abi.encode(false); // canonical false -> will hit "Wrong answer"
        }
        revert("bad selector");
    }

    function capture(address target) external {
        (bool ok, ) = target.call("");
        require(ok, "target reverted");
    }

    function captureValue(address target) external payable {
        (bool ok, ) = target.call{value: msg.value}("");
        require(ok, "target reverted");
    }
}

// Returns a *non-canonical* truthy word (e.g. 2) -> should fail the canonicality require.
contract ResponderNonCanonical is ICapture {
    fallback(bytes calldata data) external payable returns (bytes memory) {
        if (msg.sig == 0x0e8c21a3) {
            return abi.encode(uint256(2)); // not 0/1
        }
        revert("bad selector");
    }

    function capture(address target) external {
        (bool ok, ) = target.call("");
        require(ok, "target reverted");
    }

    function captureValue(address target) external payable {
        (bool ok, ) = target.call{value: msg.value}("");
        require(ok, "target reverted");
    }
}

// Returns too-short returndata (<32 bytes) -> length check must fail.
contract ResponderShort is ICapture {
    fallback(bytes calldata data) external payable returns (bytes memory) {
        if (msg.sig == 0x0e8c21a3) {
            // 1 byte "true-y" but *not* ABI canonical
            return hex"01";
        }
        revert("bad selector");
    }

    function capture(address target) external {
        (bool ok, ) = target.call("");
        require(ok, "target reverted");
    }

    function captureValue(address target) external payable {
        (bool ok, ) = target.call{value: msg.value}("");
        require(ok, "target reverted");
    }
}

// Reverts on the inner callback -> challenge must revert with "Call failed".
contract ResponderRevert is ICapture {
    fallback(bytes calldata) external payable returns (bytes memory) {
        revert("nope");
    }

    function capture(address target) external {
        (bool ok, ) = target.call("");
        require(ok, "target reverted");
    }

    function captureValue(address target) external payable {
        (bool ok, ) = target.call{value: msg.value}("");
        require(ok, "target reverted");
    }
}

// ---------- The test suite ----------

contract ChallengeFallbackTest is Test {
    // Provided creation bytecode (verbatim from assignment)
    bytes constant CREATION = hex"6080604052348015600e575f5ffd5b5061046d8061001c5f395ff3fe608060405260043610610021575f3560e01c8063890eba68146101e557610022565b5b5f5f3373ffffffffffffffffffffffffffffffffffffffff166040516024016040516020818303038152906040527f0e8c21a3000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff83818316178352505050506040516100cb9190610285565b5f604051808303815f865af19150503d805f8114610104576040519150601f19603f3d011682016040523d82523d5f602084013e610109565b606091505b50915091508161014e576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610145906102f5565b60405180910390fd5b5f81806020019051810190610163919061034c565b9050806101a5576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161019c906103c1565b60405180910390fd5b335f5f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055005b3480156101f0575f5ffd5b506101f961020f565b604051610206919061041e565b60405180910390f35b5f5f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b5f81519050919050565b5f81905092915050565b8281835e5f83830152505050565b5f61025f82610233565b610269818561023d565b9350610279818560208601610247565b80840191505092915050565b5f6102908284610255565b915081905092915050565b5f82825260208201905092915050565b7f43616c6c206661696c65640000000000000000000000000000000000000000005f82015250565b5f6102df600b8361029b565b91506102ea826102ab565b602082019050919050565b5f6020820190508181035f83015261030c816102d3565b9050919050565b5f5ffd5b5f8115159050919050565b61032b81610317565b8114610335575f5ffd5b50565b5f8151905061034681610322565b92915050565b5f6020828403121561036157610360610313565b5b5f61036e84828501610338565b91505092915050565b7f57726f6e6720616e7377657200000000000000000000000000000000000000005f82015250565b5f6103ab600c8361029b565b91506103b682610377565b602082019050919050565b5f6020820190508181035f8301526103d88161039f565b9050919050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f610408826103df565b9050919050565b610418816103fe565b82525050565b5f6020820190506104315f83018461040f565b9291505056fea264697066735822122071cd63f7255e3ade7ae5f4db4492fdff08135bd0d2ac354f6c70b45b8942ddf364736f6c634300081c0033";

    address challenge;

    // test EOAs
    address eoa1 = vm.addr(0xA11CE);
    address eoa2 = vm.addr(0xB0B);

    function setUp() public {
        // fund EOAs
        vm.deal(eoa1, 100 ether);
        vm.deal(eoa2, 100 ether);

        // deploy the challenge from creation bytecode
        challenge = _deploy(CREATION);
        require(challenge.code.length > 0, "challenge not deployed");
        console2.log("Challenge deployed at", challenge);
    }

    // --- helpers ---

    function _deploy(bytes memory creation) internal returns (address addr) {
        assembly {
            addr := create(0, add(creation, 0x20), mload(creation))
        }
        require(addr != address(0), "create failed");
    }

    function _slot0Address(address a) internal view returns (address out) {
        // Foundry cheatcode to read raw storage
        bytes32 raw = vm.load(a, bytes32(uint256(0)));
        out = address(uint160(uint256(raw)));
    }

    // --- tests ---

    /// EOA calls cannot capture: the inner self-call to EOA returns empty data (<32),
    /// so the length check fails and the whole tx reverts.
    function test_EOA_CannotCapture() public {
        vm.startPrank(eoa1, eoa1);
        vm.expectRevert(); // any reason is fine (length check or following checks)
        (bool ok, ) = challenge.call("");
        // If revert bubbles up, `ok` is false only for low-level call without revert;
        // here, .call("") from EOA -> challenge reverts; expectRevert will catch it.
        vm.stopPrank();

        // flag remains zero
        assertEq(IChallenge(challenge).flag(), address(0));
        assertEq(_slot0Address(challenge), address(0));
    }

    /// A correct responder (contract) that returns ABI-canonical `true`
    /// to selector 0x0e8c21a3 should capture.
    function test_ResponderTrue_Captures() public {
        ResponderTrue r = new ResponderTrue();

        // Have the responder initiate the call so msg.sender == responder
        vm.prank(eoa1);
        r.capture(challenge);

        // Verify flag via view and raw slot
        address flagged = IChallenge(challenge).flag();
        assertEq(flagged, address(r), "flag() mismatch");
        assertEq(_slot0Address(challenge), address(r), "slot0 mismatch");
    }

    /// Returning canonical false triggers "Wrong answer".
    function test_ResponderFalse_WrongAnswer() public {
        ResponderFalse r = new ResponderFalse();

        vm.expectRevert(bytes("Wrong answer"));
        vm.prank(eoa1);
        r.capture(challenge);

        // still zero
        assertEq(IChallenge(challenge).flag(), address(0));
    }

    /// Returning a non-canonical boolean (e.g., 2) must fail the canonicality check.
    function test_ResponderNonCanonical_Reverts() public {
        ResponderNonCanonical r = new ResponderNonCanonical();

        vm.expectRevert(); // canonicality require has no custom string
        vm.prank(eoa1);
        r.capture(challenge);

        assertEq(IChallenge(challenge).flag(), address(0));
    }

    /// Returning less than 32 bytes must fail the length check.
    function test_ResponderShort_Reverts() public {
        ResponderShort r = new ResponderShort();

        vm.expectRevert(); // length check require has no custom string
        vm.prank(eoa1);
        r.capture(challenge);

        assertEq(IChallenge(challenge).flag(), address(0));
    }

    /// If the inner callback reverts, challenge should revert with "Call failed".
    function test_ResponderRevert_CallFailed() public {
        ResponderRevert r = new ResponderRevert();

        vm.expectRevert(bytes("Call failed"));
        vm.prank(eoa1);
        r.capture(challenge);

        assertEq(IChallenge(challenge).flag(), address(0));
    }

    /// Sending ETH along should not matter (fallback is payable) and capture still works.
    function test_ResponderTrue_Captures_WithValue() public {
        ResponderTrue r = new ResponderTrue();

        vm.prank(eoa1);
        r.captureValue{value: 1 wei}(challenge);

        assertEq(IChallenge(challenge).flag(), address(r));
    }

    /// Once captured by a correct responder, an EOA still cannot overwrite it.
    function test_EOA_CannotOverwrite_AfterCapture() public {
        ResponderTrue r = new ResponderTrue();
        vm.prank(eoa1);
        r.capture(challenge);
        assertEq(IChallenge(challenge).flag(), address(r));

        // Now EOA tries again
        vm.startPrank(eoa2, eoa2);
        vm.expectRevert();
        (bool ok, ) = challenge.call("");
        vm.stopPrank();

        // flag unchanged
        assertEq(IChallenge(challenge).flag(), address(r));
    }

    /// Another valid responder can re-capture and overwrite the flag.
    function test_AnotherResponder_CanRecapture() public {
        ResponderTrue r1 = new ResponderTrue();
        ResponderTrue r2 = new ResponderTrue();

        vm.prank(eoa1);
        r1.capture(challenge);
        assertEq(IChallenge(challenge).flag(), address(r1));

        vm.prank(eoa2);
        r2.capture(challenge);
        assertEq(IChallenge(challenge).flag(), address(r2));
    }

    /// Sanity: flag view must mirror raw slot value.
    function test_FlagMatchesRawSlot() public {
        ResponderTrue r = new ResponderTrue();
        vm.prank(eoa1);
        r.capture(challenge);

        address viaView = IChallenge(challenge).flag();
        address viaSlot = _slot0Address(challenge);
        assertEq(viaView, viaSlot);
    }
}
