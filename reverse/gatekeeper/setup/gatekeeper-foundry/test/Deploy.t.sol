// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {Proxy} from "../src/Proxy.sol";
import {GatekeeperLogic} from "../src/GatekeeperLogic.sol";

contract DeployTest is Test {
    Proxy proxy;
    address logicAddr;

    function setUp() public {
        // fork mainnet
        string memory rpc = vm.envString("ETH_RPC_URL");
        uint256 forkId = vm.createSelectFork(rpc, 22_823_151);
        vm.selectFork(forkId);

        GatekeeperLogic logic = new GatekeeperLogic();
        logicAddr = address(logic);
        proxy = new Proxy(logicAddr);
    }

    function test_ProxyDelegates() public {
        // success() should read false via proxy
        (bool ok, bytes memory ret) = address(proxy).call(
            abi.encodeWithSignature("success()")
        );
        assertTrue(ok);
        assertEq(abi.decode(ret, (bool)), false);
    }
}
