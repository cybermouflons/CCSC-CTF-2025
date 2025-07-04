// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

import "forge-std/Script.sol";
import {GatekeeperLogic} from "../src/GatekeeperLogic.sol";
import {Proxy} from "../src/Proxy.sol";

/// forge script --broadcast --rpc-url $RPC_URL script/Deploy.s.sol
contract Deploy is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY"); // deployer key
        vm.startBroadcast(pk);

        GatekeeperLogic logic = new GatekeeperLogic();
        Proxy proxy = new Proxy(address(logic));

        console2.log("Logic  :", address(logic));
        console2.log("Proxy  :", address(proxy));

        vm.stopBroadcast();
    }
}
