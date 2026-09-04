// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console2} from "forge-std/Script.sol";
import {AccessRegistry} from "../src/AccessRegistry.sol";
import {AnchorRegistry} from "../src/AnchorRegistry.sol";
import {CustodyLedger} from "../src/CustodyLedger.sol";

contract DeployLegalDMS is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console2.log("Deployer:", deployer);

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy AccessRegistry first (other contracts depend on it)
        AccessRegistry accessRegistry = new AccessRegistry(deployer);
        console2.log("AccessRegistry deployed to:", address(accessRegistry));

        // 2. Deploy AnchorRegistry (references AccessRegistry for auth)
        AnchorRegistry anchorRegistry = new AnchorRegistry(address(accessRegistry));
        console2.log("AnchorRegistry deployed to:", address(anchorRegistry));

        // 3. Deploy CustodyLedger (references AccessRegistry for auth)
        CustodyLedger custodyLedger = new CustodyLedger(address(accessRegistry));
        console2.log("CustodyLedger deployed to:", address(custodyLedger));

        vm.stopBroadcast();

        console2.log("--- All contracts deployed successfully ---");
    }
}
