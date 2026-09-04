// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {DeployLegalDMS} from "../script/DeployDocumentRegistry.s.sol";

contract DeployTest is Test {
    function test_RunDeploymentScript() public {
        // Mock the PRIVATE_KEY environment variable that the script expects
        vm.setEnv("PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        
        DeployLegalDMS deployer = new DeployLegalDMS();
        
        // Execute the deployment script
        deployer.run();
        
        // If the script runs without reverting, the test passes 
        // and we get 100% coverage on the script itself!
    }
}
