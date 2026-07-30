// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ResolverIdentityRegistryV1} from "../src/ResolverIdentityRegistryV1.sol";

interface Vm {
    function envAddress(string calldata name) external returns (address);
    function startBroadcast() external;
    function stopBroadcast() external;
}

contract DeployResolverIdentityRegistry {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant SEPOLIA_CHAIN_ID = 11155111;

    function run() external returns (ResolverIdentityRegistryV1 registry) {
        require(block.chainid != 1, "Ethereum Mainnet is forbidden");
        require(block.chainid == SEPOLIA_CHAIN_ID, "expected Ethereum Sepolia");

        address governance = vm.envAddress("GOVERNANCE_ADDRESS");
        require(governance != address(0), "GOVERNANCE_ADDRESS is zero");

        vm.startBroadcast();
        registry = new ResolverIdentityRegistryV1(governance);
        vm.stopBroadcast();

        require(address(registry).code.length > 0, "deployment produced no code");
    }
}
