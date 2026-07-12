// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ResolverIdentityRegistryV1} from "../src/ResolverIdentityRegistryV1.sol";

contract DeployResolverIdentityRegistryV1 {
    function deploy(address admin) external returns (ResolverIdentityRegistryV1) {
        return new ResolverIdentityRegistryV1(admin);
    }
}
