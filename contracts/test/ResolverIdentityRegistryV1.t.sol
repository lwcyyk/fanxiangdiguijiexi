// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ResolverIdentityRegistryV1} from "../src/ResolverIdentityRegistryV1.sol";

contract ResolverIdentityRegistryV1Test {
    ResolverIdentityRegistryV1 registry;

    bytes32 root = bytes32(uint256(1));
    bytes32 resolver = bytes32(uint256(11));
    bytes32 resolver2 = bytes32(uint256(12));
    bytes32 objectHash = bytes32(uint256(21));
    bytes32 objectHash2 = bytes32(uint256(22));
    bytes32 endpoint = bytes32(uint256(31));

    function setUp() public {
        registry = new ResolverIdentityRegistryV1(address(this));
    }

    function testAuthorizedRootPublish() public {
        registry.publishRoot(root, 1);
        assertEq(uint256(registry.getRootStatus(root)), uint256(ResolverIdentityRegistryV1.Status.ACTIVE));
    }

    function testUnauthorizedRootPublishFails() public {
        UnauthorizedCaller caller = new UnauthorizedCaller(registry);
        expectRevert(address(caller), abi.encodeWithSignature("publishRoot(bytes32,uint64)", root, uint64(1)));
    }

    function testRootCanRevoke() public {
        registry.publishRoot(root, 1);
        registry.revokeRoot(root);
        assertEq(uint256(registry.getRootStatus(root)), uint256(ResolverIdentityRegistryV1.Status.REVOKED));
    }

    function testRevokedRootCannotBeRepublished() public {
        registry.publishRoot(root, 1);
        registry.revokeRoot(root);
        expectRevertHere(abi.encodeWithSelector(registry.publishRoot.selector, root, uint64(2)));
    }

    function testResolverAnchorCanPublish() public {
        publishRootAndResolver();
        ResolverIdentityRegistryV1.ResolverAnchor memory anchor = registry.getResolverAnchor(resolver);
        assertEq(anchor.resolverIdKey, resolver);
        assertEq(anchor.objectHash, objectHash);
        assertEq(anchor.stateRoot, root);
        assertEq(uint256(anchor.objectVersion), 1);
    }

    function testResolverObjectVersionMustIncrease() public {
        publishRootAndResolver();
        expectRevertHere(
            abi.encodeWithSelector(
                registry.updateResolver.selector,
                resolver,
                objectHash2,
                root,
                uint64(1),
                future(),
                ResolverIdentityRegistryV1.Status.ACTIVE
            )
        );
        expectRevertHere(
            abi.encodeWithSelector(
                registry.updateResolver.selector,
                resolver,
                objectHash2,
                root,
                uint64(0),
                future(),
                ResolverIdentityRegistryV1.Status.ACTIVE
            )
        );
        registry.updateResolver(resolver, objectHash2, root, 2, future(), ResolverIdentityRegistryV1.Status.ACTIVE);
        assertEq(uint256(registry.getResolverAnchor(resolver).objectVersion), 2);
    }

    function testLowVersionReplayFails() public {
        publishRootAndResolver();
        registry.updateResolver(resolver, objectHash2, root, 3, future(), ResolverIdentityRegistryV1.Status.ACTIVE);
        expectRevertHere(
            abi.encodeWithSelector(
                registry.updateResolver.selector,
                resolver,
                objectHash,
                root,
                uint64(2),
                future(),
                ResolverIdentityRegistryV1.Status.ACTIVE
            )
        );
    }

    function testResolverCanRevoke() public {
        publishRootAndResolver();
        registry.revokeResolver(resolver);
        assertEq(
            uint256(registry.getResolverAnchor(resolver).status), uint256(ResolverIdentityRegistryV1.Status.REVOKED)
        );
    }

    function testRevokedResolverCannotBeUpdatedOrBound() public {
        publishRootAndResolver();
        registry.revokeResolver(resolver);
        expectRevertHere(
            abi.encodeWithSelector(
                registry.updateResolver.selector,
                resolver,
                objectHash2,
                root,
                uint64(2),
                future(),
                ResolverIdentityRegistryV1.Status.ACTIVE
            )
        );
        expectRevertHere(abi.encodeWithSelector(registry.bindEndpoint.selector, endpoint, resolver));
    }

    function testCannotRevokeLastAdmin() public {
        bytes32 adminRole = registry.DEFAULT_ADMIN_ROLE();
        assertEq(registry.adminCount(), 1);
        expectRevertHere(abi.encodeWithSelector(registry.revokeRole.selector, adminRole, address(this)));

        UnauthorizedCaller secondAdmin = new UnauthorizedCaller(registry);
        registry.grantRole(adminRole, address(secondAdmin));
        assertEq(registry.adminCount(), 2);
        registry.revokeRole(adminRole, address(this));
        assertEq(registry.adminCount(), 1);
        require(!registry.hasRole(adminRole, address(this)), "admin role still assigned");
    }

    function testEndpointBindConflictAndUnbind() public {
        publishRootAndResolver();
        registry.publishResolver(resolver2, objectHash2, root, 1, future(), ResolverIdentityRegistryV1.Status.ACTIVE);
        registry.bindEndpoint(endpoint, resolver);
        assertEq(registry.lookupResolverByEndpoint(endpoint), resolver);
        expectRevertHere(abi.encodeWithSelector(registry.bindEndpoint.selector, endpoint, resolver2));
        registry.unbindEndpoint(endpoint);
        assertEq(registry.lookupResolverByEndpoint(endpoint), bytes32(0));
    }

    function testMissingOrRevokedRootFailsResolverPublish() public {
        expectRevertHere(
            abi.encodeWithSelector(
                registry.publishResolver.selector,
                resolver,
                objectHash,
                root,
                uint64(1),
                future(),
                ResolverIdentityRegistryV1.Status.ACTIVE
            )
        );
        registry.publishRoot(root, 1);
        registry.revokeRoot(root);
        expectRevertHere(
            abi.encodeWithSelector(
                registry.publishResolver.selector,
                resolver,
                objectHash,
                root,
                uint64(1),
                future(),
                ResolverIdentityRegistryV1.Status.ACTIVE
            )
        );
    }

    function testZeroKeyAndHashInputsFail() public {
        registry.publishRoot(root, 1);
        expectRevertHere(abi.encodeWithSelector(registry.publishRoot.selector, bytes32(0), uint64(1)));
        expectRevertHere(
            abi.encodeWithSelector(
                registry.publishResolver.selector,
                bytes32(0),
                objectHash,
                root,
                uint64(1),
                future(),
                ResolverIdentityRegistryV1.Status.ACTIVE
            )
        );
        expectRevertHere(
            abi.encodeWithSelector(
                registry.publishResolver.selector,
                resolver,
                bytes32(0),
                root,
                uint64(1),
                future(),
                ResolverIdentityRegistryV1.Status.ACTIVE
            )
        );
        expectRevertHere(
            abi.encodeWithSelector(
                registry.publishResolver.selector,
                resolver,
                objectHash,
                bytes32(0),
                uint64(1),
                future(),
                ResolverIdentityRegistryV1.Status.ACTIVE
            )
        );
        expectRevertHere(abi.encodeWithSelector(registry.bindEndpoint.selector, bytes32(0), resolver));
    }

    function testExpectedEventsExecute() public {
        registry.publishRoot(root, 1);
        registry.publishResolver(resolver, objectHash, root, 1, future(), ResolverIdentityRegistryV1.Status.ACTIVE);
        registry.updateResolver(resolver, objectHash2, root, 2, future(), ResolverIdentityRegistryV1.Status.ACTIVE);
        registry.bindEndpoint(endpoint, resolver);
        registry.unbindEndpoint(endpoint);
        registry.revokeResolver(resolver);
        registry.revokeRoot(root);
    }

    function publishRootAndResolver() internal {
        registry.publishRoot(root, 1);
        registry.publishResolver(resolver, objectHash, root, 1, future(), ResolverIdentityRegistryV1.Status.ACTIVE);
    }

    function future() internal view returns (uint64) {
        return uint64(block.timestamp + 365 days);
    }

    function expectRevertHere(bytes memory data) internal {
        (bool ok,) = address(registry).call(data);
        require(!ok, "expected revert");
    }

    function expectRevert(address target, bytes memory data) internal {
        (bool ok,) = target.call(data);
        require(!ok, "expected revert");
    }

    function assertEq(bytes32 a, bytes32 b) internal pure {
        require(a == b, "bytes32 not equal");
    }

    function assertEq(uint256 a, uint256 b) internal pure {
        require(a == b, "uint not equal");
    }
}

contract UnauthorizedCaller {
    ResolverIdentityRegistryV1 registry;

    constructor(ResolverIdentityRegistryV1 _registry) {
        registry = _registry;
    }

    function publishRoot(bytes32 stateRoot, uint64 version) external {
        registry.publishRoot(stateRoot, version);
    }
}
