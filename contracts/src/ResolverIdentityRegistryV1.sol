// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ResolverIdentityRegistryV1 {
    enum Status {
        UNKNOWN,
        ACTIVE,
        SUSPENDED,
        REVOKED,
        EXPIRED
    }

    struct ResolverAnchor {
        bytes32 resolverIdKey;
        bytes32 objectHash;
        bytes32 stateRoot;
        uint64 objectVersion;
        uint64 validUntil;
        Status status;
    }

    struct RootRecord {
        bytes32 stateRoot;
        Status status;
        uint64 publishedAt;
        uint64 version;
    }

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant ROOT_PUBLISHER_ROLE = keccak256("ROOT_PUBLISHER_ROLE");
    bytes32 public constant RESOLVER_PUBLISHER_ROLE = keccak256("RESOLVER_PUBLISHER_ROLE");
    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");
    bytes32 public constant ENDPOINT_MANAGER_ROLE = keccak256("ENDPOINT_MANAGER_ROLE");

    mapping(bytes32 => mapping(address => bool)) private roles;
    mapping(bytes32 => bytes32) private endpointToResolverIdKey;
    mapping(bytes32 => ResolverAnchor) private resolverAnchors;
    mapping(bytes32 => RootRecord) private rootRecords;
    uint256 public adminCount;

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    event RootPublished(bytes32 indexed stateRoot, uint64 version, uint64 publishedAt, Status status);
    event RootRevoked(bytes32 indexed stateRoot, uint64 version);
    event ResolverPublished(
        bytes32 indexed resolverIdKey,
        bytes32 objectHash,
        bytes32 indexed stateRoot,
        uint64 objectVersion,
        uint64 validUntil,
        Status status
    );
    event ResolverUpdated(
        bytes32 indexed resolverIdKey,
        bytes32 objectHash,
        bytes32 indexed stateRoot,
        uint64 objectVersion,
        uint64 validUntil,
        Status status
    );
    event ResolverRevoked(bytes32 indexed resolverIdKey, uint64 objectVersion, bytes32 indexed stateRoot);
    event EndpointBound(bytes32 indexed endpointKey, bytes32 indexed resolverIdKey);
    event EndpointUnbound(bytes32 indexed endpointKey, bytes32 indexed resolverIdKey);

    modifier onlyRole(bytes32 role) {
        require(hasRole(role, msg.sender), "missing role");
        _;
    }

    constructor(address initialAdmin) {
        require(initialAdmin != address(0), "admin required");
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(ROOT_PUBLISHER_ROLE, initialAdmin);
        _grantRole(RESOLVER_PUBLISHER_ROLE, initialAdmin);
        _grantRole(REVOKER_ROLE, initialAdmin);
        _grantRole(ENDPOINT_MANAGER_ROLE, initialAdmin);
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return roles[role][account];
    }

    function grantRole(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(account != address(0), "account required");
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(roles[role][account], "role not granted");
        if (role == DEFAULT_ADMIN_ROLE) {
            require(adminCount > 1, "last admin required");
            adminCount -= 1;
        }
        roles[role][account] = false;
        emit RoleRevoked(role, account, msg.sender);
    }

    function publishRoot(bytes32 stateRoot, uint64 version) external onlyRole(ROOT_PUBLISHER_ROLE) {
        require(stateRoot != bytes32(0), "root required");
        require(rootRecords[stateRoot].status != Status.REVOKED, "root permanently revoked");
        require(version > rootRecords[stateRoot].version, "version must increase");
        rootRecords[stateRoot] = RootRecord(stateRoot, Status.ACTIVE, uint64(block.timestamp), version);
        emit RootPublished(stateRoot, version, uint64(block.timestamp), Status.ACTIVE);
    }

    function revokeRoot(bytes32 stateRoot) external onlyRole(REVOKER_ROLE) {
        RootRecord storage root = rootRecords[stateRoot];
        require(root.stateRoot != bytes32(0), "missing root");
        root.status = Status.REVOKED;
        emit RootRevoked(stateRoot, root.version);
    }

    function publishResolver(
        bytes32 resolverIdKey,
        bytes32 objectHash,
        bytes32 stateRoot,
        uint64 objectVersion,
        uint64 validUntil,
        Status status
    ) external onlyRole(RESOLVER_PUBLISHER_ROLE) {
        _validateAnchorInput(resolverIdKey, objectHash, stateRoot, objectVersion, validUntil, status);
        ResolverAnchor storage current = resolverAnchors[resolverIdKey];
        require(current.objectVersion == 0, "already exists");
        resolverAnchors[resolverIdKey] =
            ResolverAnchor(resolverIdKey, objectHash, stateRoot, objectVersion, validUntil, status);
        emit ResolverPublished(resolverIdKey, objectHash, stateRoot, objectVersion, validUntil, status);
    }

    function updateResolver(
        bytes32 resolverIdKey,
        bytes32 objectHash,
        bytes32 stateRoot,
        uint64 objectVersion,
        uint64 validUntil,
        Status status
    ) external onlyRole(RESOLVER_PUBLISHER_ROLE) {
        _validateAnchorInput(resolverIdKey, objectHash, stateRoot, objectVersion, validUntil, status);
        ResolverAnchor storage current = resolverAnchors[resolverIdKey];
        require(current.objectVersion != 0, "missing resolver");
        require(current.status != Status.REVOKED, "resolver permanently revoked");
        require(objectVersion > current.objectVersion, "version must increase");
        resolverAnchors[resolverIdKey] =
            ResolverAnchor(resolverIdKey, objectHash, stateRoot, objectVersion, validUntil, status);
        emit ResolverUpdated(resolverIdKey, objectHash, stateRoot, objectVersion, validUntil, status);
    }

    function revokeResolver(bytes32 resolverIdKey) external onlyRole(REVOKER_ROLE) {
        require(resolverIdKey != bytes32(0), "resolver id required");
        ResolverAnchor storage current = resolverAnchors[resolverIdKey];
        require(current.objectVersion != 0, "missing resolver");
        current.status = Status.REVOKED;
        emit ResolverRevoked(resolverIdKey, current.objectVersion, current.stateRoot);
    }

    function bindEndpoint(bytes32 endpointKey, bytes32 resolverIdKey) external onlyRole(ENDPOINT_MANAGER_ROLE) {
        require(endpointKey != bytes32(0), "endpoint required");
        require(resolverIdKey != bytes32(0), "resolver id required");
        ResolverAnchor storage anchor = resolverAnchors[resolverIdKey];
        require(anchor.objectVersion != 0, "missing resolver");
        require(anchor.status == Status.ACTIVE || anchor.status == Status.SUSPENDED, "resolver not bindable");
        require(anchor.validUntil > block.timestamp, "resolver expired");
        bytes32 existing = endpointToResolverIdKey[endpointKey];
        require(existing == bytes32(0) || existing == resolverIdKey, "endpoint conflict");
        endpointToResolverIdKey[endpointKey] = resolverIdKey;
        emit EndpointBound(endpointKey, resolverIdKey);
    }

    function unbindEndpoint(bytes32 endpointKey) external onlyRole(ENDPOINT_MANAGER_ROLE) {
        require(endpointKey != bytes32(0), "endpoint required");
        bytes32 resolverIdKey = endpointToResolverIdKey[endpointKey];
        require(resolverIdKey != bytes32(0), "missing endpoint");
        delete endpointToResolverIdKey[endpointKey];
        emit EndpointUnbound(endpointKey, resolverIdKey);
    }

    function getResolverAnchor(bytes32 resolverIdKey) external view returns (ResolverAnchor memory) {
        return resolverAnchors[resolverIdKey];
    }

    function getRootStatus(bytes32 stateRoot) external view returns (Status) {
        return rootRecords[stateRoot].status;
    }

    function getRootRecord(bytes32 stateRoot) external view returns (RootRecord memory) {
        return rootRecords[stateRoot];
    }

    function lookupResolverByEndpoint(bytes32 endpointKey) external view returns (bytes32) {
        return endpointToResolverIdKey[endpointKey];
    }

    function _validateAnchorInput(
        bytes32 resolverIdKey,
        bytes32 objectHash,
        bytes32 stateRoot,
        uint64 objectVersion,
        uint64 validUntil,
        Status status
    ) internal view {
        require(resolverIdKey != bytes32(0), "resolver id required");
        require(objectHash != bytes32(0), "object hash required");
        require(stateRoot != bytes32(0), "root required");
        require(objectVersion > 0, "version required");
        require(validUntil > block.timestamp, "invalid validUntil");
        require(status == Status.ACTIVE || status == Status.SUSPENDED, "invalid status");
        require(rootRecords[stateRoot].status == Status.ACTIVE, "root not active");
    }

    function _grantRole(bytes32 role, address account) internal {
        if (!roles[role][account]) {
            roles[role][account] = true;
            if (role == DEFAULT_ADMIN_ROLE) {
                adminCount += 1;
            }
            emit RoleGranted(role, account, msg.sender);
        }
    }
}
