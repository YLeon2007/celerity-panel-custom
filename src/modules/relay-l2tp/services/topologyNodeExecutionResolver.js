'use strict';

const TOPOLOGY_NODE_EXECUTION_SELECT = '_id name ip type active cascadeRole ssh.port ssh.username ssh.privateKey ssh.password';
const TOPOLOGY_TEST_TARGET = 'test';
const TOPOLOGY_TEST_HOST_IDENTITY = 'test.infograd.online';
const TOPOLOGY_EXECUTION_ROLES = new Set(['portal', 'relay', 'bridge']);
const SAFE_NODE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

class TopologyNodeExecutionResolverError extends Error {
    constructor() {
        super('Topology node execution is unavailable');
        this.name = 'TopologyNodeExecutionResolverError';
        this.code = 'TOPOLOGY_NODE_EXECUTION_UNAVAILABLE';
    }
}

function hiddenCredentials(ssh = {}) {
    const credentials = {};
    for (const field of ['port', 'username', 'privateKey', 'password']) {
        Object.defineProperty(credentials, field, {
            value: ssh[field],
            enumerable: false,
            writable: false,
            configurable: false,
        });
    }
    return credentials;
}

function executionNode(node) {
    const projected = {
        _id: node._id,
        name: node.name,
        ip: node.ip,
        type: node.type,
        active: node.active,
        cascadeRole: node.cascadeRole,
    };
    Object.defineProperty(projected, 'ssh', {
        value: hiddenCredentials(node.ssh),
        enumerable: false,
        writable: false,
        configurable: false,
    });
    return projected;
}

function isExactResolutionRequest(request) {
    return Boolean(request)
        && typeof request === 'object'
        && !Array.isArray(request)
        && JSON.stringify(Object.keys(request).sort()) === JSON.stringify(['nodeId', 'role'])
        && typeof request.nodeId === 'string'
        && SAFE_NODE_ID_PATTERN.test(request.nodeId)
        && TOPOLOGY_EXECUTION_ROLES.has(request.role);
}

function hasUsableConnection(node, nodeId, role) {
    const ssh = node?.ssh;
    let persistedNodeId;
    try {
        persistedNodeId = node?._id === undefined || node?._id === null
            ? null
            : String(node._id);
    } catch {
        return false;
    }
    return Boolean(node)
        && persistedNodeId === nodeId
        && node.active === true
        && node.type === 'xray'
        && node.cascadeRole === role
        && typeof node.ip === 'string'
        && node.ip.length > 0
        && ssh !== null
        && typeof ssh === 'object'
        && Number.isSafeInteger(ssh.port)
        && ssh.port >= 1
        && ssh.port <= 65535
        && typeof ssh.username === 'string'
        && ssh.username.length > 0
        && (
            (typeof ssh.privateKey === 'string' && ssh.privateKey.length > 0)
            || (typeof ssh.password === 'string' && ssh.password.length > 0)
        );
}

class TopologyNodeExecutionResolver {
    #HyNode;
    #NodeSSH;
    #target;
    #hostIdentity;

    constructor({ HyNode, NodeSSH, target, hostIdentity } = {}) {
        if (!HyNode || typeof HyNode.findById !== 'function') {
            throw new TypeError('TopologyNodeExecutionResolver requires HyNode.findById');
        }
        if (typeof NodeSSH !== 'function') {
            throw new TypeError('TopologyNodeExecutionResolver requires NodeSSH');
        }
        this.#HyNode = HyNode;
        this.#NodeSSH = NodeSSH;
        this.#target = target;
        this.#hostIdentity = hostIdentity;
    }

    async resolve(request) {
        if (
            this.#target !== TOPOLOGY_TEST_TARGET
            || this.#hostIdentity !== TOPOLOGY_TEST_HOST_IDENTITY
            || !isExactResolutionRequest(request)
        ) {
            throw new TopologyNodeExecutionResolverError();
        }

        let node;
        try {
            node = await this.#HyNode.findById(request.nodeId)
                .select(TOPOLOGY_NODE_EXECUTION_SELECT)
                .lean();
        } catch {
            throw new TopologyNodeExecutionResolverError();
        }
        if (!hasUsableConnection(node, request.nodeId, request.role)) {
            throw new TopologyNodeExecutionResolverError();
        }

        try {
            return new this.#NodeSSH(executionNode(node));
        } catch {
            throw new TopologyNodeExecutionResolverError();
        }
    }
}

module.exports = {
    TOPOLOGY_NODE_EXECUTION_SELECT,
    TOPOLOGY_TEST_HOST_IDENTITY,
    TOPOLOGY_TEST_TARGET,
    TopologyNodeExecutionResolver,
    TopologyNodeExecutionResolverError,
};
