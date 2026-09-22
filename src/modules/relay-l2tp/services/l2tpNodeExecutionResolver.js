'use strict';

const NODE_EXECUTION_SELECT = '_id name ip type active cascadeRole ssh.port ssh.username ssh.privateKey ssh.password';

class L2tpNodeExecutionResolverError extends Error {
    constructor() {
        super('Node execution is unavailable');
        this.name = 'L2tpNodeExecutionResolverError';
        this.code = 'NODE_EXECUTION_UNAVAILABLE';
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

class L2tpNodeExecutionResolver {
    #HyNode;
    #NodeSSH;

    constructor({ HyNode, NodeSSH } = {}) {
        if (!HyNode || typeof HyNode.findById !== 'function') {
            throw new TypeError('L2tpNodeExecutionResolver requires HyNode.findById');
        }
        if (typeof NodeSSH !== 'function') {
            throw new TypeError('L2tpNodeExecutionResolver requires NodeSSH');
        }
        this.#HyNode = HyNode;
        this.#NodeSSH = NodeSSH;
    }

    async resolve(nodeId) {
        const node = await this.#HyNode.findById(nodeId)
            .select(NODE_EXECUTION_SELECT)
            .lean();

        if (!node || node.active !== true || node.type !== 'xray' || node.cascadeRole !== 'relay') {
            throw new L2tpNodeExecutionResolverError();
        }

        return new this.#NodeSSH(executionNode(node));
    }
}

module.exports = {
    L2tpNodeExecutionResolver,
    L2tpNodeExecutionResolverError,
    NODE_EXECUTION_SELECT,
};
