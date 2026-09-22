'use strict';

const EXECUTION_USER_SELECT = [
    '_id',
    'relayNode',
    'login',
    'ip',
    'enabled',
    'desiredRevision',
    '+passwordEncrypted',
].join(' ');

class L2tpUserExecutionRepository {
    constructor({ model } = {}) {
        if (!model || typeof model.find !== 'function') {
            throw new TypeError('L2tpUser model with find is required');
        }
        this.model = model;
    }

    async findEnabledByRelayNode(nodeId) {
        return this.model.find({ relayNode: nodeId, enabled: true })
            .select(EXECUTION_USER_SELECT)
            .sort({ login: 1, _id: 1 })
            .lean();
    }

    async findByRelayNode(nodeId) {
        return this.model.find({ relayNode: nodeId })
            .select(EXECUTION_USER_SELECT)
            .sort({ login: 1, _id: 1 })
            .lean();
    }
}

module.exports = {
    EXECUTION_USER_SELECT,
    L2tpUserExecutionRepository,
};
