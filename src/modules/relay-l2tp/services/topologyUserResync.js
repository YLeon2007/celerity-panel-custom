'use strict';

// After a topology deploy commits, xray on the node restarts with the
// candidate config, which contains no subscription clients: users live only
// in the xray runtime, added through the node agent HTTP API. Without a
// re-push the freshly deployed chain authenticates nobody and clients see
// TLS/Reality handshake failures. This service re-pushes subscription users
// to every node of a successfully deployed plan via the legacy syncService
// agent path (the same path used when a user is created or updated).

const USER_PUSH_ATTEMPTS = 2;
const USER_PUSH_RETRY_DELAY_MS = 1500;

function defaultLogger() {
    try {
        return require('../../../utils/logger');
    } catch {
        return { info: () => {}, warn: () => {}, error: () => {} };
    }
}

function loadSyncService() {
    // Lazy require: the legacy service pulls in mongoose models and must not
    // be touched at module load time in unit tests.
    return require('../../../services/syncService');
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

class TopologyUserResync {
    constructor({ HyNode, syncService, logger, sleep } = {}) {
        if (!HyNode || typeof HyNode.findById !== 'function') {
            throw new TypeError('TopologyUserResync requires HyNode.findById');
        }
        this.HyNode = HyNode;
        this._syncService = syncService;
        this.logger = logger || defaultLogger();
        this.sleep = typeof sleep === 'function' ? sleep : delay;
    }

    get syncService() {
        if (this._syncService === undefined) {
            this._syncService = loadSyncService();
        }
        return this._syncService;
    }

    planNodeIds(plan) {
        const ids = [];
        for (const entry of plan?.nodes || []) {
            const id = entry?.node;
            if ((typeof id === 'string' || typeof id === 'object') && id !== null) {
                const key = String(id);
                if (key && !ids.includes(key)) {
                    ids.push(key);
                }
            }
        }
        return ids;
    }

    async resyncPlan(plan) {
        if (plan?.kind !== 'deploy') {
            return { nodeCount: 0, userCount: 0 };
        }
        const syncService = this.syncService;
        if (typeof syncService?._getUsersForNode !== 'function'
            || typeof syncService?.addXrayUser !== 'function') {
            return { nodeCount: 0, userCount: 0 };
        }
        let nodeCount = 0;
        let userCount = 0;
        for (const id of this.planNodeIds(plan)) {
            const node = await this.HyNode.findById(id).lean();
            if (!node || node.type !== 'xray') {
                continue;
            }
            nodeCount += 1;
            const users = await syncService._getUsersForNode(node);
            for (const user of users || []) {
                if (await this.pushUser(node, user)) {
                    userCount += 1;
                }
            }
        }
        return { nodeCount, userCount };
    }

    async pushUser(node, user) {
        for (let attempt = 1; attempt <= USER_PUSH_ATTEMPTS; attempt += 1) {
            try {
                const ok = await this.syncService.addXrayUser(node, user);
                if (ok !== false) {
                    return true;
                }
            } catch (error) {
                this.logger.warn(
                    `[Topology] user resync push failed for ${node.name}/${user?.userId || user?.username}: ${error?.message || error}`,
                );
            }
            if (attempt < USER_PUSH_ATTEMPTS) {
                await this.sleep(USER_PUSH_RETRY_DELAY_MS);
            }
        }
        this.logger.warn(`[Topology] user resync gave up on ${node.name}/${user?.userId || user?.username}`);
        return false;
    }
}

module.exports = {
    TopologyUserResync,
    USER_PUSH_ATTEMPTS,
    USER_PUSH_RETRY_DELAY_MS,
};
