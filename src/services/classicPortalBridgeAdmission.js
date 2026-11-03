'use strict';
const { AsyncLocalStorage } = require('node:async_hooks');
const scopes = new AsyncLocalStorage();
const executionContexts = new WeakSet();
const failure = code => Object.assign(new Error(code), { code });
function defaultLockService() {
    const { NodeOperationLockService } = require('../modules/relay-l2tp/services/nodeOperationLockService');
    const { NodeOperationLockRepository } = require('../modules/relay-l2tp/services/nodeOperationLockRepository');
    const model = require('../modules/relay-l2tp/models/nodeOperationLockModel');
    return new NodeOperationLockService({ repository: new NodeOperationLockRepository({ model }), clock: { now: () => new Date() } });
}
function getHeldScopedClassicNodeIds() {
    const scope = scopes.getStore();
    return scope?.active ? [...scope.nodeIds] : [];
}
// Internal capability, not an input flag. A core caller can only consume one
// minted in a currently active exact-node scope; no HTTP object can forge it.
function createScopedClassicExecutionContext({ verify, nodeIds }) {
    const parent = scopes.getStore();
    if (!parent?.active || nodeIds.some(id => !parent.nodeIds.includes(id)) || typeof verify !== 'function') {
        throw failure('CLASSIC_CONFIG_WRITE_SCOPE_CLOSED');
    }
    const context = Object.freeze({ nodeIds: Object.freeze([...nodeIds]), async verify() {
        await parent.verify(); await verify(); await parent.verify();
    } });
    executionContexts.add(context);
    return context;
}
function isScopedClassicExecutionContext(context) { return !!context && executionContexts.has(context); }
async function withScopedClassicNodeLocks({ nodeIds, operationId, leaseMs = 120000, lockService }, work) {
    if (!Array.isArray(nodeIds) || !nodeIds.length || nodeIds.some(id => !/^[a-f0-9]{24}$/i.test(String(id)))
        || typeof operationId !== 'string' || !operationId || typeof work !== 'function'
        || !Number.isSafeInteger(leaseMs) || leaseMs < 1000 || leaseMs > 120000) throw failure('CLASSIC_CONFIG_WRITE_INVALID');
    const ids = [...new Set(nodeIds.map(String))].sort();
    const parent = scopes.getStore();
    if (parent) {
        if (!parent.active) throw failure('CLASSIC_CONFIG_WRITE_SCOPE_CLOSED');
        if (!ids.every(id => parent.nodeIds.includes(id))) throw failure('CLASSIC_CONFIG_WRITE_SCOPE_CONFLICT');
        await parent.verify();
        parent.pending++;
        try { return await work(parent.held); } finally { parent.pending--; }
    }
    const service = lockService ?? defaultLockService();
    const owner = 'classic-portal-bridge';
    const locks = [];
    const scope = { active: true, pending: 0, mutated: false, settled: false, uncertain: false, nodeIds: ids };
    scope.verify = async () => {
        if (!scope.active) throw failure('CLASSIC_CONFIG_WRITE_SCOPE_CLOSED');
        for (const lock of locks) {
            const row = await service.repository.findByNode(lock.node);
            if (!scope.active || !row || String(row.node) !== String(lock.node) || row.owner !== lock.owner
                || row.operationId !== lock.operationId || row.generation !== lock.generation || row.remoteUncertain !== true
                || !(row.leaseUntil instanceof Date) || row.leaseUntil <= service.clock.now()) {
                throw failure('CLASSIC_CONFIG_WRITE_LOCK_UNCERTAIN');
            }
        }
    };
    const held = scope.held = Object.freeze({ nodeIds: Object.freeze(ids), verify: scope.verify,
        async beforeRemoteMutation({ nodeId, phase } = {}) {
            if (!ids.includes(String(nodeId)) || typeof phase !== 'string' || !phase) throw failure('CLASSIC_CONFIG_WRITE_INVALID');
            await scope.verify();
            // Mark BEFORE returning dispatch permission, including staging writes.
            scope.mutated = true; scope.settled = false;
        },
        async settleVerified() { await scope.verify(); scope.settled = true; },
        async runWithHeldConfigWrites(work) {
            await scope.verify(); scope.pending++;
            try {
                const { withHeldScopedClassicConfigWrites } = require('./classicNodeConfigWrite');
                return await withHeldScopedClassicConfigWrites({ locks, lockService: service, verify: scope.verify }, work);
            } catch (error) {
                if (error.remoteOutcomeUncertain === true) scope.uncertain = true;
                throw error;
            } finally { scope.pending--; }
        },
    });
    let result, thrown;
    try {
        for (const node of ids) {
            const acquired = await service.acquire({ node, owner, operationId, leaseMs });
            if (acquired?.ok !== true) throw failure('NODE_OPERATION_LOCK_CONFLICT');
            const lock = acquired.lock;
            if (!lock || String(lock.node) !== node || lock.owner !== owner || lock.operationId !== operationId
                || typeof lock.generation !== 'string' || !lock.generation || lock.remoteUncertain !== true) {
                throw failure('CLASSIC_CONFIG_WRITE_LOCK_UNCERTAIN');
            }
            locks.push(Object.freeze({ node, owner, operationId, generation: lock.generation }));
        }
        await scope.verify();
        result = await scopes.run(scope, () => work(held));
        await scope.verify();
    } catch (error) { thrown = error; }
    // Close before the first awaited release. Captured ALS callbacks cannot
    // acquire/dispatch through a released or borrowed generation.
    scope.active = false;
    if (!scope.uncertain && scope.pending === 0 && (!scope.mutated || scope.settled)) {
        for (const lock of [...locks].reverse()) {
            try {
                if ((await service.releaseVerified(lock))?.ok !== true) throw failure('CLASSIC_CONFIG_WRITE_RELEASE_UNCERTAIN');
            } catch (error) { thrown ??= error; }
        }
    }
    if (thrown) {
        // The outer dispatch ledger overrides even a privately branded error
        // from a different nested phase after a possible effect.
        if (scope.uncertain || (scope.mutated && !scope.settled) || scope.pending !== 0) thrown.remoteOutcomeUncertain = true;
        throw thrown;
    }
    return result;
}
module.exports = { withScopedClassicNodeLocks, getHeldScopedClassicNodeIds,
    createScopedClassicExecutionContext, isScopedClassicExecutionContext };
