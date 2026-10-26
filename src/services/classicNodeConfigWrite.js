'use strict';

const { AsyncLocalStorage } = require('node:async_hooks');
const { randomUUID } = require('node:crypto');
const { resolveL2tpExecutionAuthorization } = require('../modules/relay-l2tp/domain/l2tpExecutionAuthorization');
const heldWrites = new AsyncLocalStorage();
const failure = code => Object.assign(new Error(code), { code });

// This is only a shared exclusion fence, never topology adoption/handback
// authority. The callback must return true ONLY after checked completion of all
// dispatched effects. A false/unknown result or throw keeps the uncertain row.
async function withClassicNodeConfigWrite({ nodeId, kind, env = process.env }, callback) {
    const selectedEnv = Object.freeze({ ...env });
    if (!resolveL2tpExecutionAuthorization(selectedEnv).enableInstallAdmission) return callback();
    if (!nodeId || typeof kind !== 'string' || !kind) throw failure('CLASSIC_CONFIG_WRITE_INVALID');
    const key = String(nodeId);
    const parent = heldWrites.getStore();
    const nested = parent?.get(key);
    if (nested && !nested.active) throw failure('CLASSIC_CONFIG_WRITE_SCOPE_CLOSED');
    async function run(scope) {
        scope.pending++;
        try {
            const result = await callback();
            if (result !== true) scope.uncertain = true;
            return result;
        } catch (error) {
            scope.uncertain = true;
            throw error;
        } finally {
            scope.pending--;
        }
    }
    if (nested) return run(nested);

    // Lazy imports: dormant classic startup must not register optional models
    // or cause additive collection/index DDL.
    const { NodeOperationLockRepository } = require('../modules/relay-l2tp/services/nodeOperationLockRepository');
    const { NodeOperationLockService } = require('../modules/relay-l2tp/services/nodeOperationLockService');
    const model = require('../modules/relay-l2tp/models/nodeOperationLockModel');
    const service = new NodeOperationLockService({ repository: new NodeOperationLockRepository({ model }),
        clock: { now: () => new Date() } });
    const owner = 'classic-config-writer';
    const operationId = `classic:${kind}:${randomUUID()}`;
    const acquired = await service.acquire({ node: nodeId, owner, operationId, leaseMs: 30000 });
    if (!acquired?.ok) throw failure('NODE_OPERATION_LOCK_CONFLICT');
    const lock = acquired.lock;
    if (!lock || String(lock.node) !== key || lock.owner !== owner || lock.operationId !== operationId
        || typeof lock.generation !== 'string' || !lock.generation || lock.remoteUncertain !== true) {
        throw failure('CLASSIC_CONFIG_WRITE_LOCK_UNCERTAIN');
    }
    const scope = { active: true, uncertain: false, pending: 0 };
    const scopes = new Map(parent || []);
    scopes.set(key, scope);
    try {
        return await heldWrites.run(scopes, async () => {
            // Re-read durable veto under exclusion, before generation or any
            // remote read. A pre-lock ownership check alone is not sufficient.
            const { topologyManagesNodeConfig } = require('./topologyConfigOwnership');
            if (await topologyManagesNodeConfig({ _id: nodeId }, selectedEnv)) {
                throw failure('CLASSIC_CONFIG_WRITE_OWNER_VETO');
            }
            const result = await run(scope);
            scope.active = false; // No new nested dispatch while exact release awaits.
            if (result === true && !scope.uncertain && scope.pending === 0) {
                const released = await service.releaseVerified({ node: nodeId, owner, operationId, generation: lock.generation });
                if (!released?.ok) throw failure('CLASSIC_CONFIG_WRITE_RELEASE_UNCERTAIN');
            }
            return result;
        });
    } finally {
        scope.active = false;
    }
}

module.exports = { withClassicNodeConfigWrite };
