'use strict';

const { AsyncLocalStorage } = require('node:async_hooks');
const { randomUUID } = require('node:crypto');
const { resolveL2tpExecutionAuthorization } = require('../modules/relay-l2tp/domain/l2tpExecutionAuthorization');
const heldWrites = new AsyncLocalStorage();
const failure = code => Object.assign(new Error(code), { code });

// This is only a shared exclusion fence, never topology adoption/handback
// authority. The callback must return true ONLY after checked completion of all
// dispatched effects. A false/unknown result or throw keeps the uncertain row.
async function withClassicNodeConfigWrite({ nodeId, kind, env = process.env, leaseMs = 30000 }, callback) {
    const selectedEnv = Object.freeze({ ...env });
    if (!nodeId || typeof kind !== 'string' || !kind
        || !Number.isSafeInteger(leaseMs) || leaseMs < 1000 || leaseMs > 120000) throw failure('CLASSIC_CONFIG_WRITE_INVALID');
    const key = String(nodeId);
    const parent = heldWrites.getStore();
    const nested = parent?.get(key);
    if (nested && !nested.active) throw failure('CLASSIC_CONFIG_WRITE_SCOPE_CLOSED');
    if (!nested && !resolveL2tpExecutionAuthorization(selectedEnv).enableInstallAdmission) return callback();
    async function run(scope) {
        scope.pending++;
        try {
            await scope.verify?.();
            const result = await callback();
            await scope.verify?.();
            if (result !== true) scope.uncertain = true;
            return result;
        } catch (error) {
            // Only the private phase brand can prove a nested preflight did not
            // dispatch. Public codes/flags and transport assertions are not proof.
            if (!require('./classicPortalBridgePhase').isClassicPortalBridgePreflightError(error)) scope.uncertain = true;
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
    const acquired = await service.acquire({ node: nodeId, owner, operationId, leaseMs });
    if (!acquired?.ok) throw failure('NODE_OPERATION_LOCK_CONFLICT');
    const lock = acquired.lock;
    if (!lock || String(lock.node) !== key || lock.owner !== owner || lock.operationId !== operationId
        || typeof lock.generation !== 'string' || !lock.generation || lock.remoteUncertain !== true) {
        throw failure('CLASSIC_CONFIG_WRITE_LOCK_UNCERTAIN');
    }
    const scope = { active: true, uncertain: false, pending: 0, verify: async () => {
        if (!scope.active) throw failure('CLASSIC_CONFIG_WRITE_SCOPE_CLOSED');
        const row = await service.repository.findByNode(nodeId);
        if (!scope.active || !row || String(row.node) !== key || row.owner !== owner
            || row.operationId !== operationId || row.generation !== lock.generation
            || row.remoteUncertain !== true || !(row.leaseUntil instanceof Date)
            || row.leaseUntil <= service.clock.now()) throw failure('CLASSIC_CONFIG_WRITE_LOCK_UNCERTAIN');
    } };
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

// Internal worker-to-classic bridge. The supplied service is the actual
// already-acquired worker lock service, not a caller-controlled bypass flag.
// Never acquires or releases a generation; the worker owns settlement.
async function withHeldL2tpNodeConfigWrite({ lock: acquiredLock, lockService, clock,
    standaloneAdmission }, callback) {
    const lock = Object.freeze({ node: acquiredLock?.node, owner: acquiredLock?.owner,
        operationId: acquiredLock?.operationId, generation: acquiredLock?.generation });
    const { NodeOperationLockService } = require('../modules/relay-l2tp/services/nodeOperationLockService');
    if (!(lockService instanceof NodeOperationLockService) || !lock?.generation
        || typeof clock?.now !== 'function') throw failure('CLASSIC_CONFIG_WRITE_LOCK_UNCERTAIN');
    const key = String(lock.node);
    // Standalone acquire() intentionally has no operationId/leaseOwner. Bind
    // its exact acquired invocation identity, never fabricate a worker link.
    const admissionId = standaloneAdmission?.id;
    const admissionRepository = standaloneAdmission?.repository;
    if (standaloneAdmission !== undefined) {
        const { RemoteAdmissionRepository } = require('../modules/relay-l2tp/repositories/remoteAdmissionRepository');
        if (!(admissionRepository instanceof RemoteAdmissionRepository)
            || typeof admissionId !== 'string' || !admissionId
            || typeof admissionRepository.RemoteAdmission?.findOne !== 'function'
            || !admissionRepository.RemoteAdmission.db
            || admissionRepository.RemoteAdmission.db !== admissionRepository.CascadeTopologyState.db
            || admissionRepository.RemoteAdmission.db !== lockService.repository.model?.db) {
            throw Object.assign(failure('CLASSIC_CONFIG_WRITE_ADMISSION_UNCERTAIN'), { remoteOutcomeUncertain: true });
        }
    }
    const scope = { active: true, uncertain: false, pending: 0, standaloneAdmissionId: admissionId, verify: async () => {
        if (!scope.active) throw failure('CLASSIC_CONFIG_WRITE_SCOPE_CLOSED');
        if (admissionId !== undefined) {
            const admission = await admissionRepository.RemoteAdmission.findOne({ _id: admissionId })
                .setOptions({ readPreference: 'primary', readConcern: { level: 'majority' }, maxTimeMS: 5000 }).lean()
                .catch(error => { error.remoteOutcomeUncertain = true; throw error; });
            if (!scope.active || !admission || admission._id !== admissionId || admission.nodeId !== key
                || admission.kind !== 'standalone_preflight' || admission.phase !== 'running'
                || admission.ownerGeneration !== 1 || Object.hasOwn(admission, 'operationId')
                || Object.hasOwn(admission, 'leaseOwner')) throw Object.assign(failure('CLASSIC_CONFIG_WRITE_ADMISSION_UNCERTAIN'), { remoteOutcomeUncertain: true });
        }
        const row = await lockService.repository.findByNode(lock.node);
        if (!scope.active || !row || String(row.node) !== key || row.owner !== lock.owner
            || row.operationId !== lock.operationId || row.generation !== lock.generation
            || row.remoteUncertain !== true || !(row.leaseUntil instanceof Date)
            || row.leaseUntil <= clock.now()) throw failure('CLASSIC_CONFIG_WRITE_LOCK_UNCERTAIN');
    } };
    await scope.verify();
    const scopes = new Map(heldWrites.getStore() || []);
    if (scopes.has(key)) throw failure('CLASSIC_CONFIG_WRITE_SCOPE_CONFLICT');
    scopes.set(key, scope);
    let verifyingCompletion = false;
    try {
        return await heldWrites.run(scopes, async () => {
            const result = await callback();
            verifyingCompletion = true;
            await scope.verify();
            if (scope.uncertain || scope.pending !== 0) throw failure('CLASSIC_CONFIG_WRITE_OUTCOME_UNCERTAIN');
            return result;
        });
    } catch (error) {
        // A swallowed/unknown nested classic dispatch cannot authorize release.
        if (verifyingCompletion || scope.uncertain || scope.pending !== 0) error.remoteOutcomeUncertain = true;
        throw error;
    } finally { scope.active = false; }
}

async function assertHeldL2tpNodeConfigWrite(nodeId) {
    const scope = heldWrites.getStore()?.get(String(nodeId));
    if (!scope?.verify || !scope.active) throw failure('CLASSIC_CONFIG_WRITE_SCOPE_CLOSED');
    await scope.verify();
    return Object.freeze({ standaloneAdmissionId: scope.standaloneAdmissionId });
}

async function assertClassicNodeConfigWriteHeld(nodeId) {
    const scope = heldWrites.getStore()?.get(String(nodeId));
    if (scope) {
        if (!scope.active) throw failure('CLASSIC_CONFIG_WRITE_SCOPE_CLOSED');
        await scope.verify?.();
    }
}

// Internal multi-node bridge: use the exact already-acquired service and
// generations. It owns neither acquisition nor release; settlement is outer.
async function withHeldScopedClassicConfigWrites({ locks, lockService, verify }, callback) {
    if (!lockService?.repository || typeof verify !== 'function' || !Array.isArray(locks) || !locks.length) {
        throw failure('CLASSIC_CONFIG_WRITE_LOCK_UNCERTAIN');
    }
    const scopes = new Map(heldWrites.getStore() || []);
    const owned = [];
    for (const lock of locks) {
        const key = String(lock.node);
        if (scopes.has(key)) throw failure('CLASSIC_CONFIG_WRITE_SCOPE_CONFLICT');
        const scope = { active: true, uncertain: false, pending: 0, verify: async () => {
            if (!scope.active) throw failure('CLASSIC_CONFIG_WRITE_SCOPE_CLOSED');
            await verify();
            const row = await lockService.repository.findByNode(lock.node);
            if (!scope.active || !row || String(row.node) !== key || row.owner !== lock.owner
                || row.operationId !== lock.operationId || row.generation !== lock.generation
                || row.remoteUncertain !== true || !(row.leaseUntil instanceof Date)
                || row.leaseUntil <= lockService.clock.now()) throw failure('CLASSIC_CONFIG_WRITE_LOCK_UNCERTAIN');
        } };
        scopes.set(key, scope); owned.push(scope);
    }
    try {
        return await heldWrites.run(scopes, async () => {
            for (const scope of owned) await scope.verify();
            const result = await callback();
            for (const scope of owned) await scope.verify();
            if (owned.some(scope => scope.uncertain || scope.pending !== 0)) throw failure('CLASSIC_CONFIG_WRITE_OUTCOME_UNCERTAIN');
            return result;
        });
    } catch (error) {
        if (owned.some(scope => scope.uncertain || scope.pending !== 0)) error.remoteOutcomeUncertain = true;
        throw error;
    } finally { for (const scope of owned) scope.active = false; }
}

module.exports = { withClassicNodeConfigWrite, withHeldL2tpNodeConfigWrite, withHeldScopedClassicConfigWrites,
    assertHeldL2tpNodeConfigWrite, assertClassicNodeConfigWriteHeld };
