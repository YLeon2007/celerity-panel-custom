'use strict';

const {
    projectCanonicalXrayCandidate,
} = require('../services/topologyXrayCandidate');
const { validNodeRef } = require('../services/topologyNodeRef');

function loadLogger() {
    try {
        return require('../../../utils/logger');
    } catch {
        return { error: () => {}, warn: () => {}, info: () => {} };
    }
}
const logger = loadLogger();

const EXECUTOR_METHODS = Object.freeze([
    'prepare',
    'commit',
    'verify',
    'cleanupPrepared',
    'rollback',
]);
const ACTIVE_OPERATION_STATUSES = new Set(['preparing', 'committing', 'rolling_back']);
const DURABLE_NODE_STATES = new Set(['pending', 'prepared', 'committed', 'failed', 'rolled_back']);
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const TARGET_BY_ROLE = Object.freeze({
    portal: Object.freeze({
        targetProfile: 'xray-main',
        serviceUnit: 'xray.service',
        serviceUnitPath: '/etc/systemd/system/xray.service',
        configPath: '/usr/local/etc/xray/config.json',
    }),
    relay: Object.freeze({
        targetProfile: 'xray-bridge',
        serviceUnit: 'xray-bridge.service',
        serviceUnitPath: '/etc/systemd/system/xray-bridge.service',
        configPath: '/usr/local/etc/xray-bridge/config.json',
    }),
    bridge: Object.freeze({
        targetProfile: 'xray-bridge',
        serviceUnit: 'xray-bridge.service',
        serviceUnitPath: '/etc/systemd/system/xray-bridge.service',
        configPath: '/usr/local/etc/xray-bridge/config.json',
    }),
});

class LeaseLostError extends Error {
    constructor() {
        super('Topology operation lease was lost');
        this.name = 'LeaseLostError';
        this.code = 'TOPOLOGY_OPERATION_LEASE_LOST';
    }
}

function entityId(value) {
    const id = value !== null && typeof value === 'object'
        ? value.operationId ?? value._id ?? value.id ?? value.node
        : value;
    return id === null || id === undefined ? '' : String(id);
}

function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
    Object.values(value).forEach(deepFreeze);
    return Object.freeze(value);
}

function hasExactKeys(value, keys) {
    return Boolean(value)
        && typeof value === 'object'
        && !Array.isArray(value)
        && JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys);
}

function validChecks(checks, target) {
    return Array.isArray(checks) && checks.every(check => {
        if (check?.type === 'service') {
            return hasExactKeys(check, ['expectedState', 'serviceUnit', 'type'])
                && check.serviceUnit === target.serviceUnit
                && check.expectedState === 'active';
        }
        if (check?.type === 'port') {
            return hasExactKeys(check, ['expectedState', 'port', 'protocol', 'type'])
                && check.protocol === 'tcp'
                && Number.isSafeInteger(check.port)
                && check.port >= 1
                && check.port <= 65535
                && check.expectedState === 'listening';
        }
        return false;
    });
}

function durableNodePlan(metadata) {
    const node = entityId(metadata?.node);
    const target = TARGET_BY_ROLE[metadata?.role];
    const state = metadata?.state;
    const backupId = metadata?.backupId;
    if (!SAFE_ID_PATTERN.test(node)
        || !DURABLE_NODE_STATES.has(state)
        || typeof backupId !== 'string'
        || (state === 'pending' ? backupId !== '' : !SAFE_ID_PATTERN.test(backupId))
        || !target
        || !validNodeRef(metadata.role, metadata.nodeRef)
        || metadata.targetProfile !== target.targetProfile
        || !validChecks(metadata.checks, target)) {
        throw new TypeError('Invalid durable topology candidate');
    }

    let candidate;
    try {
        candidate = projectCanonicalXrayCandidate(
            metadata.candidate,
            metadata.candidateHash,
        ).candidate;
    } catch {
        throw new TypeError('Invalid durable topology candidate');
    }

    return {
        node,
        nodeRef: metadata.nodeRef,
        role: metadata.role,
        ...target,
        candidate,
        candidateHash: metadata.candidateHash,
        checks: metadata.checks.map(check => ({ ...check })),
    };
}

function durablePlan(operation, operationId) {
    if (!operation
        || entityId(operation) !== operationId
        || !ACTIVE_OPERATION_STATUSES.has(operation.status)
        || !Number.isSafeInteger(operation.topologyRevision)
        || operation.topologyRevision < 0
        || !Number.isSafeInteger(operation.priorDeployedRevision)
        || operation.priorDeployedRevision < 0
        || !Array.isArray(operation.nodes)
        || operation.nodes.length === 0) {
        throw new TypeError('Invalid durable topology operation');
    }
    const nodes = operation.nodes.map(durableNodePlan);
    if (new Set(nodes.map(node => node.node)).size !== nodes.length) {
        throw new TypeError('Invalid durable topology operation');
    }
    if (operation.kind === 'link.attach'
        && (!SAFE_ID_PATTERN.test(operation.groupId)
            || !SAFE_ID_PATTERN.test(operation.pathKey)
            || !SAFE_ID_PATTERN.test(operation.ownerNodeId)
            || nodes.filter(node => node.node === operation.ownerNodeId && node.role === 'relay').length !== 1)) {
        throw new TypeError('Invalid durable attach identity');
    }
    return deepFreeze({
        operationId,
        topologyRevision: operation.topologyRevision,
        priorDeployedRevision: operation.priorDeployedRevision,
        ...(operation.kind === 'link.attach' ? {
            kind: 'link.attach',
            groupId: operation.groupId,
            pathKey: operation.pathKey,
            ownerNodeId: operation.ownerNodeId,
        } : {}),
        // Only the durable scoped link.apply identity can authorize a PPP skip.
        ...(operation.kind === 'link.apply' && operation.staged === true ? { staged: true } : {}),
        nodes,
    });
}

function isDeepFrozen(value) {
    if (!value || typeof value !== 'object') return true;
    if (!Object.isFrozen(value)) return false;
    return Object.values(value).every(isDeepFrozen);
}

function orderedPlanNodes(plan) {
    if (!isDeepFrozen(plan)) {
        throw new TypeError('Topology operation worker requires an already-frozen plan');
    }
    if (!plan || typeof plan !== 'object'
        || entityId(plan.operationId) === ''
        || !Number.isSafeInteger(plan.topologyRevision)
        || plan.topologyRevision < 0
        || !Number.isSafeInteger(plan.priorDeployedRevision)
        || plan.priorDeployedRevision < 0
        || !Array.isArray(plan.nodes)
        || plan.nodes.length === 0) {
        throw new TypeError('Topology operation worker received an invalid frozen plan');
    }
    const nodes = [...plan.nodes];
    const ids = nodes.map(node => entityId(node?.node));
    if (ids.some(id => id === '') || new Set(ids).size !== ids.length
        || nodes.some(node => typeof node.candidateHash !== 'string'
            || node.candidateHash.length === 0)) {
        throw new TypeError('Topology operation worker received invalid frozen nodes');
    }
    return nodes;
}

function matchesFrozenMetadata(operation, plan, nodes) {
    if (!operation
        || Number(operation.topologyRevision) !== plan.topologyRevision
        || Number(operation.priorDeployedRevision) !== plan.priorDeployedRevision
        || !Array.isArray(operation.nodes)
        || operation.nodes.length !== nodes.length) {
        return false;
    }
    return operation.nodes.every((metadata, index) => (
        entityId(metadata.node) === entityId(nodes[index].node)
        && metadata.candidateHash === nodes[index].candidateHash
    ));
}

class TopologyOperationWorker {
    #allowUnprovenTestExecution;

    constructor({
        operationRepository,
        executor,
        finalizer,
        lockService,
        workerId,
        leaseMs,
        clock,
        timer = globalThis,
        renewalIntervalMs,
        userResync,
        pppReadinessGate,
        pppResumeReadinessGate,
        pppDriftSync,
        attachIngressGate,
        allowUnprovenTestExecution = false,
    } = {}) {
        const repositoryMethods = [
            'claim',
            'renewLease',
            'recordNode',
            'setPhase',
            'finishClaimed',
        ];
        if (!operationRepository
            || repositoryMethods.some(method => typeof operationRepository[method] !== 'function')) {
            throw new TypeError('Topology operation worker requires a fenced operation repository');
        }
        if (!executor || EXECUTOR_METHODS.some(method => typeof executor[method] !== 'function')) {
            throw new TypeError('Topology operation worker requires a typed executor');
        }
        if (!finalizer || typeof finalizer.finalizeSucceeded !== 'function') {
            throw new TypeError('Topology operation worker requires atomic terminal finalization');
        }
        if (!lockService
            || ['acquire', 'renew', 'release'].some(method => (
                typeof lockService[method] !== 'function'
            ))) {
            throw new TypeError('Topology operation worker requires node operation locks');
        }
        if (typeof workerId !== 'string' || workerId.length === 0
            || !Number.isSafeInteger(leaseMs) || leaseMs < 2
            || typeof clock?.now !== 'function'
            || typeof timer?.setInterval !== 'function'
            || typeof timer?.clearInterval !== 'function'
            || (renewalIntervalMs !== undefined
                && (!Number.isSafeInteger(renewalIntervalMs)
                    || renewalIntervalMs < 1
                    || renewalIntervalMs >= leaseMs))) {
            throw new TypeError('Topology operation worker requires lease identity and clock');
        }
        this.operationRepository = operationRepository;
        this.executor = executor;
        this.finalizer = finalizer;
        this.lockService = lockService;
        this.workerId = workerId;
        this.leaseMs = leaseMs;
        this.clock = clock;
        Object.defineProperty(this, 'timer', {
            value: timer,
            enumerable: false,
        });
        this.renewalIntervalMs = renewalIntervalMs
            ?? Math.max(1, Math.floor(leaseMs / 3));
        if (userResync !== undefined
            && (!userResync || typeof userResync.resyncPlan !== 'function')) {
            throw new TypeError('Topology operation worker user resync requires resyncPlan');
        }
        this.userResync = userResync;
        if (pppReadinessGate !== undefined
            && typeof pppReadinessGate?.verifyPlan !== 'function') {
            throw new TypeError('Topology operation worker PPP gate requires verifyPlan');
        }
        this.pppReadinessGate = pppReadinessGate;
        if (pppResumeReadinessGate !== undefined
            && (pppResumeReadinessGate === pppReadinessGate
                || pppResumeReadinessGate?.readOnly !== true
                || typeof pppResumeReadinessGate.verifyPlan !== 'function')) {
            throw new TypeError('Topology PPP resume requires a separate read-only gate');
        }
        this.pppResumeReadinessGate = pppResumeReadinessGate;
        if (pppDriftSync !== undefined && typeof pppDriftSync?.enqueue !== 'function') {
            throw new TypeError('Topology PPP drift sync requires enqueue');
        }
        this.pppDriftSync = pppDriftSync;
        if (attachIngressGate !== undefined
            && typeof attachIngressGate?.verifyPlan !== 'function') {
            throw new TypeError('Topology attach ingress gate requires verifyPlan');
        }
        this.attachIngressGate = attachIngressGate;
        // TEST-only fake-executor seam. The composed runtime never grants this:
        // lock generation and quiescence are not proven for real execution.
        this.#allowUnprovenTestExecution = allowUnprovenTestExecution === true;
        this.running = new Set();
    }

    async renew(operationId) {
        const now = this.clock.now();
        const leaseUntil = new Date(now.getTime() + this.leaseMs);
        const renewed = await this.operationRepository.renewLease({
            operationId,
            owner: this.workerId,
            leaseMs: this.leaseMs,
            now,
        });
        if (renewed !== true) throw new LeaseLostError();
        return leaseUntil;
    }

    async renewLocks(operationId, lockedNodes) {
        for (const { node, generation } of lockedNodes) {
            const renewed = await this.lockService.renew({
                node,
                owner: this.workerId,
                operationId,
                generation,
                leaseMs: this.leaseMs,
            });
            if (renewed?.ok !== true) throw new LeaseLostError();
        }
    }

    createLeaseHeartbeat(operationId, lockedNodeIds) {
        let intervalId;
        let inFlight = null;
        let renewalError = null;
        let stopped = false;

        const clear = () => {
            if (intervalId === undefined) return;
            this.timer.clearInterval(intervalId);
            intervalId = undefined;
        };
        const tick = () => {
            if (stopped || renewalError) return inFlight || Promise.resolve();
            if (inFlight) return inFlight;
            inFlight = this.renew(operationId)
                .then(leaseUntil => this.renewLocks(operationId, lockedNodeIds)
                    .then(() => leaseUntil))
                .catch(error => {
                    renewalError = error instanceof LeaseLostError
                        ? error
                        : new LeaseLostError();
                    clear();
                })
                .finally(() => {
                    inFlight = null;
                });
            return inFlight;
        };
        const assertOwned = () => {
            if (renewalError) throw renewalError;
        };
        const renewOwned = async () => {
            const leaseUntil = await tick();
            assertOwned();
            return leaseUntil;
        };

        intervalId = this.timer.setInterval(tick, this.renewalIntervalMs);
        return {
            run: async work => {
                await renewOwned();
                let result;
                let workError;
                try {
                    result = await work();
                } catch (error) {
                    workError = error;
                }
                await renewOwned();
                if (workError) throw workError;
                return result;
            },
            renew: renewOwned,
            stop: async () => {
                stopped = true;
                clear();
                if (inFlight) await inFlight;
            },
        };
    }

    async acquireLocks(operationId, nodes, acquiredNodeIds) {
        const nodeIds = nodes
            .map(node => entityId(node.node))
            .sort((left, right) => left.localeCompare(right));
        for (const nodeId of nodeIds) {
            let acquired;
            try {
                acquired = await this.lockService.acquire({
                    node: nodeId,
                    owner: this.workerId,
                    operationId,
                    leaseMs: this.leaseMs,
                });
            } catch {
                return 'NODE_LOCK_UNAVAILABLE';
            }
            if (acquired?.ok !== true) {
                return acquired?.error?.code || 'NODE_LOCK_UNAVAILABLE';
            }
            if (typeof acquired.lock?.generation !== 'string' || !acquired.lock.generation) {
                return 'NODE_OPERATION_LOCK_LOST';
            }
            acquiredNodeIds.push({ node: nodeId, generation: acquired.lock.generation });
        }
        return null;
    }

    async releaseVerifiedLocks(operationId, acquiredNodeIds) {
        let released = true;
        for (const { node, generation } of [...acquiredNodeIds].reverse()) {
            try {
                const result = await this.lockService.releaseVerified({
                    node,
                    owner: this.workerId,
                    operationId,
                    generation,
                });
                if (result?.ok !== true) released = false;
            } catch {
                released = false;
            }
        }
        return released;
    }

    async releaseRollbackFence(plan, operationId, status, acquiredNodeIds) {
        if (status !== 'rolled_back'
            || typeof this.finalizer.finalizeRolledBack !== 'function'
            || !Array.isArray(acquiredNodeIds)) {
            return false;
        }
        const locksReleased = await this.releaseVerifiedLocks(operationId, acquiredNodeIds);
        if (!locksReleased || typeof this.finalizer.finalizeRolledBack !== 'function') {
            logger.warn?.(`[TopologyWorker] rollback fence remains held for operation ${operationId}`);
            return false;
        }
        try {
            const released = await this.finalizer.finalizeRolledBack({
                operationId,
                topologyRevision: plan.topologyRevision,
                priorDeployedRevision: plan.priorDeployedRevision,
            });
            if (!released) {
                logger.warn?.(`[TopologyWorker] rollback admission release was rejected for operation ${operationId}`);
                return false;
            }
            acquiredNodeIds.length = 0;
            return true;
        } catch {
            logger.warn?.(`[TopologyWorker] rollback admission release failed for operation ${operationId}`);
            return false;
        }
    }

    async releasePppWaitLocks(operationId, wait, acquiredNodeIds) {
        if (!Array.isArray(wait?.locks) || !Array.isArray(wait.releasedNodes)
            || typeof wait.lockOwner !== 'string' || !wait.lockOwner) return false;
        for (const { node, generation } of [...wait.locks].reverse()) {
            if (wait.releasedNodes.includes(node)) continue;
            await this.renew(operationId);
            let released;
            try {
                released = await this.lockService.releaseVerified({
                    node, owner: wait.lockOwner, operationId, generation,
                });
            } catch {
                return false;
            }
            if (released?.ok !== true) {
                // A crash can occur after deletion but before the durable ACK.
                // Only an empty readback proves this generation is gone; never
                // delete a foreign generation or ACK an uncertain lock.
                if (!await this.isNodeLockAbsent(node)) return false;
            }
            const index = acquiredNodeIds.findIndex(lock => lock.node === node
                && lock.generation === generation);
            if (index >= 0) acquiredNodeIds.splice(index, 1);
            const acknowledged = await this.operationRepository.acknowledgePppLockRelease({
                operationId, owner: this.workerId, now: this.clock.now(),
                node, generation, lockOwner: wait.lockOwner,
            });
            if (acknowledged !== true) throw new LeaseLostError();
            wait.releasedNodes.push(node);
        }
        return true;
    }

    async isNodeLockAbsent(node) {
        if (typeof this.lockService.repository?.findByNode !== 'function') return false;
        try {
            return await this.lockService.repository.findByNode(node) === null;
        } catch {
            return false;
        }
    }

    async releasePppProbeLocks(operationId, wait, acquiredNodeIds) {
        for (const { node, owner, generation } of [...(wait.probeLocks || [])].reverse()) {
            await this.renew(operationId);
            let released;
            try {
                released = await this.lockService.releaseVerified({
                    node, owner, operationId, generation,
                });
            } catch {
                return false;
            }
            if (released?.ok !== true && !await this.isNodeLockAbsent(node)) return false;
            const index = acquiredNodeIds.findIndex(lock => lock.node === node
                && lock.generation === generation);
            if (index >= 0) acquiredNodeIds.splice(index, 1);
            const acknowledged = await this.operationRepository.acknowledgePppProbeLockRelease({
                operationId, owner: this.workerId, now: this.clock.now(),
                node, lockOwner: owner, generation,
            });
            if (acknowledged !== true) throw new LeaseLostError();
            wait.probeLocks = wait.probeLocks.filter(lock => lock.node !== node
                || lock.generation !== generation);
        }
        return true;
    }

    async releaseOrphanProbeLocks(operationId, wait) {
        const read = this.lockService.repository?.findByNode;
        if (typeof read !== 'function') return true; // Exact recorded generations remain recoverable.
        for (const { node } of wait.locks) {
            let current;
            try {
                current = await read.call(this.lockService.repository, node);
            } catch {
                return false;
            }
            if (!current || String(current.operationId) !== operationId) continue;
            if (wait.probeLocks?.some(lock => lock.node === node
                && lock.generation === current.generation)) return false;
            // All original generations have been released. An unrecorded
            // generation from this operation can only be a read-only probe.
            if (wait.locks.some(lock => lock.node === node
                && lock.generation === current.generation)) return false;
            let released;
            try {
                released = await this.lockService.releaseVerified({
                    node, owner: current.owner, operationId, generation: current.generation,
                });
            } catch {
                return false;
            }
            if (released?.ok !== true && !await this.isNodeLockAbsent(node)) return false;
        }
        return true;
    }

    async acquirePppProbeLocks(operationId, nodes, wait, acquiredNodeIds) {
        const ids = nodes.map(node => node.node).sort((a, b) => a.localeCompare(b));
        for (const node of ids) {
            let acquired;
            try {
                acquired = await this.lockService.acquire({
                    node, owner: this.workerId, operationId, leaseMs: this.leaseMs,
                });
            } catch {
                return false;
            }
            if (acquired?.ok !== true || typeof acquired.lock?.generation !== 'string'
                || !acquired.lock.generation) return false;
            const generation = acquired.lock.generation;
            acquiredNodeIds.push({ node, generation });
            const recorded = await this.operationRepository.recordPppProbeLock({
                operationId, owner: this.workerId, now: this.clock.now(), node, generation,
            });
            if (recorded !== true) throw new LeaseLostError();
            wait.probeLocks.push({ node, owner: this.workerId, generation });
        }
        return true;
    }

    async releaseUnrecordedProbeLocks(operationId, wait, acquiredNodeIds) {
        // A persistence failure between acquire and record must not turn into
        // a lost exact generation. Try the known local generation; a crash in
        // this gap is recovered by releaseOrphanProbeLocks on the next claim.
        const recorded = new Set((wait.probeLocks || []).map(lock => `${lock.node}:${lock.generation}`));
        for (const lock of [...acquiredNodeIds].reverse()) {
            if (recorded.has(`${lock.node}:${lock.generation}`)) continue;
            try {
                const released = await this.lockService.releaseVerified({
                    ...lock, owner: this.workerId, operationId,
                });
                if (released?.ok !== true && !await this.isNodeLockAbsent(lock.node)) continue;
                acquiredNodeIds.splice(acquiredNodeIds.indexOf(lock), 1);
            } catch {
                // Recovery reads the inserted lock's exact generation.
            }
        }
    }

    async resumePppWait(plan, operation, operationId, nodes, heartbeat, acquiredNodeIds) {
        const waiting = () => ({ claimed: true, operationId, status: 'awaiting_ppp' });
        const wait = operation.pppWait;
        if (operation.status !== 'committing' || operation.heldTopologyAdmission !== true
            || !wait || typeof wait.relayNode !== 'string'
            || !nodes.some(node => node.role === 'relay' && node.node === wait.relayNode)
            || !this.pppResumeReadinessGate || !this.pppDriftSync) return waiting();
        // Recover a crash between exact-generation release and acknowledgement
        // before attempting a new read-only probe. Never call a bootstrap gate.
        if (!await this.releasePppWaitLocks(operationId, wait, acquiredNodeIds)) return waiting();
        if (!await this.releasePppProbeLocks(operationId, wait, acquiredNodeIds)) return waiting();
        if (!await this.releaseOrphanProbeLocks(operationId, wait)) return waiting();
        if (typeof this.operationRepository.recordPppProbeLock !== 'function'
            || typeof this.operationRepository.acknowledgePppProbeLockRelease !== 'function') {
            return waiting();
        }
        wait.probeLocks ||= [];
        const lockError = await this.acquirePppProbeLocks(operationId, nodes, wait, acquiredNodeIds);
        if (!lockError) {
            await heartbeat.stop();
            await this.releaseUnrecordedProbeLocks(operationId, wait, acquiredNodeIds);
            await this.releasePppProbeLocks(operationId, wait, acquiredNodeIds);
            return waiting();
        }
        let readiness;
        try {
            readiness = await heartbeat.run(() => this.pppResumeReadinessGate.verifyPlan(plan));
        } catch (error) {
            if (error instanceof LeaseLostError) throw error;
            await heartbeat.stop();
            await this.releasePppProbeLocks(operationId, wait, acquiredNodeIds);
            return waiting();
        }
        // No read-only probe or remote mutation remains in flight. Stop lock
        // renewal before releasing generations; keep the operation lease fresh
        // with explicit fenced renewals during release/finalization.
        await heartbeat.stop();
        if (readiness?.ok === true) {
            const proof = readiness.relayRevisions;
            const relayIds = nodes.filter(node => node.role === 'relay').map(node => node.node);
            if (Array.isArray(proof) && proof.length > 0 && proof.length <= relayIds.length
                && proof.some(item => item.relayNode === wait.relayNode)
                && new Set(proof.map(item => item.relayNode)).size === proof.length
                && proof.every(item => relayIds.includes(item.relayNode)
                    && Number.isSafeInteger(item.credentialRevision)
                    && item.credentialRevision > 0)) {
                if (!await this.releasePppProbeLocks(operationId, wait, acquiredNodeIds)) return waiting();
                const leaseUntil = await this.renew(operationId);
                try {
                    const finalized = await this.finalizer.finalizeSucceeded({
                        operationId, owner: this.workerId, leaseUntil,
                        topologyRevision: plan.topologyRevision,
                        priorDeployedRevision: plan.priorDeployedRevision,
                        pppProof: proof,
                    });
                    if (finalized) return { claimed: true, operationId, status: 'succeeded' };
                } catch (error) {
                    if (error instanceof LeaseLostError
                        || error?.code === 'TOPOLOGY_OPERATION_LEASE_LOST') throw new LeaseLostError();
                    // Transaction rejection is not permission to roll back a
                    // completed topology; retry a fresh read-only proof later.
                }
            }
            await this.releasePppProbeLocks(operationId, wait, acquiredNodeIds);
            return waiting();
        }
        let releasedDuringDrift = false;
        if (readiness?.reason === 'PPP_DRIFT'
            && readiness.relayNode === wait.relayNode
            && Number.isSafeInteger(readiness.credentialRevision)
            && readiness.credentialRevision > 0) {
            // Release the entire read-only lock set before queueing sync_users.
            const released = await this.releasePppProbeLocks(operationId, wait, acquiredNodeIds);
            releasedDuringDrift = true;
            if (released) {
                try {
                    await this.pppDriftSync.enqueue({
                        relayNode: readiness.relayNode, now: this.clock.now(),
                    });
                } catch {
                    // The durable wait remains claimable for a bounded retry.
                }
            }
        }
        if (!releasedDuringDrift) {
            await this.releasePppProbeLocks(operationId, wait, acquiredNodeIds);
        }
        return waiting();
    }

    context(plan, node, prepared, backupId) {
        return {
            operationId: entityId(plan.operationId),
            topologyRevision: plan.topologyRevision,
            priorDeployedRevision: plan.priorDeployedRevision,
            node,
            ...(prepared === undefined ? {} : { prepared }),
            ...(backupId === undefined ? {} : { backupId }),
        };
    }

    durableEntries(operation, nodes) {
        const metadataByNode = new Map(
            operation.nodes.map(metadata => [entityId(metadata.node), metadata]),
        );
        return nodes.map(node => {
            const metadata = metadataByNode.get(entityId(node.node));
            if (!metadata || metadata.candidateHash !== node.candidateHash) {
                throw new TypeError('Durable topology metadata does not match the frozen plan');
            }
            return {
                node,
                state: metadata.state,
                backupId: metadata.backupId,
            };
        });
    }

    async invokeDurableNode(plan, entry, command, heartbeat) {
        if (typeof this.executor.rehydrate !== 'function') {
            throw new Error('Topology executor cannot rehydrate a durable binding');
        }
        const rehydrated = await this.executor.rehydrate(
            this.context(plan, entry.node, undefined, entry.backupId),
        );
        if (rehydrated?.ok !== true
            || rehydrated.backupId !== entry.backupId
            || !rehydrated.prepared
            || typeof rehydrated.prepared !== 'object'
            || !Object.isFrozen(rehydrated.prepared)) {
            throw new Error('Topology executor rejected durable binding rehydration');
        }
        const result = await this.executor[command](this.context(
            plan,
            entry.node,
            rehydrated.prepared,
            entry.backupId,
        ));
        if (result?.ok !== true) throw new Error('Topology durable node operation was rejected');
        return result;
    }

    async cleanupExpiredPreparation(plan, operationId, entries, heartbeat) {
        let cleanupFailed = false;
        for (const entry of [...entries].reverse()) {
            if (!['prepared', 'committed', 'failed'].includes(entry.state)) continue;
            await this.renew(operationId);
            const command = entry.state === 'prepared' ? 'cleanupPrepared' : 'rollback';
            let state = 'pending';
            try {
                await heartbeat.run(() => this.invokeDurableNode(
                    plan,
                    entry,
                    command,
                    heartbeat,
                ));
            } catch (error) {
                if (error instanceof LeaseLostError) throw error;
                cleanupFailed = true;
                state = 'failed';
            }
            const recorded = await this.operationRepository.recordNode({
                operationId,
                owner: this.workerId,
                now: this.clock.now(),
                node: entry.node.node,
                state,
                ...(state === 'pending' ? { backupId: '' } : {}),
            });
            if (recorded !== true) throw new LeaseLostError();
            entry.state = state;
            if (state === 'pending') entry.backupId = '';
        }
        if (cleanupFailed) {
            const finished = await this.operationRepository.finishClaimed({
                operationId,
                owner: this.workerId,
                now: this.clock.now(),
                status: 'failed',
            });
            if (finished !== true) throw new LeaseLostError();
            return false;
        }
        return true;
    }

    async rollbackDurableOperation(plan, operation, operationId, entries, heartbeat, acquiredNodeIds) {
        if (operation.status === 'committing') {
            const rollingBack = await this.operationRepository.setPhase({
                operationId,
                owner: this.workerId,
                now: this.clock.now(),
                from: 'committing',
                to: 'rolling_back',
            });
            if (rollingBack !== true) throw new LeaseLostError();
        }

        let rollbackFailed = false;
        for (const entry of [...entries].reverse()) {
            if (!['prepared', 'committed', 'failed'].includes(entry.state)) continue;
            await this.renew(operationId);
            let state = 'rolled_back';
            try {
                const command = entry.state === 'prepared' ? 'cleanupPrepared' : 'rollback';
                await heartbeat.run(() => this.invokeDurableNode(
                    plan,
                    entry,
                    command,
                    heartbeat,
                ));
            } catch (error) {
                if (error instanceof LeaseLostError) throw error;
                rollbackFailed = true;
                state = 'failed';
            }
            const recorded = await this.operationRepository.recordNode({
                operationId,
                owner: this.workerId,
                now: this.clock.now(),
                node: entry.node.node,
                state,
            });
            if (recorded !== true) throw new LeaseLostError();
            entry.state = state;
        }

        if (!rollbackFailed && !(await this.restoreUsersAfterRollback(plan, operationId, heartbeat))) {
            rollbackFailed = true;
        }
        const status = rollbackFailed ? 'failed' : 'rolled_back';
        const finished = await this.operationRepository.finishClaimed({
            operationId,
            owner: this.workerId,
            now: this.clock.now(),
            status,
        });
        if (finished !== true) throw new LeaseLostError();
        await this.releaseRollbackFence(plan, operationId, status, acquiredNodeIds);
        return { claimed: true, operationId, status };
    }

    async cleanupAfterPrepareFailure(plan, operationId, prepared, heartbeat, acquiredNodeIds) {
        const rollingBack = await this.operationRepository.setPhase({
            operationId,
            owner: this.workerId,
            now: this.clock.now(),
            from: 'preparing',
            to: 'rolling_back',
        });
        if (rollingBack !== true) throw new LeaseLostError();

        let cleanupFailed = false;
        for (const entry of [...prepared].reverse()) {
            await this.renew(operationId);
            let state = 'rolled_back';
            try {
                const cleaned = await heartbeat.run(() => this.executor.cleanupPrepared(
                    this.context(plan, entry.node, entry.prepared, entry.backupId),
                ));
                if (cleaned?.ok !== true) {
                    throw new Error('Topology prepared-node cleanup was rejected');
                }
            } catch (error) {
                if (error instanceof LeaseLostError) throw error;
                cleanupFailed = true;
                state = 'failed';
            }
            const recorded = await this.operationRepository.recordNode({
                operationId,
                owner: this.workerId,
                now: this.clock.now(),
                node: entry.node.node,
                state,
            });
            if (recorded !== true) throw new LeaseLostError();
        }

        const status = cleanupFailed ? 'failed' : 'rolled_back';
        const finished = await this.operationRepository.finishClaimed({
            operationId,
            owner: this.workerId,
            now: this.clock.now(),
            status,
        });
        if (finished !== true) throw new LeaseLostError();
        await this.releaseRollbackFence(plan, operationId, status, acquiredNodeIds);
        return { claimed: true, operationId, status };
    }


    async restoreUsersAfterRollback(plan, operationId, heartbeat) {
        if (!this.userResync) return true;
        await this.renew(operationId);
        try {
            // Restoring a node config restarts Xray and clears dynamic users
            // again. A successful config rollback alone is not client recovery.
            const result = await heartbeat.run(() => this.userResync.resyncPlan(plan));
            return result?.ok === true;
        } catch (error) {
            if (error instanceof LeaseLostError) throw error;
            logger.warn?.('[TopologyWorker] user restoration after rollback failed');
            return false;
        }
    }

    async rollbackAfterCommitFailure(plan, operationId, prepared, changing, heartbeat, acquiredNodeIds) {
        const rollingBack = await this.operationRepository.setPhase({
            operationId,
            owner: this.workerId,
            now: this.clock.now(),
            from: 'committing',
            to: 'rolling_back',
        });
        if (rollingBack !== true) throw new LeaseLostError();

        let rollbackFailed = false;
        for (const entry of [...changing].reverse()) {
            await this.renew(operationId);
            let state = 'rolled_back';
            try {
                const rolledBack = await heartbeat.run(() => this.executor.rollback(
                    this.context(plan, entry.node, entry.prepared, entry.backupId),
                ));
                if (rolledBack?.ok !== true) {
                    throw new Error('Topology node rollback was rejected');
                }
            } catch (error) {
                if (error instanceof LeaseLostError) throw error;
                rollbackFailed = true;
                state = 'failed';
            }
            const recorded = await this.operationRepository.recordNode({
                operationId,
                owner: this.workerId,
                now: this.clock.now(),
                node: entry.node.node,
                state,
            });
            if (recorded !== true) throw new LeaseLostError();
        }

        const changingIds = new Set(changing.map(entry => entityId(entry.node.node)));
        const untouched = prepared.filter(entry => !changingIds.has(entityId(entry.node.node)));
        for (const entry of [...untouched].reverse()) {
            await this.renew(operationId);
            let state = 'rolled_back';
            try {
                const cleaned = await heartbeat.run(() => this.executor.cleanupPrepared(
                    this.context(plan, entry.node, entry.prepared, entry.backupId),
                ));
                if (cleaned?.ok !== true) {
                    throw new Error('Topology prepared-node cleanup was rejected');
                }
            } catch (error) {
                if (error instanceof LeaseLostError) throw error;
                rollbackFailed = true;
                state = 'failed';
            }
            const recorded = await this.operationRepository.recordNode({
                operationId,
                owner: this.workerId,
                now: this.clock.now(),
                node: entry.node.node,
                state,
            });
            if (recorded !== true) throw new LeaseLostError();
        }

        if (!rollbackFailed && !(await this.restoreUsersAfterRollback(plan, operationId, heartbeat))) {
            rollbackFailed = true;
        }
        const status = rollbackFailed ? 'failed' : 'rolled_back';
        const finished = await this.operationRepository.finishClaimed({
            operationId,
            owner: this.workerId,
            now: this.clock.now(),
            status,
        });
        if (finished !== true) throw new LeaseLostError();
        await this.releaseRollbackFence(plan, operationId, status, acquiredNodeIds);
        return { claimed: true, operationId, status };
    }

    async run(operationIdentity) {
        const operationId = entityId(operationIdentity);
        if (!SAFE_ID_PATTERN.test(operationId)) {
            throw new TypeError('Topology operation worker requires an operation id');
        }
        if (!this.#allowUnprovenTestExecution) {
            return {
                claimed: false,
                operationId,
                stopped: true,
                errorCode: 'TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN',
            };
        }
        if (this.running.has(operationId)) {
            return { claimed: false, operationId };
        }
        this.running.add(operationId);
        let heartbeat;
        let terminalSuccess = false;
        let resumeWait;
        let durablePppWait = false;
        const acquiredNodeIds = [];
        try {
            const operation = await this.operationRepository.claim({
                operationId,
                owner: this.workerId,
                leaseMs: this.leaseMs,
                now: this.clock.now(),
            });
            if (!operation) return { claimed: false, operationId };
            let plan;
            let nodes;
            let entries;
            try {
                plan = durablePlan(operation, operationId);
                nodes = orderedPlanNodes(plan);
                entries = this.durableEntries(operation, nodes);
            } catch {
                if (operation.pppWait) {
                    return { claimed: true, operationId, status: 'awaiting_ppp', stopped: true };
                }
                const failed = await this.operationRepository.finishClaimed({
                    operationId,
                    owner: this.workerId,
                    now: this.clock.now(),
                    status: 'failed',
                });
                if (failed !== true) throw new LeaseLostError();
                return { claimed: true, operationId, status: 'failed' };
            }

            heartbeat = this.createLeaseHeartbeat(operationId, acquiredNodeIds);
            if (operation.pppWait) {
                resumeWait = operation.pppWait;
                return await this.resumePppWait(
                    plan, operation, operationId, nodes, heartbeat, acquiredNodeIds,
                );
            }
            const lockErrorCode = await this.acquireLocks(operationId, nodes, acquiredNodeIds);
            if (lockErrorCode) {
                return {
                    claimed: true,
                    operationId,
                    status: operation.status,
                    stopped: true,
                    errorCode: lockErrorCode,
                };
            }

            if (operation.status === 'committing' || operation.status === 'rolling_back') {
                return await this.rollbackDurableOperation(
                    plan,
                    operation,
                    operationId,
                    entries,
                    heartbeat,
                    acquiredNodeIds,
                );
            }

            if (entries.some(entry => ['prepared', 'committed', 'failed'].includes(entry.state))) {
                const cleaned = await this.cleanupExpiredPreparation(
                    plan,
                    operationId,
                    entries,
                    heartbeat,
                );
                if (!cleaned) return { claimed: true, operationId, status: 'failed' };
            }

            const prepared = [];
            try {
                for (const node of nodes) {
                    await this.renew(operationId);
                    const result = await heartbeat.run(
                        () => this.executor.prepare(this.context(plan, node)),
                    );
                    if (!result || typeof result.backupId !== 'string' || result.backupId.length === 0) {
                        throw new TypeError('Topology executor prepare must return a backup identifier');
                    }
                    const recorded = await this.operationRepository.recordNode({
                        operationId,
                        owner: this.workerId,
                        now: this.clock.now(),
                        node: node.node,
                        state: 'prepared',
                        candidateHash: node.candidateHash,
                        backupId: result.backupId,
                    });
                    if (recorded !== true) throw new LeaseLostError();
                    prepared.push({ node, prepared: result.prepared, backupId: result.backupId });
                }
            } catch (error) {
                if (error instanceof LeaseLostError) throw error;
                logger.error(`[TopologyWorker] prepare failed for operation ${operationId}: ${error?.message || error}${error?.cause ? ` (cause: ${error.cause?.message || error.cause})` : ''}`);
                return await this.cleanupAfterPrepareFailure(
                    plan,
                    operationId,
                    prepared,
                    heartbeat,
                    acquiredNodeIds,
                );
            }

            const committing = await this.operationRepository.setPhase({
                operationId,
                owner: this.workerId,
                now: this.clock.now(),
                from: 'preparing',
                to: 'committing',
            });
            if (committing !== true) throw new LeaseLostError();

            const changing = [];
            for (const entry of prepared) {
                await this.renew(operationId);
                changing.push(entry);
                let committed;
                try {
                    committed = await heartbeat.run(() => this.executor.commit(
                        this.context(plan, entry.node, entry.prepared, entry.backupId),
                    ));
                    if (committed?.ok !== true) {
                        throw new Error('Topology node commit was rejected');
                    }
                } catch (error) {
                    if (error instanceof LeaseLostError) throw error;
                    return await this.rollbackAfterCommitFailure(
                        plan,
                        operationId,
                        prepared,
                        changing,
                        heartbeat,
                        acquiredNodeIds,
                    );
                }
                const recorded = await this.operationRepository.recordNode({
                    operationId,
                    owner: this.workerId,
                    now: this.clock.now(),
                    node: entry.node.node,
                    state: 'committed',
                });
                if (recorded !== true) throw new LeaseLostError();
                await this.renew(operationId);
                try {
                    const verified = await heartbeat.run(() => this.executor.verify(
                        this.context(plan, entry.node, entry.prepared, entry.backupId),
                    ));
                    if (verified?.ok !== true) {
                        throw new Error('Topology node verification was rejected');
                    }
                } catch (error) {
                    if (error instanceof LeaseLostError) throw error;
                    return await this.rollbackAfterCommitFailure(
                        plan,
                        operationId,
                        prepared,
                        changing,
                        heartbeat,
                        acquiredNodeIds,
                    );
                }
            }

            // The candidate restart clears dynamic Xray users. Reconcile and
            // verify them while the operation still owns its node locks and
            // lease, before the atomic topology success transition. A failed
            // user sync must roll back the changed candidate, not report ready.
            if (this.userResync) {
                try {
                    await this.renew(operationId);
                    const resynced = await heartbeat.run(() => this.userResync.resyncPlan(plan));
                    if (resynced?.ok !== true) {
                        throw new Error('Topology user synchronization was not verified');
                    }
                } catch (error) {
                    if (error instanceof LeaseLostError) throw error;
                    return await this.rollbackAfterCommitFailure(
                        plan,
                        operationId,
                        prepared,
                        changing,
                        heartbeat,
                        acquiredNodeIds,
                    );
                }
            }
            if (this.pppReadinessGate) {
                try {
                    await this.renew(operationId);
                    const readiness = await heartbeat.run(() => this.pppReadinessGate.verifyPlan(plan));
                    if (readiness?.ok !== true) {
                        if (readiness?.reason === 'PPP_DRIFT'
                            && operation.heldTopologyAdmission === true
                            && typeof readiness.relayNode === 'string'
                            && nodes.some(node => node.role === 'relay'
                                && node.node === readiness.relayNode)
                            && Number.isSafeInteger(readiness.credentialRevision)
                            && readiness.credentialRevision > 0
                            && this.pppDriftSync
                            && typeof this.operationRepository.beginPppWait === 'function'
                            && typeof this.operationRepository.acknowledgePppLockRelease === 'function') {
                            const locks = acquiredNodeIds.map(lock => ({ ...lock }));
                            const persisted = await this.operationRepository.beginPppWait({
                                operationId, owner: this.workerId, now: this.clock.now(),
                                relayNode: readiness.relayNode,
                                credentialRevision: readiness.credentialRevision, locks,
                            });
                            if (persisted !== true) throw new LeaseLostError();
                            durablePppWait = true;
                            // Do not roll back after the wait is persisted. Only
                            // exact owned generations can be handed to sync_users.
                            await heartbeat.stop();
                            const released = await this.releasePppWaitLocks(operationId, {
                                lockOwner: this.workerId, locks, releasedNodes: [],
                            }, acquiredNodeIds);
                            if (released) {
                                try {
                                    await this.pppDriftSync.enqueue({
                                        relayNode: readiness.relayNode, now: this.clock.now(),
                                    });
                                } catch {
                                    // Durable wait remains for the next claim.
                                }
                            }
                            return { claimed: true, operationId, status: 'awaiting_ppp' };
                        }
                        throw new Error('Topology PPP node readback was not verified');
                    }
                } catch (error) {
                    if (error instanceof LeaseLostError) throw error;
                    if (durablePppWait) {
                        return { claimed: true, operationId, status: 'awaiting_ppp' };
                    }
                    return await this.rollbackAfterCommitFailure(
                        plan, operationId, prepared, changing, heartbeat, acquiredNodeIds,
                    );
                }
            }
            if (plan.kind === 'link.attach') {
                try {
                    if (!this.attachIngressGate) throw new Error('Attach ingress proof unavailable');
                    await this.renew(operationId);
                    const proof = await heartbeat.run(() => this.attachIngressGate.verifyPlan(plan));
                    if (proof?.ok !== true) throw new Error('Attach ingress proof was not verified');
                } catch (error) {
                    if (error instanceof LeaseLostError) throw error;
                    return await this.rollbackAfterCommitFailure(
                        plan, operationId, prepared, changing, heartbeat, acquiredNodeIds,
                    );
                }
            }
            const leaseUntil = await heartbeat.renew();
            try {
                const finalized = await this.finalizer.finalizeSucceeded({
                    operationId,
                    owner: this.workerId,
                    leaseUntil,
                    topologyRevision: plan.topologyRevision,
                    priorDeployedRevision: plan.priorDeployedRevision,
                });
                if (!finalized) throw new Error('Topology operation finalization was rejected');
            } catch (error) {
                if (error instanceof LeaseLostError
                    || error?.code === 'TOPOLOGY_OPERATION_LEASE_LOST') {
                    throw new LeaseLostError();
                }
                return await this.rollbackAfterCommitFailure(
                    plan,
                    operationId,
                    prepared,
                    changing,
                    heartbeat,
                    acquiredNodeIds,
                );
            }
            terminalSuccess = true;
            return { claimed: true, operationId, status: 'succeeded' };
        } catch (error) {
            if (error instanceof LeaseLostError
                || error?.code === 'TOPOLOGY_OPERATION_LEASE_LOST') {
                return {
                    claimed: true,
                    operationId,
                    status: 'running',
                    stopped: true,
                    errorCode: 'TOPOLOGY_OPERATION_LEASE_LOST',
                };
            }
            throw error;
        } finally {
            if (heartbeat) await heartbeat.stop();
            if (resumeWait) await this.releaseUnrecordedProbeLocks(
                operationId, resumeWait, acquiredNodeIds,
            );
            if (terminalSuccess) await this.releaseVerifiedLocks(operationId, acquiredNodeIds);
            this.running.delete(operationId);
        }
    }
}

module.exports = {
    LeaseLostError,
    TopologyOperationWorker,
    durablePlan,
    isDeepFrozen,
    matchesFrozenMetadata,
    orderedPlanNodes,
};
