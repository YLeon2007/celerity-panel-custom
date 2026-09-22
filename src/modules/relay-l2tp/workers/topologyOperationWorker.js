'use strict';

const {
    projectCanonicalXrayCandidate,
} = require('../services/topologyXrayCandidate');

const EXECUTOR_METHODS = Object.freeze([
    'prepare',
    'commit',
    'verify',
    'cleanupPrepared',
    'rollback',
]);
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

function validNodeRef(role, nodeRef) {
    if (role === 'relay') return /^relay-[1-9][0-9]*$/.test(nodeRef);
    return nodeRef === role;
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
    if (!SAFE_ID_PATTERN.test(node)
        || metadata?.state !== 'pending'
        || metadata?.backupId !== ''
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
        || operation.status !== 'preparing'
        || !Number.isSafeInteger(operation.topologyRevision)
        || operation.topologyRevision < 0
        || !Number.isSafeInteger(operation.priorDeployedRevision)
        || operation.priorDeployedRevision < 0
        || !Array.isArray(operation.nodes)
        || operation.nodes.length === 0) {
        throw new TypeError('Invalid durable topology operation');
    }
    const nodes = operation.nodes.map(durableNodePlan)
        .sort((left, right) => left.node.localeCompare(right.node));
    if (new Set(nodes.map(node => node.node)).size !== nodes.length) {
        throw new TypeError('Invalid durable topology operation');
    }
    return deepFreeze({
        operationId,
        topologyRevision: operation.topologyRevision,
        priorDeployedRevision: operation.priorDeployedRevision,
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
    const nodes = [...plan.nodes].sort((left, right) => (
        entityId(left?.node).localeCompare(entityId(right?.node))
    ));
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
    constructor({
        operationRepository,
        executor,
        deploymentRepository,
        workerId,
        leaseMs,
        clock,
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
        if (!deploymentRepository
            || typeof deploymentRepository.markDeployed !== 'function') {
            throw new TypeError('Topology operation worker requires deployedRevision CAS finalization');
        }
        if (typeof workerId !== 'string' || workerId.length === 0
            || !Number.isSafeInteger(leaseMs) || leaseMs < 1
            || typeof clock?.now !== 'function') {
            throw new TypeError('Topology operation worker requires lease identity and clock');
        }
        this.operationRepository = operationRepository;
        this.executor = executor;
        this.deploymentRepository = deploymentRepository;
        this.workerId = workerId;
        this.leaseMs = leaseMs;
        this.clock = clock;
        this.running = new Set();
    }

    async renew(operationId) {
        const renewed = await this.operationRepository.renewLease({
            operationId,
            owner: this.workerId,
            leaseMs: this.leaseMs,
            now: this.clock.now(),
        });
        if (renewed !== true) throw new LeaseLostError();
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

    async cleanupAfterPrepareFailure(plan, operationId, prepared) {
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
                const cleaned = await this.executor.cleanupPrepared(
                    this.context(plan, entry.node, entry.prepared, entry.backupId),
                );
                if (cleaned?.ok !== true) {
                    throw new Error('Topology prepared-node cleanup was rejected');
                }
            } catch {
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
        return { claimed: true, operationId, status };
    }

    async rollbackAfterCommitFailure(plan, operationId, prepared, changing) {
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
                const rolledBack = await this.executor.rollback(
                    this.context(plan, entry.node, entry.prepared, entry.backupId),
                );
                if (rolledBack?.ok !== true) {
                    throw new Error('Topology node rollback was rejected');
                }
            } catch {
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
                const cleaned = await this.executor.cleanupPrepared(
                    this.context(plan, entry.node, entry.prepared, entry.backupId),
                );
                if (cleaned?.ok !== true) {
                    throw new Error('Topology prepared-node cleanup was rejected');
                }
            } catch {
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

        const status = rollbackFailed ? 'failed' : 'rolled_back';
        const finished = await this.operationRepository.finishClaimed({
            operationId,
            owner: this.workerId,
            now: this.clock.now(),
            status,
        });
        if (finished !== true) throw new LeaseLostError();
        return { claimed: true, operationId, status };
    }

    async run(operationIdentity) {
        const operationId = entityId(operationIdentity);
        if (!SAFE_ID_PATTERN.test(operationId)) {
            throw new TypeError('Topology operation worker requires an operation id');
        }
        if (this.running.has(operationId)) {
            return { claimed: false, operationId };
        }
        this.running.add(operationId);
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
            try {
                plan = durablePlan(operation, operationId);
                nodes = orderedPlanNodes(plan);
            } catch {
                const failed = await this.operationRepository.finishClaimed({
                    operationId,
                    owner: this.workerId,
                    now: this.clock.now(),
                    status: 'failed',
                });
                if (failed !== true) throw new LeaseLostError();
                return { claimed: true, operationId, status: 'failed' };
            }

            const prepared = [];
            try {
                for (const node of nodes) {
                    await this.renew(operationId);
                    const result = await this.executor.prepare(this.context(plan, node));
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
                return this.cleanupAfterPrepareFailure(plan, operationId, prepared);
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
                    committed = await this.executor.commit(
                        this.context(plan, entry.node, entry.prepared, entry.backupId),
                    );
                    if (committed?.ok !== true) {
                        throw new Error('Topology node commit was rejected');
                    }
                } catch (error) {
                    if (error instanceof LeaseLostError) throw error;
                    return this.rollbackAfterCommitFailure(
                        plan,
                        operationId,
                        prepared,
                        changing,
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
                    const verified = await this.executor.verify(
                        this.context(plan, entry.node, entry.prepared, entry.backupId),
                    );
                    if (verified?.ok !== true) {
                        throw new Error('Topology node verification was rejected');
                    }
                } catch (error) {
                    if (error instanceof LeaseLostError) throw error;
                    return this.rollbackAfterCommitFailure(
                        plan,
                        operationId,
                        prepared,
                        changing,
                    );
                }
            }

            await this.renew(operationId);
            let deployed;
            try {
                deployed = await this.deploymentRepository.markDeployed({
                    expectedRevision: plan.topologyRevision,
                    expectedDeployedRevision: plan.priorDeployedRevision,
                });
                if (deployed?.revision !== plan.topologyRevision
                    || deployed?.deployedRevision !== plan.topologyRevision) {
                    throw new Error('Topology deployedRevision CAS was rejected');
                }
            } catch (error) {
                if (error instanceof LeaseLostError) throw error;
                return this.rollbackAfterCommitFailure(
                    plan,
                    operationId,
                    prepared,
                    changing,
                );
            }
            await this.renew(operationId);
            const succeeded = await this.operationRepository.finishClaimed({
                operationId,
                owner: this.workerId,
                now: this.clock.now(),
                status: 'succeeded',
            });
            if (succeeded !== true) throw new LeaseLostError();
            return { claimed: true, operationId, status: 'succeeded' };
        } catch (error) {
            if (error instanceof LeaseLostError) {
                return {
                    claimed: true,
                    operationId,
                    status: 'running',
                    stopped: true,
                    errorCode: error.code,
                };
            }
            throw error;
        } finally {
            this.running.delete(operationId);
        }
    }
}

module.exports = {
    LeaseLostError,
    TopologyOperationWorker,
    isDeepFrozen,
    matchesFrozenMetadata,
    orderedPlanNodes,
};
