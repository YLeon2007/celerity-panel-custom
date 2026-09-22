'use strict';

const { randomUUID } = require('node:crypto');
const { compileTopology } = require('../domain/topologyCompiler');
const {
    projectGroups,
    projectLinks,
    projectNodes,
} = require('../domain/topologyDraft');
const { validateTopology } = require('../domain/topologyValidator');
const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');

const TOPOLOGY_DEPLOYMENT_UNAVAILABLE = 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE';

class TopologyDeploymentError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'TopologyDeploymentError';
        this.code = code;
        Object.assign(this, details);
    }
}

function topologyDeploymentUnavailableError() {
    return new TopologyDeploymentError(
        TOPOLOGY_DEPLOYMENT_UNAVAILABLE,
        'Topology deployment capabilities are unavailable',
    );
}

const unavailableTopologyDeploymentService = Object.freeze({
    async deploy() {
        throw topologyDeploymentUnavailableError();
    },
});

function assertRevision(revision) {
    if (!Number.isSafeInteger(revision) || revision < 0) {
        throw new TopologyDeploymentError(
            'INVALID_TOPOLOGY_REVISION',
            'expectedTopologyRevision must be a non-negative safe integer',
            { expectedTopologyRevision: revision },
        );
    }
}

function safeDeploymentError(error, operationId, expectedTopologyRevision) {
    if (error?.code === 'STALE_TOPOLOGY_REVISION') {
        return new TopologyDeploymentError(
            'STALE_TOPOLOGY_REVISION',
            'The topology revision changed before deployment could be pinned',
            {
                operationId,
                expectedTopologyRevision,
                topologyRevision: Number.isSafeInteger(error.topologyRevision)
                    ? error.topologyRevision
                    : null,
            },
        );
    }
    if (error instanceof TopologyDeploymentError) return error;
    return new TopologyDeploymentError(
        'TOPOLOGY_DEPLOYMENT_FAILED',
        'Topology deployment failed',
        { operationId, expectedTopologyRevision },
    );
}

function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
    for (const nested of Object.values(value)) deepFreeze(nested);
    return Object.freeze(value);
}

class TopologyDeploymentService {
    constructor({
        repository,
        nodeDeployer,
        validator = validateTopology,
        compiler = compileTopology,
        idFactory = randomUUID,
    } = {}) {
        if (!repository || typeof repository.pinTopology !== 'function'
            || typeof repository.markDeployed !== 'function') {
            throw new TypeError('Topology deployment requires a revision-fenced repository');
        }
        if (!nodeDeployer || typeof nodeDeployer.applyNode !== 'function'
            || typeof nodeDeployer.verifyNode !== 'function'
            || typeof nodeDeployer.rollbackNode !== 'function') {
            throw new TypeError('Topology deployment requires a restorative node deployer');
        }
        if (typeof validator !== 'function' || typeof compiler !== 'function') {
            throw new TypeError('Topology deployment requires validator and compiler functions');
        }
        if (typeof idFactory !== 'function') {
            throw new TypeError('Topology deployment requires an evidence id factory');
        }
        this.repository = repository;
        this.nodeDeployer = nodeDeployer;
        this.validator = validator;
        this.compiler = compiler;
        this.idFactory = idFactory;
    }

    async rollbackChangedNodes({ operationId, topologyRevision, changedNodes }) {
        const rolledBackNodeIds = [];
        const rollbackFailedNodeIds = [];
        for (const changed of [...changedNodes].reverse()) {
            try {
                const result = await this.nodeDeployer.rollbackNode({
                    operationId,
                    topologyRevision,
                    nodeId: changed.nodeId,
                    rollbackToken: changed.rollbackToken,
                });
                if (result?.ok === true) rolledBackNodeIds.push(changed.nodeId);
                else rollbackFailedNodeIds.push(changed.nodeId);
            } catch {
                rollbackFailedNodeIds.push(changed.nodeId);
            }
        }
        return { rolledBackNodeIds, rollbackFailedNodeIds };
    }

    async failNode({
        operationId,
        topologyRevision,
        failedNodeId,
        changedNodes,
        code = 'NODE_DEPLOY_FAILED',
        message = 'A topology node deployment failed',
    }) {
        const rollback = await this.rollbackChangedNodes({
            operationId,
            topologyRevision,
            changedNodes,
        });
        throw new TopologyDeploymentError(code, message, {
            operationId,
            topologyRevision,
            failedNodeId,
            changedNodeIds: changedNodes.map(entry => entry.nodeId),
            ...rollback,
        });
    }

    async deploy({ expectedTopologyRevision } = {}) {
        assertRevision(expectedTopologyRevision);
        const operationId = this.idFactory('operation');
        let pinned;
        try {
            pinned = await this.repository.pinTopology({
                expectedRevision: expectedTopologyRevision,
                prepare: async snapshot => {
                    const topology = {
                        nodes: projectNodes(snapshot.nodes)
                            .sort((left, right) => left.id.localeCompare(right.id)),
                        links: projectLinks(snapshot.links)
                            .sort((left, right) => left.id.localeCompare(right.id)),
                        groups: projectGroups(snapshot.groups)
                            .sort((left, right) => left._id.localeCompare(right._id)),
                    };
                    const validation = this.validator(topology);
                    if (!validation?.valid) {
                        throw new TopologyDeploymentError(
                            'INVALID_TOPOLOGY_DEPLOYMENT',
                            'The pinned topology is invalid',
                            { operationId, errors: validation?.errors || [] },
                        );
                    }
                    const compiled = this.compiler({ ...topology, healthByPathKey: {} });
                    if (!compiled?.valid) {
                        throw new TopologyDeploymentError(
                            'INVALID_TOPOLOGY_DEPLOYMENT',
                            'The pinned topology could not be compiled',
                            { operationId, errors: compiled?.errors || [] },
                        );
                    }
                    return {
                        topology: deepFreeze(topology),
                        compiled: deepFreeze(compiled),
                    };
                },
            });
        } catch (error) {
            throw safeDeploymentError(error, operationId, expectedTopologyRevision);
        }

        const topologyRevision = pinned.revision;
        const changedNodes = [];
        const nodeEvidence = [];
        for (const node of pinned.topology.nodes) {
            const nodeId = node.id;
            let applied;
            try {
                applied = await this.nodeDeployer.applyNode({
                    operationId,
                    topologyRevision,
                    nodeId,
                    node,
                    topology: pinned.topology,
                    compiledTopology: pinned.compiled,
                });
            } catch {
                await this.failNode({ operationId, topologyRevision, failedNodeId: nodeId, changedNodes });
            }

            if (applied?.changed === true) {
                if (applied.rollbackToken === undefined) {
                    await this.failNode({
                        operationId,
                        topologyRevision,
                        failedNodeId: nodeId,
                        changedNodes,
                        code: 'NODE_DEPLOYER_CONTRACT_VIOLATION',
                        message: 'A changed node did not provide restorative rollback scope',
                    });
                }
                changedNodes.push({ nodeId, rollbackToken: applied.rollbackToken });
            }
            if (applied?.ok !== true) {
                await this.failNode({ operationId, topologyRevision, failedNodeId: nodeId, changedNodes });
            }

            const deploymentEvidenceId = this.idFactory('deployment');
            let verified;
            try {
                verified = await this.nodeDeployer.verifyNode({
                    operationId,
                    topologyRevision,
                    nodeId,
                    node,
                    topology: pinned.topology,
                    compiledTopology: pinned.compiled,
                });
            } catch {
                await this.failNode({
                    operationId,
                    topologyRevision,
                    failedNodeId: nodeId,
                    changedNodes,
                    code: 'NODE_VERIFICATION_FAILED',
                    message: 'A topology node verification failed',
                });
            }
            if (verified?.ok !== true) {
                await this.failNode({
                    operationId,
                    topologyRevision,
                    failedNodeId: nodeId,
                    changedNodes,
                    code: 'NODE_VERIFICATION_FAILED',
                    message: 'A topology node verification failed',
                });
            }
            nodeEvidence.push({
                nodeId,
                deploymentEvidenceId,
                verificationEvidenceId: this.idFactory('verification'),
            });
        }

        let deployedState;
        try {
            deployedState = await this.repository.markDeployed({
                expectedRevision: topologyRevision,
                expectedDeployedRevision: pinned.deployedRevision,
            });
        } catch (error) {
            const rollback = await this.rollbackChangedNodes({
                operationId,
                topologyRevision,
                changedNodes,
            });
            if (error?.code === 'STALE_TOPOLOGY_REVISION') {
                throw new TopologyDeploymentError(
                    'STALE_TOPOLOGY_REVISION',
                    'The topology revision changed before deployment could be committed',
                    {
                        operationId,
                        expectedTopologyRevision: topologyRevision,
                        topologyRevision: Number.isSafeInteger(error.topologyRevision)
                            ? error.topologyRevision
                            : null,
                        changedNodeIds: changedNodes.map(entry => entry.nodeId),
                        ...rollback,
                    },
                );
            }
            throw new TopologyDeploymentError(
                'DEPLOYED_REVISION_UPDATE_FAILED',
                'The deployed topology revision could not be committed',
                {
                    operationId,
                    topologyRevision,
                    changedNodeIds: changedNodes.map(entry => entry.nodeId),
                    ...rollback,
                },
            );
        }
        if (deployedState?.revision !== topologyRevision
            || deployedState?.deployedRevision !== topologyRevision) {
            const rollback = await this.rollbackChangedNodes({
                operationId,
                topologyRevision,
                changedNodes,
            });
            throw new TopologyDeploymentError(
                'DEPLOYED_REVISION_UPDATE_FAILED',
                'The deployed topology revision was not fenced to the pinned revision',
                {
                    operationId,
                    topologyRevision,
                    changedNodeIds: changedNodes.map(entry => entry.nodeId),
                    ...rollback,
                },
            );
        }

        return {
            operationId,
            topologyRevision,
            deployedRevision: deployedState.deployedRevision,
            nodeEvidence,
        };
    }
}

function createTopologyNodeDeployer({
    cascadeNodeDeployer,
    cascadeNodeVerifier,
    cascadeNodeRestorer,
} = {}) {
    if (typeof cascadeNodeDeployer?.deployNode !== 'function') {
        throw new TypeError('Topology deployment requires cascadeNodeDeployer.deployNode');
    }
    if (typeof cascadeNodeVerifier?.verifyNode !== 'function') {
        throw new TypeError('Topology deployment requires cascadeNodeVerifier.verifyNode');
    }
    if (typeof cascadeNodeRestorer?.restoreNode !== 'function') {
        throw new TypeError('Topology deployment requires cascadeNodeRestorer.restoreNode');
    }
    return Object.freeze({
        applyNode: input => cascadeNodeDeployer.deployNode(input),
        verifyNode: input => cascadeNodeVerifier.verifyNode(input),
        rollbackNode: input => cascadeNodeRestorer.restoreNode(input),
    });
}

function createTopologyDeploymentService({
    HyNode,
    CascadeLink,
    CascadeRouteGroup,
    CascadeTopologyState,
    RelayL2tpState,
    cascadeNodeDeployer,
    cascadeNodeVerifier,
    cascadeNodeRestorer,
    transactionRunner,
    SnapshotRepository = TopologyDraftRepository,
    DeploymentRepository = TopologyDeploymentRepository,
    validator,
    compiler,
    idFactory,
} = {}) {
    if (typeof cascadeNodeDeployer?.deployNode !== 'function'
        || typeof cascadeNodeVerifier?.verifyNode !== 'function'
        || typeof cascadeNodeRestorer?.restoreNode !== 'function') {
        return unavailableTopologyDeploymentService;
    }
    const snapshotReader = new SnapshotRepository({
        HyNode,
        CascadeLink,
        CascadeRouteGroup,
        CascadeTopologyState,
        RelayL2tpState,
        ...(transactionRunner === undefined ? {} : { transactionRunner }),
    });
    const repository = new DeploymentRepository({
        snapshotReader,
        CascadeTopologyState,
        ...(transactionRunner === undefined ? {} : { transactionRunner }),
    });
    return new TopologyDeploymentService({
        repository,
        nodeDeployer: createTopologyNodeDeployer({
            cascadeNodeDeployer,
            cascadeNodeVerifier,
            cascadeNodeRestorer,
        }),
        ...(validator === undefined ? {} : { validator }),
        ...(compiler === undefined ? {} : { compiler }),
        ...(idFactory === undefined ? {} : { idFactory }),
    });
}

module.exports = {
    TOPOLOGY_DEPLOYMENT_UNAVAILABLE,
    TopologyDeploymentError,
    TopologyDeploymentService,
    assertRevision,
    createTopologyDeploymentService,
    createTopologyNodeDeployer,
    topologyDeploymentUnavailableError,
    unavailableTopologyDeploymentService,
};
