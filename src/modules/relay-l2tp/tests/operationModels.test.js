'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const mongoose = require('mongoose');

const L2tpOperation = require('../models/l2tpOperationModel');
const TopologyOperation = require('../models/topologyOperationModel');

const L2TP_OPERATION_KINDS = [
    'preflight',
    'install',
    'remove',
    'repair',
    'verify',
    'sync_users',
    'disconnect_user',
    'rotate_psk',
    'change_route_group',
];
const L2TP_OPERATION_STATUSES = [
    'queued',
    'running',
    'rolling_back',
    'succeeded',
    'failed',
    'rolled_back',
    'cancelled',
];
const TOPOLOGY_OPERATION_STATUSES = [
    'queued',
    'preparing',
    'committing',
    'rolling_back',
    'succeeded',
    'failed',
    'rolled_back',
];
const TOPOLOGY_NODE_STATES = [
    'pending',
    'prepared',
    'committed',
    'failed',
    'rolled_back',
];

function objectId() {
    return new mongoose.Types.ObjectId();
}

function l2tpOperation(overrides = {}) {
    return new L2tpOperation({
        node: objectId(),
        kind: 'install',
        status: 'queued',
        idempotencyKey: 'install:node:revision-1',
        plan: {
            ok: true,
            topologyRevision: 1,
            relayId: 'relay-1',
            routeGroupId: 'group-a',
            steps: [{ type: 'verify' }],
        },
        ...overrides,
    });
}

function topologyOperation(overrides = {}) {
    return new TopologyOperation({
        topologyRevision: 1,
        status: 'queued',
        ...overrides,
    });
}

function assertValidationKind(document, path, kind) {
    const error = document.validateSync();
    assert.ok(error, `${path} should be invalid`);
    assert.equal(error.errors[path]?.kind, kind);
}

test('L2TP operation requires a node reference', () => {
    assert.equal(l2tpOperation().validateSync(), undefined);

    const error = l2tpOperation({ node: undefined }).validateSync();
    assert.equal(error.errors.node.kind, 'required');
    assert.equal(L2tpOperation.schema.path('node').options.ref, 'HyNode');
});

test('L2TP operation kind is required and limited to the documented v1 kinds', () => {
    assert.deepEqual(L2tpOperation.schema.path('kind').enumValues, L2TP_OPERATION_KINDS);

    for (const kind of L2TP_OPERATION_KINDS) {
        assert.equal(l2tpOperation({ kind }).validateSync(), undefined);
    }

    assertValidationKind(l2tpOperation({ kind: undefined }), 'kind', 'required');
    assertValidationKind(l2tpOperation({ kind: 'deploy' }), 'kind', 'enum');
});

test('L2TP operation status is required and limited to durable lifecycle states', () => {
    assert.deepEqual(L2tpOperation.schema.path('status').enumValues, L2TP_OPERATION_STATUSES);

    for (const status of L2TP_OPERATION_STATUSES) {
        assert.equal(l2tpOperation({ status }).validateSync(), undefined);
    }

    assertValidationKind(l2tpOperation({ status: undefined }), 'status', 'required');
    assertValidationKind(l2tpOperation({ status: 'complete' }), 'status', 'enum');
});

test('L2TP operation requires an idempotency key with a unique index', () => {
    assertValidationKind(
        l2tpOperation({ idempotencyKey: undefined }),
        'idempotencyKey',
        'required',
    );

    const index = L2tpOperation.schema.indexes().find(([fields]) => fields.idempotencyKey === 1);
    assert.ok(index, 'idempotency key index exists');
    assert.equal(index[1].unique, true);
});

test('L2TP operation requires an immutable durable plan', () => {
    const planPath = L2tpOperation.schema.path('plan');

    assert.ok(planPath, 'plan schema path exists');
    assert.equal(planPath.options.required, true);
    assert.equal(planPath.options.immutable, true);
    assert.equal(l2tpOperation().validateSync(), undefined);
    assertValidationKind(l2tpOperation({ plan: undefined }), 'plan', 'required');
});

test('L2TP operation plan retains only the worker allowlist and drops plaintext secrets', () => {
    const operation = l2tpOperation({
        plan: {
            ok: false,
            operationId: 'operation-17',
            topologyRevision: 17,
            relayId: 'relay-1',
            routeGroupId: 'group-a',
            selectedPathKey: 'primary',
            nextHopNodeId: 'bridge-1',
            error: {
                code: 'NO_HEALTHY_PATH',
                password: 'error-password',
            },
            steps: [{
                type: 'verify',
                psk: 'step-psk',
                password: 'step-password',
            }],
            psk: 'plan-psk',
            password: 'plan-password',
            unknown: 'not-allowed',
        },
    });

    assert.equal(operation.validateSync(), undefined);
    assert.deepEqual(operation.toObject().plan, {
        ok: false,
        operationId: 'operation-17',
        topologyRevision: 17,
        relayId: 'relay-1',
        routeGroupId: 'group-a',
        selectedPathKey: 'primary',
        nextHopNodeId: 'bridge-1',
        error: { code: 'NO_HEALTHY_PATH' },
        steps: [{ type: 'verify' }],
    });
});

test('L2TP operation retains optional topology and route-group plan identity', () => {
    const routeGroupId = objectId();
    const operation = l2tpOperation({ topologyRevision: 17, routeGroupId });

    assert.equal(operation.validateSync(), undefined);
    assert.equal(operation.topologyRevision, 17);
    assert.equal(String(operation.routeGroupId), String(routeGroupId));
    assert.equal(
        L2tpOperation.schema.path('routeGroupId').options.ref,
        'CascadeRouteGroup',
    );
    assertValidationKind(l2tpOperation({ topologyRevision: -1 }), 'topologyRevision', 'min');
});

test('L2TP operation progress is numeric and bounded from 0 through 100', () => {
    assert.equal(L2tpOperation.schema.path('progress').instance, 'Number');

    for (const progress of [0, 50, 100]) {
        assert.equal(l2tpOperation({ progress }).validateSync(), undefined);
    }

    for (const progress of [-1, 101, Number.NaN, Number.POSITIVE_INFINITY]) {
        const error = l2tpOperation({ progress }).validateSync();
        assert.ok(error?.errors.progress, `progress ${String(progress)} should be invalid`);
    }
});

test('L2TP operation logs retain only sanitized journal fields', () => {
    const operation = l2tpOperation({
        logs: [{
            at: new Date('2026-09-22T00:00:00.000Z'),
            level: 'info',
            code: 'INSTALL_STARTED',
            message: 'installation started',
            psk: 'secret-psk',
            password: 'secret-password',
            sshCommand: 'command --password secret',
            token: 'secret-token',
        }],
    });

    assert.equal(operation.validateSync(), undefined);
    const log = operation.toObject().logs[0];
    assert.deepEqual(Object.keys(log).sort(), ['at', 'code', 'level', 'message']);
    assert.equal(log.code, 'INSTALL_STARTED');
});

test('L2TP operation retains durable lifecycle metadata', () => {
    const user = objectId();
    const leaseUntil = new Date('2026-09-22T01:00:00.000Z');
    const operation = l2tpOperation({
        user,
        step: 'preflight',
        attempts: 2,
        leaseOwner: 'worker-1',
        leaseUntil,
        backupId: 'backup-1',
        errorCode: 'NONE',
        errorMessage: '',
        requestedBy: 'admin',
        startedAt: new Date('2026-09-22T00:00:00.000Z'),
        finishedAt: new Date('2026-09-22T00:05:00.000Z'),
    });

    assert.equal(operation.validateSync(), undefined);
    assert.equal(String(operation.user), String(user));
    assert.equal(operation.leaseUntil.getTime(), leaseUntil.getTime());
    assertValidationKind(l2tpOperation({ attempts: -1 }), 'attempts', 'min');
});

test('topology operation requires a nonnegative topology revision', () => {
    assert.equal(topologyOperation({ topologyRevision: 0 }).validateSync(), undefined);
    assertValidationKind(
        topologyOperation({ topologyRevision: undefined }),
        'topologyRevision',
        'required',
    );
    assertValidationKind(topologyOperation({ topologyRevision: -1 }), 'topologyRevision', 'min');
});

test('topology operation status is required and limited to durable coordinator states', () => {
    assert.deepEqual(
        TopologyOperation.schema.path('status').enumValues,
        TOPOLOGY_OPERATION_STATUSES,
    );

    for (const status of TOPOLOGY_OPERATION_STATUSES) {
        assert.equal(topologyOperation({ status }).validateSync(), undefined);
    }

    assertValidationKind(topologyOperation({ status: undefined }), 'status', 'required');
    assertValidationKind(topologyOperation({ status: 'complete' }), 'status', 'enum');
});

test('topology operation retains durable per-node deployment state', () => {
    const nodeSchema = TopologyOperation.schema.path('nodes').schema;
    assert.deepEqual(nodeSchema.path('state').enumValues, TOPOLOGY_NODE_STATES);
    assert.equal(nodeSchema.path('node').options.ref, 'HyNode');

    for (const state of TOPOLOGY_NODE_STATES) {
        const operation = topologyOperation({
            nodes: [{
                node: objectId(),
                state,
                candidateHash: 'sha256:candidate-1',
                backupId: 'backup-1',
            }],
        });

        assert.equal(operation.validateSync(), undefined);
        assert.equal(operation.nodes[0].candidateHash, 'sha256:candidate-1');
        assert.equal(operation.nodes[0].backupId, 'backup-1');
    }

    assertValidationKind(
        topologyOperation({ nodes: [{ node: objectId(), state: undefined }] }),
        'nodes.0.state',
        'required',
    );
    assertValidationKind(
        topologyOperation({ nodes: [{ node: objectId(), state: 'complete' }] }),
        'nodes.0.state',
        'enum',
    );
});
