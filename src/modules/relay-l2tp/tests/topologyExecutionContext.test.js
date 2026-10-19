'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
    createTopologyOperationExecutor,
    createTopologyOperationRuntime,
} = require('../runtime/createTopologyOperationRuntime');
const { TopologyOperationCoordinator } = require('../services/topologyOperationCoordinator');
const { TopologyOperationWorker } = require('../workers/topologyOperationWorker');
const {
    TOPOLOGY_EXECUTION_CONTEXTS,
    topologyExecutionContext,
} = require('../domain/topologyExecutionContext');
const { TopologyOperationExecutor } = require('../services/topologyOperationExecutor');

const TEST = Object.freeze({ target: 'test', hostIdentity: 'test.infograd.online' });
const PROD = Object.freeze({ target: 'production', hostIdentity: 'lm1.infograd.online' });
const TEST_ENV = Object.freeze({
    L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true',
    TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', PANEL_DOMAIN: TEST.hostIdentity,
});
const PROD_ENV = Object.freeze({
    L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true',
    TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true', PANEL_DOMAIN: PROD.hostIdentity,
});

function runtimeDependencies(env, calls = []) {
    const model = (...methods) => Object.fromEntries(methods.map(method => [method, () => {
        calls.push(method);
        assert.fail('composition must not access persistence');
    }]));
    return {
        env,
        HyNode: model('find', 'findById'),
        CascadeLink: model('find', 'create', 'updateOne', 'deleteOne'),
        CascadeRouteGroup: model('find', 'create', 'updateOne', 'deleteOne'),
        CascadeTopologyState: model('findById', 'findOneAndUpdate', 'updateOne'),
        RelayL2tpState: model('find', 'findOne', 'findOneAndUpdate'),
        L2tpUser: model('find'),
        L2tpOperation: model('findOne', 'countDocuments', 'create'),
        TopologyOperation: model('create', 'findById', 'findOneAndUpdate', 'updateOne'),
        NodeOperationLock: model('findOne', 'findOneAndUpdate', 'updateOne', 'deleteOne'),
        NodeSSH: class { constructor() { calls.push('ssh'); assert.fail('must not connect'); } },
        transactionRunner: async () => assert.fail('must not open a transaction'),
    };
}

test('assembled runtime binds the real worker claim to selected host despite later env and request identities', async () => {
    for (const selected of [TEST, PROD]) {
        const env = { ...(selected === TEST ? TEST_ENV : PROD_ENV) };
        const calls = [];
        const dependencies = runtimeDependencies(env);
        dependencies.TopologyOperation.findOneAndUpdate = async (filter, update, options) => {
            calls.push({ filter, update, options });
            return null;
        };
        const service = createTopologyOperationRuntime({ ...dependencies,
            createTopologyOperationExecutor(options) {
                Object.assign(env, selected === TEST ? PROD_ENV : TEST_ENV);
                return createTopologyOperationExecutor({ ...options, NodeSSH: class {} });
            },
        });
        assert.ok(service instanceof TopologyOperationCoordinator);
        assert.deepEqual(service.operationWorker.executionContext, selected);
        const result = await service.operationWorker.run({ operationId: 'operation-1', executionContext: PROD });
        if (selected === PROD) {
            assert.equal(result.errorCode, 'TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN');
            assert.deepEqual(calls, []);
        } else {
            assert.deepEqual(result, { claimed: false, operationId: 'operation-1' });
            assert.equal(calls.length, 2);
            for (const { filter, options } of calls) {
                assert.equal(filter['executionContext.target'], TEST.target);
                assert.equal(filter['executionContext.hostIdentity'], TEST.hostIdentity);
                assert.ok(filter.$expr);
                assert.equal(options.projection.executionContext, 1);
                assert.equal(options.projection.idempotencyKey, 1);
            }
        }
    }
});

test('allowlist contains only frozen exact pairs and never normalizes identities', () => {
    assert.deepEqual(TOPOLOGY_EXECUTION_CONTEXTS, [TEST, PROD]);
    assert.equal(Object.isFrozen(TOPOLOGY_EXECUTION_CONTEXTS), true);
    for (const pair of [TEST, PROD]) {
        const context = topologyExecutionContext(pair.target, pair.hostIdentity);
        assert.equal(Object.isFrozen(context), true);
        assert.throws(() => { context.target = 'other'; }, TypeError);
    }
    for (const pair of [
        {}, { target: 'production' }, { hostIdentity: PROD.hostIdentity },
        { target: 'test', hostIdentity: PROD.hostIdentity },
        { target: 'production', hostIdentity: TEST.hostIdentity },
        { target: 'Production', hostIdentity: PROD.hostIdentity },
        { target: 'production', hostIdentity: PROD.hostIdentity + '.' },
        { target: 'production', hostIdentity: { toString: () => PROD.hostIdentity } },
    ]) assert.equal(topologyExecutionContext(pair.target, pair.hostIdentity), undefined);
});

test('production runtime requires its independent exact opt-in before constructing anything', async () => {
    for (const env of [
        { ...TEST_ENV, PANEL_DOMAIN: PROD.hostIdentity },
        ...Object.keys(PROD_ENV).flatMap(key => [undefined, 'false', 'TRUE', true].map(value => (
            { ...PROD_ENV, [key]: value }
        ))),
        { ...PROD_ENV, PANEL_DOMAIN: 'other.invalid' },
        { ...PROD_ENV, PANEL_DOMAIN: PROD.hostIdentity + '.' },
    ]) {
        let factoryCalls = 0;
        const service = createTopologyOperationRuntime({
            ...runtimeDependencies(env),
            createTopologyOperationExecutor() { factoryCalls += 1; assert.fail('must not construct'); },
        });
        await assert.rejects(service.deploy({ expectedTopologyRevision: 7 }), {
            code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE',
        });
        assert.equal(factoryCalls, 0);
    }
});

test('runtime snapshots the actual production context without granting TEST-only execution bypasses', async () => {
    const env = { ...PROD_ENV };
    const calls = [];
    let factoryContext;
    let workerOptions;
    class CaptureWorker extends TopologyOperationWorker {
        constructor(options) { super(options); workerOptions = options; }
    }
    const service = createTopologyOperationRuntime({
        ...runtimeDependencies(env, calls),
        OperationWorker: CaptureWorker,
        createTopologyOperationExecutor(options) {
            factoryContext = options;
            // A server adapter changing its source env cannot retarget this runtime
            // or grant the TEST bypass after production context selection.
            Object.assign(env, TEST_ENV);
            return createTopologyOperationExecutor({ ...options, NodeSSH: class {} });
        },
    });
    assert.ok(service instanceof TopologyOperationCoordinator);
    assert.deepEqual({ target: factoryContext.target, hostIdentity: factoryContext.hostIdentity }, PROD);
    assert.equal(Object.isFrozen(factoryContext), true);
    env.PANEL_DOMAIN = TEST.hostIdentity;
    env.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED = 'false';
    assert.equal(factoryContext.target, 'production');
    assert.equal(workerOptions.allowUnprovenTestExecution, false);
    assert.equal(Object.hasOwn(workerOptions, 'pppDriftSync'), false);
    assert.equal(Object.hasOwn(workerOptions, 'pppResumeReadinessGate'), false);
    assert.deepEqual(await service.operationWorker.run('production-seam'), {
        claimed: false, operationId: 'production-seam', stopped: true,
        errorCode: 'TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN',
    });
    assert.deepEqual(calls, []);
});

test('factory and executor reject absent or cross-paired identities before adapter access', () => {
    for (const contour of [{}, { target: 'test' }, { target: 'production' },
        { hostIdentity: PROD.hostIdentity },
        { target: 'test', hostIdentity: PROD.hostIdentity },
        { target: 'production', hostIdentity: TEST.hostIdentity }]) {
        const HyNode = { findById() { assert.fail('must not look up a node'); } };
        const NodeSSH = class { constructor() { assert.fail('must not connect'); } };
        assert.equal(createTopologyOperationExecutor({ ...contour, HyNode, NodeSSH }), undefined);
        assert.throws(() => new TopologyOperationExecutor({
            ...contour, nodeExecutionResolver: { resolve() { assert.fail('must not resolve'); } },
        }), { code: 'UNSAFE_TOPOLOGY_TARGET' });
    }
});

test('assembled production runtime carries its context through coordinator and attach resolver seams', async () => {
    const dependencies = runtimeDependencies(PROD_ENV);
    const service = createTopologyOperationRuntime(dependencies);
    assert.ok(service instanceof TopologyOperationCoordinator);
    let materialized;
    let inserted;
    const session = { inTransaction: () => true };
    service.topologyRepository.admitTopology = async ({ prepare, admit }) => {
        const prepared = await prepare({
            revision: 7, deployedRevision: 5,
            nodes: [{ _id: 'portal-1', cascadeRole: 'portal' }, { _id: 'bridge-1', cascadeRole: 'bridge' }],
            links: [{ _id: 'link-1', portalNode: 'portal-1', bridgeNode: 'bridge-1', mode: 'forward', active: true }],
            groups: [],
        }, session);
        const admitted = { revision: 7, deployedRevision: 5, ...prepared };
        await admit(admitted, session);
        return admitted;
    };
    // Local materialization/persistence seams: no MongoDB or remote adapters.
    service.planMaterializer.materialize = async input => {
        materialized = input;
        return { nodes: ['portal', 'bridge'].map(role => ({
            role, nodeRef: role, candidate: { sha256: `${role}-hash`, bytes: [] }, checks: [],
        })) };
    };
    service.operationRepository.createFrozen = async input => { inserted = input; return { _id: input.operationId }; };
    await service.queue({ expectedTopologyRevision: 7 });
    assert.deepEqual({ target: materialized.target, hostIdentity: materialized.hostIdentity }, PROD);
    assert.match(inserted.idempotencyKey, /^topology:production:revision-7:/);
    let lookups = 0;
    dependencies.HyNode.findById = () => {
        lookups += 1;
        return { select() { return { lean: async () => null }; } };
    };
    await assert.rejects(service.operationWorker.attachIngressGate.nodeExecutionResolver.resolve({
        nodeId: 'relay-1', role: 'relay',
    }), { code: 'TOPOLOGY_NODE_EXECUTION_UNAVAILABLE' });
    assert.equal(lookups, 1, 'production attach resolver must pass the context fence before lookup');
    for (const field of ['target', 'hostIdentity', 'executionContext']) {
        await assert.rejects(service.queue({ expectedTopologyRevision: 7, [field]: PROD[field] ?? PROD }), {
            code: 'INVALID_REQUEST',
        });
    }
});

test('server executor factory accepts the exact production context without starting transport', () => {
    let reads = 0;
    const executor = createTopologyOperationExecutor({
        ...PROD,
        HyNode: { findById() { reads += 1; assert.fail('composition must not read nodes'); } },
        NodeSSH: class { constructor() { assert.fail('composition must not connect'); } },
    });
    assert.ok(executor instanceof TopologyOperationExecutor);
    assert.equal(reads, 0);
});
