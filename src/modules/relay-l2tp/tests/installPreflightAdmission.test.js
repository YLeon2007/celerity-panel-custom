'use strict';
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');

const assert = require('node:assert/strict');
const test = require('node:test');
const { createL2tpRuntime } = require('../runtime/createL2tpRuntime');
const { RemoteAdmissionRepository } = require('../repositories/remoteAdmissionRepository');
const { NodeOperationLockRepository } = require('../services/nodeOperationLockRepository');
const { NodeOperationLockService } = require('../services/nodeOperationLockService');
const { createL2tpPreflightRunner } = require('../services/l2tpPreflightRunner');

const RESPONSE = { ok: true, checks: [
    { check: 'os', status: 'ok', id: 'debian', version: '13' },
    { check: 'client_cidr', status: 'ok', cidr: '10.0.0.0/24' },
    { check: 'xray', status: 'ok', version: '1.0' },
    { check: 'xray_config', status: 'ok', path: '/usr/local/etc/xray/config.json' },
    { check: 'xray_unit', status: 'ok', unit: 'xray.service' },
] };
const FOREIGN_LOCK = { node: 'relay-1', owner: 'topology-worker', operationId: 'topology-op',
    generation: 'topology-generation', remoteUncertain: true, leaseUntil: new Date(0) };

function matches(row, filter) {
    return !!row && Object.entries(filter).every(([key, expected]) => {
        const value = row[key];
        if (expected && typeof expected === 'object') {
            if ('$exists' in expected) return (value !== undefined) === expected.$exists;
            if ('$in' in expected) return expected.$in.includes(value);
            if ('$gte' in expected) return typeof value === 'number' && value >= expected.$gte;
            if ('$gt' in expected) return typeof value === 'number' && value > expected.$gt;
            throw new Error(`Unsupported filter: ${key}`);
        }
        return value === expected;
    });
}

// Real runtime, admission repository, exact lock service/repository, preflight
// runner, plan builder and materializer; only persistence and transport are fake.
// No sockets, SSH clients, deployment or remote processes are created here.
function fixture(options = {}) {
    const events = [];
    const gate = { _id: 'singleton', remoteAdmissionCount: 0, topologyAdmissionCount: 0,
        ...options.gate };
    const admissions = new Map();
    const locks = new Map();
    const operations = new Map();
    const session = { id: 'install-preflight-transaction' };
    const db = { startSession: async () => { throw new Error('unexpected uninjected transaction'); } };
    const query = (rows, filter) => ({
        session(value) { assert.strictEqual(value, session); return this; },
        async lean() { return structuredClone([...rows].find(row => matches(row, filter)) ?? null); },
    });
    const update = (rows, filter, change, settings) => {
        assert.strictEqual(settings.session, session);
        const row = [...rows].find(candidate => matches(candidate, filter));
        if (!row) return { matchedCount: 0 };
        Object.assign(row, change.$set);
        for (const [key, value] of Object.entries(change.$inc ?? {})) row[key] += value;
        return { matchedCount: 1 };
    };
    const CascadeTopologyState = { db,
        findOne: filter => query([gate], filter),
        updateOne: async (filter, change, settings) => {
            if (options.admissionReleaseFails && change.$inc?.remoteAdmissionCount < 0) {
                events.push('admission-release-failed');
                throw new Error('admission release commit unknown');
            }
            return update([gate], filter, change, settings);
        },
    };
    const RemoteAdmission = { db,
        findOne: filter => query(admissions.values(), filter),
        async create(rows, settings) {
            assert.strictEqual(settings.session, session);
            for (const row of rows) admissions.set(row._id, structuredClone(row));
        },
        updateOne: async (filter, change, settings) => update(admissions.values(), filter, change, settings),
    };
    const NodeOperationLock = { db,
        findOne: filter => query(locks.values(), filter),
        async create(row) {
            events.push('lock-insert');
            // Simulate a topology worker winning AFTER the admission snapshot.
            if (options.raceLock) locks.set('relay-1', structuredClone(FOREIGN_LOCK));
            if (locks.has(row.node)) throw Object.assign(new Error('duplicate node lock'), { code: 11000 });
            locks.set(row.node, structuredClone(row));
            if (options.uncertainLockInsert) throw new Error('lock insert commit unknown');
            return structuredClone(row);
        },
        async deleteOne(filter) {
            events.push('lock-delete');
            if (options.releaseThrows) throw new Error('lock delete commit unknown');
            if (options.staleGeneration) locks.get(filter.node).generation = 'successor-generation';
            if (!matches(locks.get(filter.node), filter)) return { deletedCount: 0 };
            locks.delete(filter.node);
            return { deletedCount: 1 };
        },
    };
    const L2tpOperation = { db,
        async create(rows, settings) {
            assert.strictEqual(settings.session, session);
            events.push('queue');
            for (const row of rows) operations.set(row._id, structuredClone(row));
        },
    };
    const repository = new RemoteAdmissionRepository({ CascadeTopologyState, RemoteAdmission,
        NodeOperationLock, L2tpOperation, transactionRunner: async work => {
            const oldGate = structuredClone(gate);
            const oldAdmissions = structuredClone(admissions);
            const oldOperations = structuredClone(operations);
            try { return await work(session); } catch (error) {
                Object.assign(gate, oldGate);
                admissions.clear();
                for (const [id, row] of oldAdmissions) admissions.set(id, row);
                operations.clear();
                for (const [id, row] of oldOperations) operations.set(id, row);
                throw error;
            }
        } });
    const clock = { now: () => new Date('2026-09-22T10:00:00Z') };
    const lockService = new NodeOperationLockService({
        repository: new NodeOperationLockRepository({ model: NodeOperationLock }), clock,
    });
    const transport = {
        async uploadRootFile() { events.push('upload'); if (options.uploadTimeout) throw new Error('upload timeout'); },
        async runArtifactCommand() {
            events.push('command');
            return options.command ? options.command() : options.response ?? RESPONSE;
        },
    };
    const preflightRunner = createL2tpPreflightRunner({ executionContext: options.executionContext ?? TEST,
        enableProductionExecution: options.enableProductionExecution === true, transportResolver: async () => {
        events.push('resolve');
        assert.equal(gate.remoteAdmissionCount, 1);
        assert.match(locks.get('relay-1').owner, /^install-preflight:/);
        return transport;
    } });
    const pass = (req, res, next) => next();
    const runtime = createL2tpRuntime({
        executionContext: options.executionContext ?? TEST,
        enableProductionExecution: options.enableProductionExecution === true,
        operationModel: L2tpOperation, operationRepository: {},
        nodeRepository: { findById: async () => ({ id: 'relay-1', cascadeRole: 'relay' }) },
        stateRepository: {
            findByNodeId: async () => ({ desiredState: 'installed', secretRevision: 1,
                clientCidr: '10.0.0.0/24', localAddress: '10.0.0.1', poolStart: '10.0.0.2',
                poolEnd: '10.0.0.254', dnsServers: ['1.1.1.1'], tproxyPort: 1000, fwmark: 3, routeTable: 4 }),
            findRouteGroupById: async () => ({ id: 'group' }), getTopologyRevision: async () => 2,
            getRelayGroupPlan: async () => ({ groupId: 'group',
                candidates: [{ pathKey: 'primary', healthy: true, nextHopNodeId: 'bridge-1' }],
                decision: { decision: 'select', groupId: 'group', pathKey: 'primary', nextHopNodeId: 'bridge-1' } }),
        },
        stateManagementService: {}, userManagementService: {},
        preflightRunner, remoteAdmissionRepository: repository, lockService, transport,
        enableInstallAdmission: true,
        secretResolver: async () => { throw new Error('worker must not execute'); },
        userSnapshotResolver: async () => { throw new Error('worker must not execute'); },
        userSyncReconciler: {}, stateReconciler: {}, candidateService: {},
        requireAuth: pass, requireOnboarding: pass, csrf: pass, rateLimiter: pass,
        loadPanelOverview: async () => ({}), renderPage() {}, clock,
        workerId: 'unused-worker', leaseMs: 30_000,
    });
    return { runtime, repository, lockService, gate, admissions, locks, operations, events,
        run: () => runtime.service.install('relay-1', { routeGroupId: 'group', expectedTopologyRevision: 2 }) };
}

function assertNoRemote(f) {
    assert.deepEqual(f.events.filter(event => ['resolve', 'upload', 'command', 'queue'].includes(event)), []);
}

test('assembled install refuses a topology-owned node before any transport resolver or upload', async () => {
    const f = fixture();
    f.locks.set('relay-1', structuredClone(FOREIGN_LOCK));
    await assert.rejects(f.run(), { code: 'NODE_OPERATION_LOCK_CONFLICT' });
    assertNoRemote(f);
    assert.equal(f.gate.remoteAdmissionCount, 0);
    assert.equal(f.admissions.size, 0);
    assert.deepEqual(f.locks.get('relay-1'), FOREIGN_LOCK);
});

test('assembled install refuses an admitted topology operation before its worker acquires a node', async () => {
    const f = fixture({ gate: { topologyAdmissionCount: 1 } });
    await assert.rejects(f.run(), { code: 'REMOTE_ADMISSION_BLOCKED' });
    assertNoRemote(f);
    assert.equal(f.gate.remoteAdmissionCount, 0);
    assert.equal(f.admissions.size, 0);
    assert.equal(f.locks.size, 0);
});

test('assembled admission-to-node-insert race preserves topology lock and releases only install count', async () => {
    const f = fixture({ raceLock: true });
    await assert.rejects(f.run(), { code: 'NODE_OPERATION_LOCK_CONFLICT' });
    assertNoRemote(f);
    assert.equal(f.gate.remoteAdmissionCount, 0);
    assert.equal([...f.admissions.values()][0].phase, 'completed');
    assert.deepEqual(f.locks.get('relay-1'), FOREIGN_LOCK);
    assert.equal(f.events.includes('lock-delete'), false);
});

test('assembled node conflict with failed admission release retains count without touching foreign lock', async () => {
    const f = fixture({ raceLock: true, admissionReleaseFails: true });
    await assert.rejects(f.run(), /admission release commit unknown/);
    assertNoRemote(f);
    assert.equal(f.gate.remoteAdmissionCount, 1);
    assert.equal([...f.admissions.values()][0].phase, 'recovery_required');
    assert.deepEqual(f.locks.get('relay-1'), FOREIGN_LOCK);
    assert.equal(f.events.filter(event => event === 'admission-release-failed').length, 1);
    assert.equal(f.events.includes('lock-delete'), false);
});

test('assembled install holds exact lock throughout command and queues the original counted admission', async () => {
    let start;
    let finish;
    const started = new Promise(resolve => { start = resolve; });
    const completed = new Promise(resolve => { finish = resolve; });
    const f = fixture({ command: () => { start(); return completed; } });
    const installing = f.run();
    await started;
    assert.equal(f.gate.remoteAdmissionCount, 1);
    const lock = structuredClone(f.locks.get('relay-1'));
    assert.equal(lock.remoteUncertain, true);
    assert.ok(lock.generation);
    const competing = await f.lockService.acquire({ node: 'relay-1', owner: 'topology-worker',
        operationId: 'concurrent-topology', leaseMs: 30_000 });
    assert.equal(competing.ok, false);
    assert.deepEqual(f.locks.get('relay-1'), lock);
    finish(RESPONSE);
    const result = await installing;
    assert.equal(f.locks.size, 0);
    assert.equal(f.gate.remoteAdmissionCount, 1);
    const admission = [...f.admissions.values()][0];
    assert.equal(admission.phase, 'queued');
    assert.equal(admission.ownerGeneration, 1);
    assert.equal(admission.operationId, result.operationId);
    assert.notEqual(result.operationId, lock.operationId);
    assert.equal(f.operations.get(result.operationId).admissionId, admission._id);
    assert.equal(f.operations.get(result.operationId).ownerGeneration, undefined);
    assert.equal(f.events.indexOf('lock-delete') < f.events.indexOf('queue'), true);
});

for (const [name, options, error] of [
    ['uncertain lock insert', { uncertainLockInsert: true }, /lock insert commit unknown/],
    ['upload timeout', { uploadTimeout: true }, { code: 'PREFLIGHT_RESPONSE_INVALID' }],
    ['command timeout', { command: async () => { throw new Error('command timeout'); } },
        { code: 'PREFLIGHT_RESPONSE_INVALID' }],
    ['invalid remote response', { response: { unexpected: true } }, { code: 'PREFLIGHT_RESPONSE_INVALID' }],
    ['stale lock generation', { staleGeneration: true }, { code: 'PREFLIGHT_FENCE_RELEASE_FAILED' }],
    ['uncertain exact release', { releaseThrows: true }, /lock delete commit unknown/],
]) {
    test(`assembled install ${name} keeps count and node fence for recovery without queueing`, async () => {
        const f = fixture(options);
        await assert.rejects(f.run(), error);
        assert.equal(f.gate.remoteAdmissionCount, 1);
        assert.equal([...f.admissions.values()][0].phase, 'recovery_required');
        assert.equal(f.locks.size, 1);
        assert.equal(f.operations.size, 0);
        assert.equal(f.events.includes('queue'), false);
        if (options.uncertainLockInsert) assertNoRemote(f);
        if (options.uploadTimeout || options.response) assert.equal(f.events.includes('lock-delete'), false);
        if (options.staleGeneration) assert.equal(f.locks.get('relay-1').generation, 'successor-generation');
    });
}

test('assembled verified remote refusal releases exact node lock and decrements admission once', async () => {
    const f = fixture({ response: { ok: false,
        checks: [{ check: 'os', status: 'error', code: 'UNSUPPORTED_OS', id: 'other', version: '1' }],
        error: { code: 'UNSUPPORTED_OS' } } });
    await assert.rejects(f.run(), { code: 'PREFLIGHT_FAILED' });
    assert.equal(f.gate.remoteAdmissionCount, 0);
    assert.equal(f.locks.size, 0);
    assert.equal(f.operations.size, 0);
    const admission = [...f.admissions.values()][0];
    assert.equal(admission.phase, 'completed');
    await assert.rejects(f.repository.release(admission._id), { code: 'REMOTE_ADMISSION_NOT_ACTIVE' });
    assert.equal(f.gate.remoteAdmissionCount, 0);
});

test('assembled production requires separate opt-in and persists identity after fenced preflight', async () => {
    const PROD = require('../domain/topologyExecutionContext').PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT;
    const denied = fixture({ executionContext: PROD });
    await assert.rejects(denied.run(), { code: 'L2TP_EXECUTION_NOT_AUTHORIZED' });
    assert.equal(denied.gate.remoteAdmissionCount, 0);
    assert.deepEqual(denied.events, []);
    const allowed = fixture({ executionContext: PROD, enableProductionExecution: true });
    const result = await allowed.run();
    assert.deepEqual(allowed.operations.get(result.operationId).executionContext, PROD);
    assert.equal(allowed.gate.remoteAdmissionCount, 1);
    assert.equal(allowed.locks.size, 0);
    assert.equal([...allowed.admissions.values()][0].phase, 'queued');
});
