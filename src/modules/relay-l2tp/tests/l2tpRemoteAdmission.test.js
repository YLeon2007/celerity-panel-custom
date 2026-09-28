'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { RemoteAdmissionRepository } = require('../repositories/remoteAdmissionRepository');
const { L2tpService } = require('../services/l2tpService');
const { createL2tpPreflightRunner } = require('../services/l2tpPreflightRunner');

function matchesAdmission(record, filter) {
    return record && Object.entries(filter).every(([key, expected]) => {
        const value = record[key];
        if (expected && typeof expected === 'object') {
            if ('$exists' in expected) return (value !== undefined) === expected.$exists;
            if ('$in' in expected) return expected.$in.includes(value);
            throw new Error(`Unsupported admission filter: ${key}`);
        }
        return value === expected;
    });
}

function fixture({ gate = {}, releaseFails = false, ambiguousAcquire = false, remote = {} } = {}) {
    const calls = [];
    const state = gate === null ? null : { _id: 'singleton', remoteAdmissionCount: 0, ...gate };
    const records = new Map();
    let failRelease = releaseFails;
    const session = { id: 'transaction' };
    const topology = {
        db: { startSession: async () => session },
        async updateOne(filter, update, options) {
            assert.strictEqual(options.session, session);
            calls.push(['gate', filter, update]);
            if (!state || filter.remoteDrain?.$exists === false && state.remoteDrain !== undefined
                || filter.replacementReservation?.$exists === false && state.replacementReservation !== undefined
                || filter.remoteAdmissionCount?.$gte !== undefined
                    && !(typeof state.remoteAdmissionCount === 'number'
                        && state.remoteAdmissionCount >= filter.remoteAdmissionCount.$gte)
                || filter.remoteAdmissionCount?.$gt !== undefined && state.remoteAdmissionCount <= 0) {
                return { matchedCount: 0 };
            }
            if (failRelease && update.$inc.remoteAdmissionCount < 0) {
                failRelease = false;
                throw new Error('release DB unavailable');
            }
            state.remoteAdmissionCount += update.$inc.remoteAdmissionCount;
            return { matchedCount: 1 };
        },
    };
    const admission = {
        db: topology.db,
        async create(documents, options) {
            assert.strictEqual(options.session, session);
            for (const document of documents) {
                if (records.has(document._id)) throw new Error('duplicate admission');
                records.set(document._id, { ...document });
            }
        },
        async updateOne(filter, update, options) {
            assert.strictEqual(options.session, session);
            calls.push(['record', filter, update]);
            const record = records.get(filter._id);
            if (!matchesAdmission(record, filter)) return { matchedCount: 0 };
            Object.assign(record, update.$set);
            return { matchedCount: 1 };
        },
    };
    const repository = new RemoteAdmissionRepository({ CascadeTopologyState: topology,
        RemoteAdmission: admission, transactionRunner: async callback => {
            const oldCount = state?.remoteAdmissionCount;
            const oldRecords = new Map([...records].map(([id, record]) => [id, { ...record }]));
            try {
                const result = await callback(session);
                if (ambiguousAcquire && records.size === 1 && [...records.values()][0].phase === 'running') {
                    const error = new Error('ambiguous admission commit');
                    error.code = 'UNKNOWN_TRANSACTION_COMMIT_RESULT';
                    throw error;
                }
                return result;
            } catch (error) {
                if (error.code === 'UNKNOWN_TRANSACTION_COMMIT_RESULT') throw error;
                if (state) state.remoteAdmissionCount = oldCount;
                records.clear();
                for (const [id, record] of oldRecords) records.set(id, record);
                throw error;
            }
        } });
    const transport = {
        uploadRootFile: async () => { calls.push(['upload']); if (remote.uploadError) throw new Error('timeout'); },
        runArtifactCommand: async () => { calls.push(['command']); if (remote.commandError) throw new Error('timeout');
            return remote.response ?? { ok: true, checks: [
                { check: 'os', status: 'ok', id: 'debian', version: '13' },
                { check: 'client_cidr', status: 'ok', cidr: '10.0.0.0/24' },
                { check: 'xray', status: 'ok', version: '1.0' },
                { check: 'xray_config', status: 'ok', path: '/usr/local/etc/xray/config.json' },
                { check: 'xray_unit', status: 'ok', unit: 'xray.service' },
            ] }; },
    };
    const runner = createL2tpPreflightRunner({ transportResolver: async () => {
        calls.push(['resolve']); return transport;
    } });
    const node = { id: 'relay-1', cascadeRole: 'relay' };
    const desired = { desiredState: 'installed', clientCidr: '10.0.0.0/24', localAddress: '10.0.0.1',
        poolStart: '10.0.0.2', poolEnd: '10.0.0.254', dnsServers: ['1.1.1.1'],
        tproxyPort: 1000, fwmark: 3, routeTable: 4 };
    const service = new L2tpService({
        nodeRepository: { findById: async () => node },
        stateRepository: {
            findByNodeId: async () => desired,
            findRouteGroupById: async () => ({ id: 'group' }),
            getTopologyRevision: async () => 2,
            getRelayGroupPlan: async () => ({}),
        }, preflightRunner: runner, remoteAdmissionRepository: repository,
    });
    const run = () => service.preflight('relay-1', { routeGroupId: 'group', expectedTopologyRevision: 2 });
    return { run, calls, state, records, repository };
}

test('default admission repository rejects missing or mismatched transactional connections', () => {
    const db = { startSession: async () => ({ withTransaction: async work => work(), endSession: async () => {} }) };
    const CascadeTopologyState = { db, updateOne: async () => ({ matchedCount: 1 }) };
    const RemoteAdmission = { db: {}, create: async () => {}, updateOne: async () => ({ matchedCount: 1 }) };
    assert.throws(() => new RemoteAdmissionRepository({ CascadeTopologyState, RemoteAdmission }),
        /one transactional Mongo connection/);
    RemoteAdmission.db = db;
    db.startSession = undefined;
    assert.throws(() => new RemoteAdmissionRepository({ CascadeTopologyState, RemoteAdmission }),
        /one transactional Mongo connection/);
});

test('standalone preflight is denied before transport for missing gate, legacy count, drain and reservation', async () => {
    for (const gate of [null, { remoteAdmissionCount: undefined },
        { remoteDrain: { ownerToken: 'drain', epoch: 1 } },
        { replacementReservation: { ownerToken: 'reserved', epoch: 1 } }]) {
        const f = fixture({ gate });
        await assert.rejects(f.run(), { code: 'REMOTE_ADMISSION_BLOCKED' });
        assert.equal(f.calls.filter(([kind]) => ['resolve', 'upload', 'command'].includes(kind)).length, 0);
        assert.equal(f.records.size, 0);
    }
});

test('validated completed preflight releases its counted admission exactly once', async () => {
    const f = fixture();
    assert.equal((await f.run()).ok, true);
    assert.equal(f.state.remoteAdmissionCount, 0);
    assert.equal([...f.records.values()][0].phase, 'completed');
    assert.deepEqual(f.calls.filter(([kind]) => ['resolve', 'upload', 'command'].includes(kind)).map(([kind]) => kind),
        ['resolve', 'upload', 'command']);
});

test('validated remote refusal releases its counted admission', async () => {
    const response = { ok: false,
        checks: [{ check: 'os', status: 'error', code: 'UNSUPPORTED_OS', id: 'other', version: '1' }],
        error: { code: 'UNSUPPORTED_OS' },
    };
    const f = fixture({ remote: { response } });
    assert.deepEqual(await f.run(), response);
    assert.equal(f.state.remoteAdmissionCount, 0);
    assert.equal([...f.records.values()][0].phase, 'completed');
});

test('ambiguous acquisition commit leaves a counted orphan with its recovery id and no transport', async () => {
    const f = fixture({ ambiguousAcquire: true });
    await assert.rejects(f.run(), error => {
        assert.equal(error.code, 'UNKNOWN_TRANSACTION_COMMIT_RESULT');
        assert.equal(error.admissionId, [...f.records.keys()][0]);
        return true;
    });
    assert.equal(f.state.remoteAdmissionCount, 1);
    assert.equal([...f.records.values()][0].phase, 'running');
    assert.equal(f.calls.filter(([kind]) => ['resolve', 'upload', 'command'].includes(kind)).length, 0);
});

test('upload and command timeouts retain a counted recovery admission', async () => {
    for (const remote of [{ uploadError: true }, { commandError: true },
        { response: { unexpected: true } }]) {
        const f = fixture({ remote });
        await f.run();
        assert.equal(f.state.remoteAdmissionCount, 1);
        assert.equal([...f.records.values()][0].phase, 'recovery_required');
    }
});

test('release DB failure leaves admission counted and does not double decrement', async () => {
    const f = fixture({ releaseFails: true });
    await assert.rejects(f.run(), /release DB unavailable/);
    assert.equal(f.state.remoteAdmissionCount, 1);
    const record = [...f.records.values()][0];
    assert.equal(record.phase, 'recovery_required');
    await assert.rejects(f.repository.release(record._id), { code: 'REMOTE_ADMISSION_NOT_ACTIVE' });
    assert.equal(f.state.remoteAdmissionCount, 1);
});

test('legacy release refuses linked running install and sync worker admissions without touching the count', async () => {
    for (const record of [
        { kind: 'install', ownerGeneration: 2, operationId: 'install-op', leaseOwner: 'worker' },
        { kind: 'sync_users', ownerGeneration: 1, operationId: 'sync-op', leaseOwner: 'worker' },
        { kind: 'sync_users', ownerGeneration: 1 }, // A malformed unlinked sync is not prequeue work.
    ]) {
        const f = fixture({ gate: { remoteAdmissionCount: 1 } });
        f.records.set('admission-1', { _id: 'admission-1', nodeId: 'relay-1', phase: 'running', ...record });
        await assert.rejects(f.repository.release('admission-1'), { code: 'REMOTE_ADMISSION_NOT_ACTIVE' });
        assert.equal(f.state.remoteAdmissionCount, 1);
        assert.equal(f.records.get('admission-1').phase, 'running');
        assert.equal(f.calls.filter(([kind]) => kind === 'gate').length, 0);
    }
});
