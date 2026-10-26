'use strict';
// SIMULATED persistence/physical authority; real BSON codec. No remote I/O.
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../../../modules/relay-l2tp/domain/topologyExecutionContext');
const IDS = ['6ab189dc63913ebd4a917399', '6ab18adc63913ebd4a917471', '6ab18d9c63913ebd4a917670',
    '6ab4b53bc4c0304573e06c72', '6ab93ad2646b4b7d2f43c907'];
const ENV = { PANEL_DOMAIN: 'lm1.infograd.online', TOPOLOGY_TEST_EXECUTION_ENABLED: 'false',
    TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false' };
const COLLECTION = 'testlegacytopologyreleases';
function api() {
    let found;
    try { found = require('../../testLegacyTopologyRelease'); } catch (e) { if (e.code !== 'MODULE_NOT_FOUND') throw e; }
    assert.equal(typeof found?.TestLegacyTopologyRelease, 'function', 'finite TEST legacy release service must exist');
    return found;
}
function fixture() {
    const { ObjectId, BSON } = require('mongodb');
    const copy = v => BSON.deserialize(BSON.serialize({ v })).v;
    const data = {
        hynodes: IDS.map((id, i) => ({ _id: new ObjectId(id), ip: `127.0.0.${i + 1}`, ssh: { port: 22, password: 'PRIVATE-fixture' },
            xray: { agentToken: 'PRIVATE-agent' }, status: 'online' })),
        topologyoperations: [{ _id: new ObjectId(), status: 'failed', heldTopologyAdmission: false,
            nodes: IDS.map(node => ({ node: new ObjectId(node), state: 'prepared' })), privateCandidate: Buffer.from('PRIVATE-config') }],
        cascadetopologystates: [{ _id: 'singleton', topologyAdmissionCount: 0, remoteAdmissionCount: 0 }],
        topologyintentqueuestates: [{ _id: 'create-v1', outstanding: 0 }],
    };
    const calls = [], deployment = { setName: 'rs0', replicaSetId: '6ab3717b28a9e4d82b5ee86a', database: 'hysteria' };
    const db = { databaseName: deployment.database,
        listCollections(filter) { return { toArray: async () => Object.hasOwn(data, filter.name) ? [{ name: filter.name }] : [] }; },
        admin: () => ({ command: async command => {
            calls.push(['command', command]);
            return { config: { _id: deployment.setName, settings: { replicaSetId: new ObjectId(deployment.replicaSetId) } } };
        } }),
        collection(name) { return {
            // SIMULATED persistence, real BSON codec and actual driver find options.
            find(filter, options) { calls.push(['find', name, filter, options]); return { toArray: async () =>
                (data[name] || []).map(row => { const raw = BSON.serialize(row);
                    return options?.raw ? raw : BSON.deserialize(raw, options); }) }; },
            async insertOne(row) { calls.push(['insert', name]); if ((data[name] || []).length) throw new Error('duplicate');
                data[name] = [copy(row)]; return { acknowledged: true }; },
        }; },
        async createCollection(name, options) { calls.push(['create', name, options]); if (Object.hasOwn(data, name)) throw new Error('exists'); data[name] = []; },
    };
    const baseline = IDS.map(node => ({ node, nodeIdentity: { machineId: '1'.repeat(32), sshHostKeySha256: '2'.repeat(64) },
        profiles: ['xray-main', 'xray-bridge'].map((profile, i) => ({ profile,
            config: i ? { state: 'absent' } : { state: 'present', sha256: '3'.repeat(64), uid: 0, gid: 0, mode: 420 },
            unit: { state: 'present', sha256: '4'.repeat(64), uid: 0, gid: 0, mode: 420 },
            additionalUnitFiles: i ? [] : [{ path: '/etc/systemd/system/xray.service.d/override.conf',
                artifact: { state: 'present', sha256: '5'.repeat(64), uid: 0, gid: 0, mode: 420 } }],
            serviceActive: i ? 'inactive' : 'active', serviceEnabled: 'enabled' })) }));
    let held = false, checks = 0;
    const authority = async ({ binding }, work) => {
        held = true;
        try { return await work({ authority: 'test-legacy-maintenance-v1', binding, proofId: randomUUID(), maintenanceId: randomUUID(),
            oldBackend: { instanceId: 'simulated-backend', pid: 42, processStartTime: '100', processTree: 'stopped', dispatch: 'disabled' },
            async recheck(challenge) { assert.equal(held, true); assert.deepEqual(challenge, binding); checks++; return copy(baseline); } });
        } finally { held = false; }
    };
    const env = { ...ENV };
    const service = (options = {}) => new (api().TestLegacyTopologyRelease)({ db, executionContext: TEST,
        expectedDeployment: deployment, acceptedBaseline: baseline, env, withVerifiedMaintenance: authority, ...options });
    return { db, data, calls, deployment, baseline, authority, service, env, get checks() { return checks; } };
}

module.exports = { api, fixture, IDS, ENV, COLLECTION, TEST };
