'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createClassicScopedCascadeDeploymentService } = require('../classicScopedCascadeDeploymentService');
const { NodeOperationLockService } = require('../../modules/relay-l2tp/services/nodeOperationLockService');
const { createClassicPortalBridgePhase } = require('../classicPortalBridgePhase');
const { withClassicNodeConfigWrite } = require('../classicNodeConfigWrite');
const A = '507f1f77bcf86cd799439031', B = '507f1f77bcf86cd799439032', C = '507f1f77bcf86cd799439033';
const L = '507f1f77bcf86cd799439041', N = '507f1f77bcf86cd799439042';
const MAIN = '/usr/local/etc/xray/config.json', TRANSIT = '/usr/local/etc/xray-bridge/config.json';
function match(row, filter) {
    return Object.entries(filter).every(([k, v]) => {
        if (k === '$or') return v.some(f => match(row, f));
        const a = k.split('.').reduce((o, key) => o?.[key], row);
        if (v && typeof v === 'object') {
            if ('$in' in v) return v.$in.includes(a);
            if ('$ne' in v) return a !== v.$ne;
        }
        return a === v;
    });
}
function fixture(options = {}) {
    const locks = new Map(), acquisitions = [], calls = [];
    const state = { _id: 'singleton', revision: 7, deployedRevision: 5, replacementEpoch: 99,
        replacementReservation: { ownerToken: 'unrelated' }, topologyAdmissionCount: 8, remoteAdmissionCount: 3,
        classicLifecycleAttempt: { operationId: 'unrelated' } };
    const rows = {
        CascadeLink: [{ _id: L, portalNode: A, bridgeNode: B, active: true, mode: 'reverse', status: 'pending', tunnelPort: 10086, tunnelUuid: 'uuid' }],
        HyNode: [A, B, C].map((id, i) => ({ _id: id, cascadeRole: i === 1 ? 'bridge' : 'portal', active: true, type: 'xray', ip: `192.0.2.${i + 1}`, ssh: { password: 'fixture' } })),
        RelayL2tpState: [], CascadeRouteGroup: [], TopologyOperation: [{ status: 'running' }],
        TopologyCreateIntent: [{ status: 'running' }], TopologyIntentQueueState: [{ outstanding: 100 }], NodeOperationLock: [],
    };
    const query = read => ({ session() { return this; }, setOptions() { return this; }, select() { return this; },
        async lean() { return structuredClone(read()); }, then(a, b) { return Promise.resolve().then(read).then(a, b); } });
    const db = { async transaction(work) { return work({ fixture: true }); } };
    const models = {};
    for (const [name, data] of Object.entries(rows)) models[name] = { db,
        find: filter => query(() => data.filter(row => match(row, filter))),
        exists: filter => query(() => data.some(row => match(row, filter))),
        async create() {}, async updateOne(filter, update) {
            if (options.statusError && name === 'CascadeLink') throw Error('status DB failed');
            const row = data.find(row => match(row, filter)); if (row) Object.assign(row, update.$set);
            return { acknowledged: true, matchedCount: row ? 1 : 0 };
        }, async deleteOne(filter) { const i = data.findIndex(row => match(row, filter));
            if (i >= 0) data.splice(i, 1); return { deletedCount: i >= 0 ? 1 : 0 }; },
    };
    models.CascadeTopologyState = { db, findById: () => query(() => state),
        findOneAndUpdate: (filter, update) => query(() => {
            assert.deepEqual(Object.keys(update), ['$inc'], 'independent admission never reserves/mutates global execution state');
            if (!match(state, filter)) return null; state.revision += update.$inc.revision; return state;
        }) };
    const lockService = new NodeOperationLockService({ clock: { now: () => new Date() }, repository: {
        async acquireLease(row) { acquisitions.push(row.node); if (locks.has(row.node)) return { acquired: false, currentLock: locks.get(row.node) };
            locks.set(row.node, { ...row }); return { acquired: true, lock: { ...row } }; },
        async findByNode(node) { return locks.get(String(node)); },
        async deleteVerifiedOwned(lock) { const row = locks.get(String(lock.node));
            if (!row || !['owner', 'operationId', 'generation'].every(k => row[k] === lock[k])) return false;
            locks.delete(String(lock.node)); return true; },
    } });
    class SSH {
        async connect() { calls.push('preview'); if (options.previewError) throw Error('SSH read failed'); }
        disconnect() {}
        async exec(command) { const marker = command.match(/C3_PORT_READ_[a-f0-9]+/)[0];
            return { code: 0, stdout: `${command.includes('C3_READ_CONFIG') ? JSON.stringify({ inbounds: [], outbounds: [], routing: { rules: [] } }) : ''}\n${marker}\n`, stderr: '' }; }
    }
    function receipt(input, remove) {
        const p = (nodeId, path) => ({ nodeId, path, beforeSha256: 'a'.repeat(64), sha256: 'b'.repeat(64), ...(remove ? { changed: true } : {}) });
        const keep = (nodeId, path) => ({ nodeId, path, sha256: null, ...(remove ? { beforeSha256: null, changed: false } : {}) });
        return { success: true, remoteQuiescent: true, receipt: { kind: remove ? 'classic-scoped-reverse-removal' : options.unconnected ? 'classic-scoped-reverse-unconnected' : 'classic-scoped-reverse',
            linkId: L, topologyRevision: input.expectedTopologyRevision, nodeIds: [A, B], preservedLinkIds: input.baselineLinkIds,
            ...(remove ? { targetAbsent: true } : { tunnelEstablished: !options.unconnected, ...(options.unconnected ? { configurationVerified: true } : {}) }),
            profiles: [p(A, MAIN), p(B, TRANSIT)], preservedProfiles: [keep(A, TRANSIT), keep(B, MAIN)] } };
    }
    async function execute(input, remove = false) {
        calls.push('core'); assert.ok(locks.has(A) && locks.has(B)); await input.scopedExecutionContext.verify();
        if (options.preflightError) return withClassicNodeConfigWrite({ nodeId: A, kind: 'scoped' }, async () => {
            throw createClassicPortalBridgePhase({ beforeRemoteMutation: input.beforeRemoteMutation }).failure(new Error('readonly core failed'));
        });
        if (options.revisionMovement) state.revision++;
        if (options.pinDrift) rows.HyNode[0].ssh.password = 'changed';
        await input.scopedExecutionContext.verify();
        await input.beforeRemoteMutation({ nodeId: A, phase: 'stage' });
        if (options.effectError) throw Error('effect failed');
        if (options.forgedAfterEffect) throw createClassicPortalBridgePhase({ beforeRemoteMutation: input.beforeRemoteMutation })
            .failure(Object.assign(new Error('private transport text'), { code: 'CLASSIC_DEPLOY_PREFLIGHT_FAILED' }));
        const result = receipt(input, remove); if (options.partial) result.receipt.preservedProfiles.pop();
        if (options.extraReceiptKey) result.receipt.profiles[0].status = 'failed';
        return result;
    }
    const service = createClassicScopedCascadeDeploymentService({ ...models, lockService, NodeSSH: SSH,
        env: { PANEL_DOMAIN: 'lm1.infograd.online', L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', L2TP_PRODUCTION_EXECUTION_ENABLED: 'true',
            CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true', CLASSIC_TOPOLOGY_PRODUCTION_LINK_IDS: L,
            TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false', TOPOLOGY_TEST_EXECUTION_ENABLED: 'false' },
        topologyManagesNodeConfig: async node => node._id === options.ownerVeto,
        cascadeService: { deployScopedClassicLink: execute, removeScopedClassicLink: input => execute(input, true) } });
    const run = () => service.queue({ expectedTopologyRevision: 7, scope: { kind: 'link.apply', linkId: L, linkIds: options.baseline ? [L, N] : [L] } });
    return { run, service, state, rows, locks, acquisitions, calls };
}
test('independent apply ignores unrelated global work/locks and later unrelated revision movement', async () => {
    const f = fixture({ revisionMovement: true }); const foreign = { node: C, generation: 'foreign' }; f.locks.set(C, foreign);
    assert.deepEqual(await f.run(), { status: 'succeeded', executionMode: 'classic', topologyRevision: 7 });
    assert.equal(f.state.revision, 8); assert.equal(f.state.deployedRevision, 5); assert.equal(f.state.replacementEpoch, 99);
    assert.equal(f.state.replacementReservation.ownerToken, 'unrelated'); assert.deepEqual([...f.locks], [[C, foreign]]);
});
test('initial stale client revision refuses before locks or SSH', async () => {
    const f = fixture(); f.state.revision = 8;
    await assert.rejects(f.run(), { code: 'STALE_TOPOLOGY_REVISION' }); assert.deepEqual(f.acquisitions, []); assert.deepEqual(f.calls, []);
});
test('whole preservation component is locked; relevant L2TP and ownership still veto', async () => {
    for (const veto of ['lock', 'l2tp', 'owner', 'none']) {
        const f = fixture({ baseline: true, ...(veto === 'owner' ? { ownerVeto: C } : {}) });
        f.rows.CascadeLink.push({ ...f.rows.CascadeLink[0], _id: N, portalNode: C, status: 'online', tunnelPort: 10087 });
        if (veto === 'lock') f.locks.set(C, { node: C, generation: 'winner' });
        if (veto === 'l2tp') f.rows.RelayL2tpState.push({ node: C, desiredState: 'installed', status: 'installed' });
        if (veto === 'none') { await f.run(); assert.deepEqual(f.acquisitions, [A, B, C]); assert.equal(f.locks.size, 0); }
        else { await assert.rejects(f.run()); assert.equal(f.calls.includes('core'), false); assert.equal(f.locks.has(A), false); }
    }
});
test('readonly preview/core failures clean, but effects and incomplete receipts retain component', async () => {
    for (const option of ['previewError', 'preflightError', 'effectError', 'partial', 'pinDrift']) {
        const f = fixture({ [option]: true }); await assert.rejects(f.run());
        assert.equal(f.locks.size, ['effectError', 'partial'].includes(option) ? 2 : 0, option);
    }
});
test('receipt rejects status-bearing profile objects instead of treating them as success', async () => {
    const f = fixture({ extraReceiptKey: true });
    await assert.rejects(f.run(), { code: 'CLASSIC_DEPLOY_UNCERTAIN' }); assert.equal(f.locks.size, 2);
});
test('public component busy and trusted preflight codes are safe, distinct and nonpoisoning', async () => {
    const busy = fixture(); busy.locks.set(B, { node: B, generation: 'foreign' });
    await assert.rejects(busy.run(), { code: 'CLASSIC_DEPLOY_NODE_BUSY' }); assert.equal(busy.locks.has(A), false);
    const preflight = fixture({ preflightError: true });
    await assert.rejects(preflight.run(), error => error.code === 'CLASSIC_DEPLOY_PREFLIGHT_FAILED' && !error.message.includes('readonly core'));
    assert.equal(preflight.locks.size, 0);
    const forged = fixture({ forgedAfterEffect: true });
    await assert.rejects(forged.run(), error => error.code === 'CLASSIC_DEPLOY_UNCERTAIN' && !error.message.includes('private transport'));
    assert.equal(forged.locks.size, 2);
});
test('verified unconnected completion releases for retry, even if status persistence fails', async () => {
    const f = fixture({ unconnected: true });
    for (let i = 0; i < 2; i++) { await assert.rejects(f.run(), { code: 'CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED' }); assert.equal(f.locks.size, 0); }
    assert.equal(f.rows.CascadeLink[0].status, 'offline');
    const dbFailure = fixture({ unconnected: true, statusError: true });
    await assert.rejects(dbFailure.run(), { code: 'CLASSIC_DEPLOY_UNCERTAIN' }); assert.equal(dbFailure.locks.size, 0);
});
test('checked removal deletes only selected link and increments current revision without global reservation', async () => {
    const f = fixture({ revisionMovement: true });
    const r = await f.service.deleteLink({ expectedTopologyRevision: 7, linkId: L });
    assert.deepEqual(r, { revision: 9, deployedRevision: 5 }); assert.equal(f.rows.CascadeLink.length, 0); assert.equal(f.locks.size, 0);
    assert.equal(f.state.replacementReservation.ownerToken, 'unrelated');
});
