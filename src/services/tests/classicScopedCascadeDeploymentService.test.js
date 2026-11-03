'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { createClassicScopedCascadeDeploymentService } = require('../classicScopedCascadeDeploymentService');
const { issueClassicLifecycleGrant } = require('../classicLifecycleAuthorization');
const lifecycleEnv = { CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED: 'true',
    CLASSIC_TOPOLOGY_LIFECYCLE_SIGNING_KEY: 'ab'.repeat(32), CLASSIC_TOPOLOGY_PRODUCTION_LINK_IDS: undefined };
const LINK = '507f1f77bcf86cd799439041';
const A = '507f1f77bcf86cd799439031';
const B = '507f1f77bcf86cd799439032';
const C = '507f1f77bcf86cd799439033';
const NEIGHBOR = '507f1f77bcf86cd799439042';
const PENDING = '507f1f77bcf86cd799439043';
const FOREIGN = '507f1f77bcf86cd799439044';
const GROUP = '6abf570edf3782a8235f1575';
const MAIN = '/usr/local/etc/xray/config.json';
const TRANSIT = '/usr/local/etc/xray-bridge/config.json';
function completed(coreInput = { linkId: LINK, expectedTopologyRevision: 7, baselineLinkIds: [] }) {
    return { success: true, remoteQuiescent: true, receipt: {
        kind: 'classic-scoped-reverse', linkId: coreInput.linkId,
        topologyRevision: coreInput.expectedTopologyRevision, nodeIds: [A, B],
        preservedLinkIds: coreInput.baselineLinkIds, tunnelEstablished: true,
        profiles: [{ nodeId: A, path: MAIN, beforeSha256: 'a'.repeat(64), sha256: 'b'.repeat(64) },
            { nodeId: B, path: TRANSIT, beforeSha256: 'c'.repeat(64), sha256: 'd'.repeat(64) }],
        preservedProfiles: [{ nodeId: A, path: TRANSIT, sha256: 'e'.repeat(64) },
            { nodeId: B, path: MAIN, sha256: null }],
    } };
}
const env = () => ({ PANEL_DOMAIN: 'lm1.infograd.online', L2TP_EXECUTION_ENABLED: 'true',
    L2TP_MIGRATIONS_ENABLED: 'true', L2TP_PRODUCTION_EXECUTION_ENABLED: 'true',
    CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true',
    CLASSIC_TOPOLOGY_PRODUCTION_LINK_IDS: LINK,
    TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false', TOPOLOGY_TEST_EXECUTION_ENABLED: 'false' });
function matches(row, filter) {
    return Object.entries(filter).every(([key, value]) => {
        if (key === '$or') return value.some(item => matches(row, item));
        const actual = key.split('.').reduce((o, k) => o?.[k], row);
        if (Array.isArray(value)) return JSON.stringify(actual) === JSON.stringify(value);
        if (value && typeof value === 'object') {
            if ('$exists' in value) return (actual !== undefined) === value.$exists;
            if ('$in' in value) return value.$in.includes(actual);
            if ('$nin' in value) return !value.$nin.includes(actual);
            if ('$ne' in value) return actual !== value.$ne;
        }
        return actual === value;
    });
}
function harness(overrides = {}) {
    const calls = { remote: [], preview: [], updates: [], owner: [], transactionActive: false };
    let state = { _id: 'singleton', revision: 7, deployedRevision: 5, replacementEpoch: 2,
        topologyAdmissionCount: 0, remoteAdmissionCount: 0, ...overrides.state };
    const rows = {
        CascadeLink: [{ _id: LINK, portalNode: A, bridgeNode: B, mode: 'reverse', active: true,
            status: 'pending', tunnelPort: 10086, tunnelUuid: 'local-target-uuid' }, ...(overrides.links || [])],
        HyNode: [{ _id: A, cascadeRole: 'relay', active: true, type: 'xray', ip: '192.0.2.1', ssh: { password: 'fixture' } },
            { _id: B, cascadeRole: 'bridge', active: true, type: 'xray', ip: '192.0.2.2', ssh: { password: 'fixture' } },
            { _id: C, cascadeRole: 'relay', active: true, type: 'xray' }],
        RelayL2tpState: overrides.relays || [], CascadeRouteGroup: overrides.groups || [],
        TopologyOperation: overrides.operations || [], TopologyCreateIntent: overrides.intents || [],
        TopologyIntentQueueState: overrides.queues || [], NodeOperationLock: overrides.locks || [],
    };
    const query = fn => ({ session() { return this; }, select() { return this; }, setOptions() { return this; },
        async lean() { return structuredClone(fn()); },
        then(resolve, reject) { return Promise.resolve().then(fn).then(resolve, reject); } });
    const connection = { async transaction(work, options) {
        calls.transactionOptions = options;
        calls.transactionActive = true;
        try { return await work({ fixture: true }); } finally { calls.transactionActive = false; }
    } };
    const models = {};
    for (const [name, records] of Object.entries(rows)) models[name] = { db: connection,
        find: filter => query(() => records.filter(row => matches(row, filter))),
        exists: filter => query(() => records.some(row => matches(row, filter))),
        async create() { throw Error('unused fixture create'); },
        async updateOne(filter, update) {
            const row = records.find(row => matches(row, filter));
            if (row) Object.assign(row, update.$set);
            return { matchedCount: row ? 1 : 0 };
        },
        async deleteOne(filter, options) {
            assert.ok(calls.transactionActive && options.session, 'draft deletion in held settlement transaction');
            assert.ok(state.replacementReservation || rows.NodeOperationLock.length >= 2);
            const i = records.findIndex(row => matches(row, filter));
            if (i >= 0) records.splice(i, 1);
            return { deletedCount: i >= 0 ? 1 : 0 };
        },
    };
    models.CascadeTopologyState = { db: connection,
        findById: () => query(() => state),
        findOne: filter => query(() => matches(state, filter) ? state : null),
        findOneAndUpdate: (filter, update, options) => query(() => {
            calls.updates.push({ filter, update, options });
            if (!matches(state, filter)) return null;
            if (overrides.releaseFailure && update.$unset) return null;
            Object.assign(state, update.$set);
            for (const [key, amount] of Object.entries(update.$inc || {})) state[key] += amount;
            for (const key of Object.keys(update.$unset || {})) delete state[key];
            return state;
        }),
    };
    class PreviewSSH {
        constructor(node) { assert.equal(String(node._id), A); this.updatesBefore = calls.updates.length; }
        async connect() {
            assert.equal(calls.transactionActive, false, 'no SSH inside a retryable transaction');
            assert.equal(state.replacementReservation, undefined, 'preview precedes topology claim');
            assert.ok([0, 2].includes(rows.NodeOperationLock.length));
            calls.preview.push('connect');
        }
        async exec(command) {
            assert.equal(calls.transactionActive, false);
            assert.equal(calls.updates.length, this.updatesBefore, 'preview is read-only and before ownership writes');
            assert.doesNotMatch(command, /\.stage|restart|ufw|firewall-cmd|\bmv\b/);
            calls.preview.push(command);
            if (overrides.previewError) throw Error('private password=redact');
            const marker = command.match(/C3_PORT_READ_[a-f0-9]+/)[0];
            let text = '';
            if (command.includes('C3_READ_CONFIG')) text = command.includes(TRANSIT)
                ? JSON.stringify(overrides.transit || { inbounds: [] }) : JSON.stringify({ inbounds: [], outbounds: [], routing: { rules: [] } });
            if (command.includes('ss -')) text = overrides.sockets || '';
            overrides.afterPreviewRead?.({ rows, state, command });
            return { code: 0, stdout: `${text}\n${marker}\n`, stderr: '' };
        }
        disconnect() { calls.preview.push('disconnect'); }
    }
    const { NodeOperationLockService } = require('../../modules/relay-l2tp/services/nodeOperationLockService');
    const lockService = new NodeOperationLockService({ clock: { now: () => new Date() }, repository: {
        async acquireLease(row) {
            const currentLock = rows.NodeOperationLock.find(lock => String(lock.node) === String(row.node));
            if (currentLock) return { acquired: false, currentLock };
            rows.NodeOperationLock.push({ ...row }); return { acquired: true, lock: { ...row } };
        },
        async findByNode(node) { return rows.NodeOperationLock.find(lock => String(lock.node) === String(node)); },
        async deleteVerifiedOwned(lock) {
            const i = rows.NodeOperationLock.findIndex(row => ['node', 'owner', 'operationId', 'generation'].every(k => String(row[k]) === String(lock[k])));
            if (i < 0) return false; rows.NodeOperationLock.splice(i, 1); return true;
        },
    } });
    const dependencies = { ...models, lockService, env: { ...env(), ...overrides.env }, NodeSSH: PreviewSSH,
        logger: { warn(event) { assert.equal(typeof event, 'string', 'production logger stringifies objects without metadata'); calls.diagnostic = JSON.parse(event); } },
        topologyManagesNodeConfig: async node => {
            assert.ok(calls.transactionActive || state.replacementReservation || rows.NodeOperationLock.length >= 2, 'ownership checked in claim transaction or held fence');
            calls.owner.push(String(node._id));
            return !!overrides.ownerVeto;
        },
        cascadeService: { async removeScopedClassicLink(input) {
            assert.equal(calls.transactionActive, false);
            assert.ok(rows.CascadeLink.some(link => link._id === input.linkId), 'link retained during SSH');
            calls.remote.push(input);
            const result = removed(input);
            return overrides.removeWork ? overrides.removeWork({ state, rows, calls, result }) : result;
        }, async deployScopedClassicLink(input) {
            assert.equal(calls.transactionActive, false, 'remote work outside retryable transaction');
            if (input.scopedExecutionContext) assert.ok(rows.NodeOperationLock.length >= 2);
            else assert.match(state.replacementReservation.ownerToken, /^classic-deploy:/);
            assert.equal(state.revision, 7);
            assert.equal(state.deployedRevision, 5);
            calls.remote.push(input);
            return overrides.work ? overrides.work({ state, rows, calls, result: completed(input) })
                : completed(input);
        } },
    };
    return { service: createClassicScopedCascadeDeploymentService(dependencies), calls, rows,
        state: () => state, dependencies };
}
const input = (linkIds = [LINK]) => ({ expectedTopologyRevision: 7,
    scope: { kind: 'link.apply', linkId: LINK, linkIds } });

test('verified unconnected settlement warns without poisoning a manual retry or delete', async () => {
    const h = harness({ work({ result }) {
        result.receipt.kind = 'classic-scoped-reverse-unconnected';
        result.receipt.configurationVerified = true; result.receipt.tunnelEstablished = false;
        return result;
    } });
    h.rows.HyNode[0].cascadeRole = 'portal';
    for (let i = 0; i < 2; i++) {
        await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED' });
        assert.equal(h.state().replacementReservation, undefined); assert.equal(h.state().classicLifecycleAttempt, undefined);
        assert.equal(h.rows.CascadeLink[0].status, 'offline');
        assert.equal(h.rows.NodeOperationLock.length, 0);
    }
    assert.equal(h.calls.remote.length, 2);
    await h.service.deleteLink(deletion());
    assert.equal(h.rows.CascadeLink.length, 0); assert.equal(h.state().revision, 8);
});

test('verified unconnected receipt cannot hide a failed settlement', async () => {
    const h = harness({ releaseFailure: true, work({ result }) {
        result.receipt.kind = 'classic-scoped-reverse-unconnected';
        result.receipt.configurationVerified = true; result.receipt.tunnelEstablished = false;
        return result;
    } });
    await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_FENCE_LOST' });
    assert.ok(h.state().replacementReservation); assert.ok(h.state().classicLifecycleAttempt);
});

test('unconnected flags and partial or failed proof cannot authorize release', async () => {
    for (const change of [r => { r.receipt.configurationVerified = false; },
        r => { delete r.receipt.configurationVerified; }, r => { r.remoteQuiescent = false; },
        r => { r.receipt.profiles.pop(); }, r => { r.receipt.preservedProfiles.pop(); },
        r => { r.receipt.topologyRevision++; }, r => { r.receipt.tunnelEstablished = true; },
        r => { r.receipt.extra = 'not a completion protocol'; }]) {
        const h = harness({ work({ result }) {
            result.receipt.kind = 'classic-scoped-reverse-unconnected';
            result.receipt.configurationVerified = true; result.receipt.tunnelEstablished = false; change(result);
            return result;
        } });
        await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_UNCERTAIN' });
        assert.ok(h.state().replacementReservation); assert.ok(h.state().classicLifecycleAttempt);
    }
});

test('unsupported endpoint capability refuses before preview or topology claim', async () => {
    for (const change of [nodes => { nodes[0].cascadeRole = 'bridge'; },
        nodes => { nodes[0].active = false; }, nodes => { nodes[0].type = 'hysteria'; },
        nodes => { nodes[0].ip = 'bad;host'; }, nodes => { nodes[1].ip = 'bridge.invalid'; },
        nodes => { delete nodes[1].ssh; }]) {
        const h = harness(); change(h.rows.HyNode);
        await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_UNSUPPORTED' });
        assert.equal(h.calls.remote.length, 0); assert.equal(h.calls.updates.length, 0);
        assert.equal(h.calls.preview.length, 0); assert.equal(h.state().replacementEpoch, 2);
        assert.equal(h.state().replacementReservation, undefined);
    }
});

test('portal auto-create and save-only manual retry use the same endpoint contract', async () => {
    for (const auto of [false, true]) {
        const h = harness(); h.rows.HyNode[0].cascadeRole = 'portal';
        let r;
        if (auto) {
            const c = h.service.beginCreatedLinkCapability({ linkId: LINK });
            h.service.confirmCreatedLinkCapability(c, { linkId: LINK, expectedTopologyRevision: 7 });
            r = await h.service.queueCreatedLink(input(), c);
        } else r = await h.service.queue(input());
        assert.equal(r.status, 'succeeded'); assert.equal(h.calls.remote.length, 1);
        assert.equal(h.state().replacementReservation, undefined);
        assert.equal(h.rows.HyNode[0].cascadeRole, 'portal');
    }
});

test('classic ingress capability is explicit and construction/access resolves no dependencies', () => {
    const service = createClassicScopedCascadeDeploymentService(new Proxy({ env: {} }, {
        get(target, key) {
            assert.equal(key, 'env', 'constructor and capability must not resolve models or services');
            return target[key];
        },
    }));
    assert.equal(service.requiresL2tpIngressPreparation, false);
    assert.equal(Object.isFrozen(service), true);
    assert.equal(typeof Object.getOwnPropertyDescriptor(service, 'requiresL2tpIngressPreparation').get, 'function');
});

test('classic baseline selector preserves connected offline links without activating unrelated pending links', async () => {
    const h = harness({ links: [{ _id: NEIGHBOR, portalNode: C, bridgeNode: B,
        active: true, status: 'offline', mode: 'reverse' },
    { _id: PENDING, portalNode: A, bridgeNode: C, active: true, status: 'pending', mode: 'reverse' }] });
    const baseline = h.service.selectBaselineLinkIds({ links: h.rows.CascadeLink, linkId: LINK });
    assert.deepEqual(baseline, [NEIGHBOR]);
    await h.service.queue(input([LINK, ...baseline]));
    assert.deepEqual(h.calls.remote[0].baselineLinkIds, [NEIGHBOR]);
});

test('checked scoped completion returns synchronous classic result without IDs or revision publication', async () => {
    const h = harness();
    const result = await h.service.queue(input());
    assert.deepEqual(result, { status: 'succeeded', executionMode: 'classic', topologyRevision: 7 });
    assert.deepEqual(h.calls.remote, [{ linkId: LINK, expectedTopologyRevision: 7, baselineLinkIds: [] }]);
    assert.deepEqual(h.calls.owner.sort(), [A, A, A, B, B, B]);
    assert.equal(h.state().revision, 7);
    assert.equal(h.state().deployedRevision, 5);
    assert.equal(h.state().replacementEpoch, 3);
    assert.equal(h.state().replacementReservation, undefined);
    assert.equal(h.calls.updates[1].options.writeConcern.w, 'majority');
});

test('internal create-and-apply path permits only the newly persisted pending target without allowlisting', async () => {
    const h = harness({ env: { CLASSIC_TOPOLOGY_PRODUCTION_LINK_IDS: FOREIGN } });
    const capability = h.service.beginCreatedLinkCapability({ linkId: LINK });
    h.service.confirmCreatedLinkCapability(capability, { linkId: LINK, expectedTopologyRevision: 7 });
    const result = await h.service.queueCreatedLink(input(), capability);
    assert.deepEqual(result, { status: 'succeeded', executionMode: 'classic', topologyRevision: 7 });
    assert.equal(h.calls.remote.length, 1);
});

test('creation capability is one-use and requires confirmation plus exact pending status', async () => {
    const h = harness({ env: { CLASSIC_TOPOLOGY_PRODUCTION_LINK_IDS: FOREIGN } });
    const capability = h.service.beginCreatedLinkCapability({ linkId: LINK });
    await assert.rejects(h.service.queueCreatedLink(input(), capability), { code: 'CLASSIC_DEPLOY_UNSUPPORTED' });
    h.service.confirmCreatedLinkCapability(capability, { linkId: LINK, expectedTopologyRevision: 7 });
    await h.service.queueCreatedLink(input(), capability);
    await assert.rejects(h.service.queueCreatedLink(input(), capability), { code: 'CLASSIC_DEPLOY_UNSUPPORTED' });

    const errored = harness({ env: { CLASSIC_TOPOLOGY_PRODUCTION_LINK_IDS: FOREIGN } });
    errored.rows.CascadeLink[0].status = 'error';
    const errorCapability = errored.service.beginCreatedLinkCapability({ linkId: LINK });
    errored.service.confirmCreatedLinkCapability(errorCapability, { linkId: LINK, expectedTopologyRevision: 7 });
    await assert.rejects(errored.service.queueCreatedLink(input(), errorCapability), { code: 'CLASSIC_DEPLOY_UNSUPPORTED' });
});

test('forward confirmed baseline is refused before dispatch', async () => {
    const h = harness({ links: [{ _id: NEIGHBOR, portalNode: B, bridgeNode: C,
        active: true, status: 'online', mode: 'forward' }] });
    await assert.rejects(h.service.queue(input([LINK, NEIGHBOR])), { code: 'CLASSIC_DEPLOY_UNSUPPORTED' });
    assert.equal(h.calls.remote.length, 0);
    assert.equal(h.state().replacementReservation, undefined);
});

test('scope is reconstructed from confirmed neighbors, never unrelated pending or foreign links', async () => {
    const links = [
        { _id: NEIGHBOR, portalNode: B, bridgeNode: C, active: true, status: 'staged', mode: 'reverse' },
        { _id: PENDING, portalNode: A, bridgeNode: C, active: true, status: 'pending', mode: 'reverse' },
        { _id: FOREIGN, portalNode: '507f1f77bcf86cd799439051', bridgeNode: '507f1f77bcf86cd799439052',
            active: true, status: 'online', mode: 'reverse' },
    ];
    const good = harness({ links });
    await good.service.queue(input([LINK, NEIGHBOR]));
    assert.deepEqual(good.calls.remote[0].baselineLinkIds, [NEIGHBOR]);
    for (const ids of [[LINK], [LINK, NEIGHBOR, PENDING], [LINK, NEIGHBOR, FOREIGN]]) {
        const h = harness({ links });
        await assert.rejects(h.service.queue(input(ids)), { code: 'CLASSIC_DEPLOY_SCOPE_CHANGED' });
        assert.equal(h.calls.remote.length, 0);
        assert.equal(h.state().replacementReservation, undefined);
    }
});

test('global, reconcile and replacement are unsupported without acquiring or dispatching', async () => {
    const h = harness();
    await assert.rejects(h.service.deploy({ expectedTopologyRevision: 7 }), { code: 'CLASSIC_DEPLOY_UNSUPPORTED' });
    for (const kind of ['domain.reconcile', 'link.replace']) {
        await assert.rejects(h.service.queue({ ...input(), scope: { ...input().scope, kind } }),
            { code: 'CLASSIC_DEPLOY_UNSUPPORTED' });
    }
    assert.equal(h.calls.remote.length, 0); assert.equal(h.calls.updates.length, 0);
});

test('stale revision and non-quiescent or uninitialized state refuse before reservation', async () => {
    for (const state of [{ revision: 8 }, { topologyAdmissionCount: undefined }, { remoteAdmissionCount: undefined },
        { topologyAdmissionCount: 1 }, { remoteAdmissionCount: 1 }, { remoteDrain: { ownerToken: 'foreign', epoch: 1 } },
        { replacementReservation: { ownerToken: 'foreign', epoch: 1 } }, { replacementEpoch: undefined }]) {
        const h = harness({ state });
        await assert.rejects(h.service.queue(input()), { code: state.revision ? 'STALE_TOPOLOGY_REVISION' : 'CLASSIC_DEPLOY_BUSY' });
        assert.equal(h.calls.remote.length, 0); assert.equal(h.calls.updates.length, 0);
        assert.deepEqual(h.calls.preview, []);
    }
});

test('active or orphaned operations, intent backlog, malformed queue counters and every lock veto admission', async () => {
    for (const overrides of [{ operations: [{ status: 'queued' }] }, { operations: [{}] },
        { operations: [{ status: 'failed', heldTopologyAdmission: true }] },
        { intents: [{ status: 'admitted' }] }, { intents: [{ status: 'blocked' }] },
        { queues: [{ outstanding: 1 }] }, { queues: [{}] }, { locks: [{ leaseUntil: new Date(0) }] }]) {
        const h = harness(overrides);
        await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_BUSY' });
        assert.equal(h.calls.remote.length, 0); assert.equal(h.calls.updates.length, 0);
        assert.deepEqual(h.calls.preview, []);
    }
});

test('fresh installed/installing/desired L2TP state and enabled route paths block classic', async () => {
    const cases = [
        { relays: [{ node: A, status: 'installed' }] }, { relays: [{ node: B, status: 'installing' }] },
        { relays: [{ node: A, status: 'error', desiredState: 'installed' }] },
        { groups: [{ paths: [{ enabled: true, linkIds: [LINK] }] }] },
        { links: [{ _id: PENDING, portalNode: B, bridgeNode: C, active: true, status: 'pending' }],
            groups: [{ paths: [{ enabled: true, linkIds: [PENDING] }] }] },
    ];
    for (const overrides of cases) {
        const h = harness(overrides);
        assert.equal(h.service.requiresL2tpIngressPreparation, false);
        await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_IN_USE' });
        assert.equal(h.calls.remote.length, 0); assert.equal(h.state().replacementReservation, undefined);
    }
});

test('ownership veto is checked before acquisition without poisoning the singleton', async () => {
    const h = harness({ ownerVeto: true });
    await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_OWNER_VETO' });
    assert.equal(h.calls.remote.length, 0); assert.equal(h.state().replacementReservation, undefined);
});

test('only exact checked completion releases; unknown results and raw errors remain fenced and redacted', async () => {
    for (const work of [() => undefined, () => false, () => ({ success: true }),
        () => ({ success: true, remoteQuiescent: false }),
        () => ({ success: true, remoteQuiescent: true, operationId: 'fake' }),
        () => { throw new Error('password=do-not-leak'); }]) {
        const h = harness({ work });
        await assert.rejects(h.service.queue(input()), error => {
            assert.equal(error.code, 'CLASSIC_DEPLOY_UNCERTAIN');
            assert.doesNotMatch(error.message, /password|do-not-leak/); return true;
        });
        assert.ok(h.state().replacementReservation); assert.equal(h.calls.updates.length, 1);
    }
});

test('foreign replacement token or epoch cannot be released after successful remote callback', async () => {
    for (const mutate of [state => { state.replacementReservation.ownerToken = 'foreign'; },
        state => { state.replacementReservation.epoch++; }, state => { state.replacementEpoch++; }]) {
        const h = harness({ work: ({ state, result }) => { mutate(state); return result; } });
        await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_FENCE_LOST' });
        assert.ok(h.state().replacementReservation); assert.equal(h.calls.updates.length, 1);
    }
    const failed = harness({ releaseFailure: true });
    await assert.rejects(failed.service.queue(input()), { code: 'CLASSIC_DEPLOY_FENCE_LOST' });
    assert.ok(failed.state().replacementReservation);
});

test('nonexpiring reservation is held across pending work and excludes concurrent deploy', async () => {
    let finish; let entered;
    const started = new Promise(resolve => { entered = resolve; });
    const wait = new Promise(resolve => { finish = resolve; });
    const h = harness({ work: async ({ result }) => { entered(); await wait; return result; } });
    const pending = h.service.queue(input());
    await started;
    assert.deepEqual(Object.keys(h.state().replacementReservation).sort(), ['epoch', 'ownerToken']);
    await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_BUSY' });
    finish(); await pending;
    assert.equal(h.calls.remote.length, 1); assert.equal(h.state().replacementReservation, undefined);
});

test('malformed fence readback cannot authorize dispatch merely because a query returned a row', async () => {
    const h = harness();
    const findOne = h.dependencies.CascadeTopologyState.findOne;
    h.dependencies.CascadeTopologyState.findOne = filter => {
        const query = findOne(filter);
        const lean = query.lean;
        query.lean = async () => { const row = await lean(); return { ...row, topologyAdmissionCount: [0] }; };
        return query;
    };
    await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_FENCE_LOST' });
    assert.equal(h.calls.remote.length, 0); assert.ok(h.state().replacementReservation);
});

test('unknown reservation commit never dispatches or attempts speculative release', async () => {
    const h = harness();
    const connection = h.dependencies.CascadeTopologyState.db;
    const transaction = connection.transaction.bind(connection);
    connection.transaction = async (...args) => {
        const result = await transaction(...args);
        if (h.state().replacementReservation) throw new Error('unknown commit password=secret');
        return result;
    };
    await assert.rejects(h.service.queue(input()), { code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE' });
    assert.ok(h.state().replacementReservation); assert.equal(h.calls.remote.length, 0);
    assert.equal(h.calls.updates.length, 1);
});

test('graph drift after reservation and disabled/forward targets refuse under the acquired fence', async () => {
    for (const change of [{ active: false }, { mode: 'forward' }]) {
        const h = harness();
        const connection = h.dependencies.CascadeTopologyState.db;
        const transaction = connection.transaction.bind(connection);
        connection.transaction = async (...args) => {
            const result = await transaction(...args);
            if (h.state().replacementReservation) Object.assign(h.rows.CascadeLink[0], change); return result;
        };
        await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_UNSUPPORTED' });
        assert.ok(h.state().replacementReservation); assert.equal(h.calls.remote.length, 0);
    }
});

test('request and server mode pins remain immutable across asynchronous acquisition', async () => {
    const h = harness();
    const request = input();
    const connection = h.dependencies.CascadeTopologyState.db;
    const transaction = connection.transaction.bind(connection);
    connection.transaction = async (...args) => {
        const result = await transaction(...args);
        request.scope.linkId = FOREIGN; request.scope.linkIds.push(FOREIGN);
        h.dependencies.env.PANEL_DOMAIN = 'lm2.infograd.online';
        h.dependencies.env.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED = 'true';
        return result;
    };
    const result = await h.service.queue(request);
    assert.equal(result.executionMode, 'classic');
    assert.equal(h.calls.remote[0].linkId, LINK);
    assert.deepEqual(h.calls.remote[0].baselineLinkIds, []);
});

test('malformed request and scope identifiers refuse before any acquisition', async () => {
    for (const bad of [{ ...input(), expectedTopologyRevision: '7' }, { ...input(), target: 'production' },
        { ...input(), scope: { ...input().scope, linkId: [LINK] } }, input([LINK, LINK]),
        { ...input(), scope: { ...input().scope, linkIds: [FOREIGN] } },
        { ...input(), scope: { ...input().scope, hostIdentity: 'lm1.infograd.online' } }]) {
        const h = harness();
        await assert.rejects(h.service.queue(bad), { code: 'INVALID_REQUEST' });
        assert.equal(h.calls.remote.length, 0); assert.equal(h.calls.updates.length, 0);
    }
});

test('typed receipt permits target main cleanup only instead of its preserved profile', async () => {
    const h = harness({ work: ({ result }) => {
        result.receipt.preservedProfiles.pop();
        result.receipt.profiles.push({ nodeId: B, path: MAIN, beforeSha256: 'e'.repeat(64), sha256: 'f'.repeat(64) });
        return result;
    } });
    assert.deepEqual(await h.service.queue(input()), { status: 'succeeded', executionMode: 'classic', topologyRevision: 7 });
});

test('missing, mismatched or malformed typed receipts retain the exact fence', async () => {
    const mutations = [r => { delete r.receipt; }, r => { r.operationId = 'fake'; },
        r => { r.receipt.kind = 'other'; }, r => { r.receipt.linkId = FOREIGN; },
        r => { r.receipt.topologyRevision = 8; }, r => { r.receipt.nodeIds = [A, C]; },
        r => { r.receipt.nodeIds.reverse(); }, r => { r.receipt.preservedLinkIds = [NEIGHBOR]; },
        r => { r.receipt.tunnelEstablished = false; }, r => { r.receipt.profiles.pop(); },
        r => { r.receipt.profiles[0].sha256 = ['b'.repeat(64)]; },
        r => { r.receipt.profiles[0].beforeSha256 = null; },
        r => { r.receipt.profiles[0].path = TRANSIT; },
        r => { r.receipt.profiles.push({ ...r.receipt.profiles[0] }); },
        r => { r.receipt.preservedProfiles.pop(); },
        r => { r.receipt.preservedProfiles[0].sha256 = 'secret'; },
        r => { r.receipt.preservedProfiles[0].nodeId = C; }];
    for (const mutate of mutations) {
        const h = harness({ work: ({ result }) => { mutate(result); return result; } });
        await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_UNCERTAIN' });
        assert.ok(h.state().replacementReservation); assert.equal(h.calls.updates.length, 1);
    }
});

test('retained uninstalled L2TP group is not installed path authority and stays untouched', async () => {
    for (const desiredState of ['not_installed', 'absent']) {
        const h = harness({ relays: [{ node: A, desiredState, status: 'not_installed', routeGroup: GROUP }],
            groups: [{ _id: GROUP, name: 'l2tp-prod-pilot', mode: 'forward', strategy: 'priority-failover',
                paths: [{ pathKey: 'pilot-main', linkIds: [LINK], priority: 1, enabled: true }] }] });
        const before = structuredClone(h.rows);
        await h.service.queue(input());
        assert.equal(h.calls.remote.length, 1); assert.deepEqual(h.rows, before);
    }
});

test('active, unknown and installed group references veto even from a non-endpoint owner', async () => {
    for (const relay of [{ node: C, routeGroup: GROUP, status: 'installed' },
        { node: C, routeGroup: GROUP, status: 'installing' },
        { node: C, routeGroup: GROUP, status: 'error', desiredState: 'installed' },
        { node: C, routeGroup: GROUP, status: 'removing', desiredState: 'absent' },
        { node: C, routeGroup: GROUP, status: 'unknown', desiredState: 'absent' },
        { node: C, installedRouteGroup: GROUP, routeGroup: FOREIGN, status: 'installed' }]) {
        const h = harness({ relays: [relay], groups: [{ _id: GROUP, paths: [{ linkIds: [LINK], enabled: true }] }] });
        await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_IN_USE' });
        assert.equal(h.calls.remote.length, 0); assert.equal(h.state().replacementReservation, undefined);
    }
});

test('missing, malformed and unknown retained group ownership remain conservative', async () => {
    for (const group of [{ _id: GROUP }, { _id: GROUP, paths: [null] },
        { _id: GROUP, paths: [{ linkIds: LINK }] }, { _id: GROUP, paths: [{ linkIds: [LINK] }] }]) {
        const h = harness({ groups: [group] });
        await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_IN_USE' });
        assert.equal(h.calls.remote.length, 0);
    }
});

test('only an exact allowlisted target can acquire the global reservation', async () => {
    for (const value of [FOREIGN, undefined, '', `${LINK},`, LINK.toUpperCase(), ` ${LINK}`,
        `${LINK},${LINK}`, Array(65).fill(LINK).join(',')]) {
        const h = harness({ env: { CLASSIC_TOPOLOGY_PRODUCTION_LINK_IDS: value } });
        await assert.rejects(h.service.queue(input()));
        assert.equal(h.calls.updates.length, 0); assert.equal(h.calls.remote.length, 0);
    }
});

test('DB-only admission refusals leave the singleton epoch and reservation untouched', async () => {
    for (const overrides of [
        { env: lifecycleEnv },
        { env: lifecycleEnv, ownerVeto: true },
        { relays: [{ node: A, status: 'installed' }] },
    ]) {
        const h = harness(overrides);
        await assert.rejects(h.service.queue(input()));
        assert.equal(h.calls.remote.length, 0);
        assert.equal(h.calls.updates.length, 0);
        assert.equal(h.state().replacementEpoch, 2);
        assert.equal(h.state().replacementReservation, undefined);
    }
});

function removed(coreInput = { linkId: LINK, expectedTopologyRevision: 7, baselineLinkIds: [] }) {
    const result = completed(coreInput);
    result.receipt.kind = 'classic-scoped-reverse-removal';
    delete result.receipt.tunnelEstablished;
    result.receipt.targetAbsent = true;
    result.receipt.profiles.forEach(p => { p.changed = true; });
    result.receipt.preservedProfiles.forEach(p => { p.beforeSha256 = p.sha256; p.changed = false; });
    return result;
}
const deletion = () => ({ expectedTopologyRevision: 7, linkId: LINK });

test('checked DELETE keeps DB link through SSH then settles deletion and exact revision atomically', async () => {
    const h = harness({ links: [{ _id: NEIGHBOR, portalNode: C, bridgeNode: B,
        mode: 'reverse', active: true, status: 'online' }] });
    const result = await h.service.deleteLink(deletion());
    assert.deepEqual(result, { revision: 8, deployedRevision: 5 });
    assert.deepEqual(h.calls.remote, [{ linkId: LINK, expectedTopologyRevision: 7, baselineLinkIds: [NEIGHBOR] }]);
    assert.deepEqual(h.rows.CascadeLink.map(l => l._id), [NEIGHBOR]);
    assert.equal(h.state().revision, 8);
    assert.equal(h.state().deployedRevision, 5);
    assert.equal(h.state().replacementReservation, undefined);
    assert.equal(h.state().classicLifecycleAttempt, undefined);
    assert.equal(h.state().classicLifecycleLastSettlement.action, 'link.delete');
});

test('durable server grant authorizes saved link through a reconstructed public service', async () => {
    const h = harness({ env: lifecycleEnv });
    h.rows.CascadeLink[0].classicLifecycleGrant = issueClassicLifecycleGrant(h.rows.CascadeLink[0], h.dependencies.env);
    const restarted = createClassicScopedCascadeDeploymentService(h.dependencies);
    assert.equal((await restarted.queue(input())).status, 'succeeded');
    assert.equal(h.calls.remote.length, 1);
});

test('durable grants never authorize arbitrary pending, forged, rebound or unknown-status links', async () => {
    for (const change of [l => { delete l.classicLifecycleGrant; }, l => { l.classicLifecycleGrant = '00'.repeat(32); },
        l => { l.bridgeNode = C; }, l => { l.mode = 'forward'; }, l => { l.active = false; },
        l => { l.status = 'unknown'; }]) {
        const h = harness({ env: lifecycleEnv });
        h.rows.CascadeLink[0].classicLifecycleGrant = issueClassicLifecycleGrant(h.rows.CascadeLink[0], h.dependencies.env);
        change(h.rows.CascadeLink[0]);
        await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_UNSUPPORTED' });
        assert.equal(h.calls.updates.length, 0); assert.equal(h.calls.remote.length, 0);
    }
    for (const key of [undefined, 'ab'.repeat(31), 'AB'.repeat(32), ['ab'.repeat(32)]]) {
        const h = harness({ env: { ...lifecycleEnv, CLASSIC_TOPOLOGY_LIFECYCLE_SIGNING_KEY: key } });
        await assert.rejects(h.service.queue(input()), { code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE' });
        assert.equal(h.calls.updates.length, 0);
    }
});

test('saved grant permits manual replay of known statuses but create receipt remains one-use', async () => {
    for (const status of ['pending', 'error', 'offline', 'online', 'deployed', 'staged']) {
        const h = harness({ env: lifecycleEnv });
        Object.assign(h.rows.CascadeLink[0], { status });
        h.rows.CascadeLink[0].classicLifecycleGrant = issueClassicLifecycleGrant(h.rows.CascadeLink[0], h.dependencies.env);
        await h.service.queue(input());
        await createClassicScopedCascadeDeploymentService(h.dependencies).queue(input());
        assert.equal(h.calls.remote.length, 2);
    }
    const h = harness({ env: lifecycleEnv });
    const cap = h.service.beginCreatedLinkCapability({ linkId: LINK });
    h.service.confirmCreatedLinkCapability(cap, { linkId: LINK, expectedTopologyRevision: 7 });
    await assert.rejects(h.service.queueCreatedLink(input(), cap), { code: 'CLASSIC_DEPLOY_UNSUPPORTED' });
    assert.equal(h.calls.updates.length, 0, 'lifecycle mode requires durable authority even with private receipt');
    h.rows.CascadeLink[0].classicLifecycleGrant = issueClassicLifecycleGrant(h.rows.CascadeLink[0], h.dependencies.env);
    await assert.rejects(h.service.queueCreatedLink(input(), cap), { code: 'CLASSIC_DEPLOY_UNSUPPORTED' });
});

test('DELETE uncertain/throwing/malformed completion retains DB link, attempt and exact nonexpiring reservation', async () => {
    const mutations = [r => { r.remoteQuiescent = false; }, r => { delete r.receipt; },
        r => { r.receipt.targetAbsent = false; }, r => { r.receipt.kind = 'classic-scoped-reverse'; },
        r => { r.receipt.linkId = FOREIGN; }, r => { r.receipt.topologyRevision++; },
        r => { r.receipt.nodeIds = [A, C]; }, r => { r.receipt.preservedLinkIds = [NEIGHBOR]; },
        r => { r.receipt.profiles.pop(); }, r => { r.receipt.profiles.push(r.receipt.profiles[0]); },
        r => { r.receipt.profiles[0].changed = false; }, r => { r.receipt.profiles[0].beforeSha256 = 'bad'; },
        r => { r.receipt.preservedProfiles[0].beforeSha256 = 'a'.repeat(64); },
        r => { r.receipt.preservedProfiles.pop(); }, r => { r.receipt.preservedProfiles[0].changed = true; },
        r => { r.receipt.profiles[0].nodeId = C; }, r => { r.receipt.extra = true; },
        () => { throw Error('password=redact'); }];
    for (const mutate of mutations) {
        const h = harness({ removeWork: ({ result }) => { mutate(result); return result; } });
        await assert.rejects(h.service.deleteLink(deletion()), error => {
            assert.equal(error.code, 'CLASSIC_DEPLOY_UNCERTAIN'); assert.doesNotMatch(error.message, /password/); return true;
        });
        assert.equal(h.rows.CascadeLink.length, 1); assert.equal(h.state().revision, 7);
        const attempt = h.state().classicLifecycleAttempt;
        assert.equal(attempt.action, 'link.delete'); assert.equal(attempt.phase, 'dispatching');
        assert.equal(attempt.linkId, LINK); assert.equal(attempt.epoch, 3);
        assert.deepEqual(attempt.nodeIds, [A, B]);
        assert.equal(attempt.topologyRevision, 7); assert.equal(attempt.deployedRevision, 5);
        assert.equal(h.state().replacementReservation.ownerToken, `classic-deploy:${attempt.operationId}`);
        await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_BUSY' });
        await assert.rejects(h.service.deleteLink(deletion()), { code: 'CLASSIC_DEPLOY_BUSY' });
        assert.equal(h.calls.remote.length, 1); assert.equal(h.calls.updates.length, 1);
    }
});

test('DELETE never infers remote absence from pending status and accepts only a checked unchanged receipt', async () => {
    const h = harness({ removeWork: ({ result }) => {
        result.receipt.profiles.forEach(p => { p.sha256 = p.beforeSha256; p.changed = false; });
        return result;
    } });
    assert.equal(h.rows.CascadeLink[0].status, 'pending');
    assert.deepEqual(await h.service.deleteLink(deletion()), { revision: 8, deployedRevision: 5 });
    assert.equal(h.calls.remote.length, 1);
});

test('DELETE performs no reservation for DB refusal or caller-supplied scope/bypass fields', async () => {
    for (const overrides of [{ state: { revision: 8 } }, { ownerVeto: true },
        { relays: [{ node: A, status: 'installed' }] }, { env: lifecycleEnv }]) {
        const h = harness(overrides); await assert.rejects(h.service.deleteLink(deletion()));
        assert.equal(h.calls.remote.length, 0); assert.equal(h.calls.updates.length, 0);
    }
    for (const bad of [null, { ...deletion(), linkId: [LINK] }, { ...deletion(), scope: {} },
        { ...deletion(), baselineLinkIds: [] }, { ...deletion(), remoteQuiescent: true },
        { ...deletion(), expectedTopologyRevision: '7' }]) {
        const h = harness(); await assert.rejects(h.service.deleteLink(bad), { code: 'INVALID_REQUEST' });
        assert.equal(h.calls.updates.length, 0);
    }
});

test('DELETE foreign owner, epoch, revision or attempt identity cannot settle or erase DB link', async () => {
    for (const mutate of [s => { s.replacementReservation.ownerToken = 'foreign'; }, s => { s.replacementEpoch++; },
        s => { s.revision++; }, s => { s.classicLifecycleAttempt.operationId = 'foreign'; },
        s => { s.classicLifecycleAttempt.nodeIds = [A, C]; }]) {
        const h = harness({ removeWork: ({ state, result }) => { mutate(state); return result; } });
        await assert.rejects(h.service.deleteLink(deletion()), { code: 'CLASSIC_DEPLOY_FENCE_LOST' });
        assert.equal(h.rows.CascadeLink.length, 1); assert.ok(h.state().replacementReservation);
    }
});

test('DELETE remains fenced across pending remote work and excludes apply/delete successors', async () => {
    let finish, entered;
    const started = new Promise(r => { entered = r; }); const wait = new Promise(r => { finish = r; });
    const h = harness({ removeWork: async ({ result }) => { entered(); await wait; return result; } });
    const pending = h.service.deleteLink(deletion()); await started;
    assert.equal(h.rows.CascadeLink.length, 1); assert.equal(h.state().classicLifecycleAttempt.phase, 'dispatching');
    await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_BUSY' });
    await assert.rejects(h.service.deleteLink(deletion()), { code: 'CLASSIC_DEPLOY_BUSY' });
    finish(); await pending; assert.equal(h.calls.remote.length, 1);
});

test('fresh operation veto after claim refuses dispatch while retaining its admitted attempt', async () => {
    const h = harness();
    const connection = h.dependencies.CascadeTopologyState.db;
    const transaction = connection.transaction.bind(connection);
    connection.transaction = async (...args) => {
        const result = await transaction(...args);
        if (h.state().replacementReservation) h.rows.TopologyOperation.push({ status: 'committing' }); return result;
    };
    await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_BUSY' });
    assert.equal(h.calls.remote.length, 0); assert.ok(h.state().classicLifecycleAttempt);
});

test('DELETE confirmation requires the full exact settlement identity, not only an operation UUID', async () => {
    const h = harness();
    const findOne = h.dependencies.CascadeTopologyState.findOne;
    h.dependencies.CascadeTopologyState.findOne = filter => {
        const q = findOne(filter), lean = q.lean;
        if (filter['classicLifecycleLastSettlement.operationId']) q.lean = async () => {
            const row = await lean(); row.classicLifecycleLastSettlement.action = 'link.apply'; return row;
        };
        return q;
    };
    await assert.rejects(h.service.deleteLink(deletion()), { code: 'CLASSIC_DEPLOY_FENCE_LOST' });
});

test('sparse removal node IDs are not a typed completion receipt', async () => {
    const h = harness({ removeWork: ({ result }) => { result.receipt.nodeIds = [A, ,]; return result; } });
    await assert.rejects(h.service.deleteLink(deletion()), { code: 'CLASSIC_DEPLOY_UNCERTAIN' });
    assert.ok(h.state().replacementReservation); assert.equal(h.rows.CascadeLink.length, 1);
});

test('occupied preserved source port refuses before claim and leaves pending row editable', async () => {
    const h = harness({ transit: { inbounds: [{ tag: 'conn-down-355c34b8', port: 10086 },
        { tag: 'conn-down-355c3623', port: 10087 }] } });
    const before = structuredClone(h.rows);
    await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_PORT_CONFLICT' });
    assert.deepEqual(h.rows, before);
    assert.equal(h.calls.updates.length, 0); assert.equal(h.calls.remote.length, 0);
    assert.equal(h.state().replacementEpoch, 2); assert.equal(h.state().classicLifecycleAttempt, undefined);
    assert.ok(h.calls.preview.includes('connect')); assert.ok(h.calls.preview.includes('disconnect'));
});

test('runtime-only source listener refuses before claim', async () => {
    const h = harness({ sockets: 'LISTEN 0 128 0.0.0.0:10086 0.0.0.0:* users:(("foreign",pid=991,fd=3))\n' });
    await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_PORT_CONFLICT' });
    assert.equal(h.calls.updates.length, 0); assert.equal(h.calls.remote.length, 0);
});

test('failed read-only inspection never claims writer effects or ownership', async () => {
    const h = harness({ previewError: true });
    await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_PORT_CHECK_UNAVAILABLE' });
    assert.equal(h.calls.updates.length, 0); assert.equal(h.calls.remote.length, 0);
    assert.equal(h.state().replacementEpoch, 2); assert.equal(h.rows.CascadeLink[0].status, 'pending');
});

test('post-claim port codes and adapter not-dispatched flags cannot authorize safe refusal or release', async () => {
    for (const code of ['CLASSIC_DEPLOY_PORT_CONFLICT', 'CLASSIC_DEPLOY_PORT_CHECK_UNAVAILABLE', 'CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED']) {
        const h = harness({ work: () => { throw Object.assign(Error('password=secret'), { code, notDispatched: true }); } });
        await assert.rejects(h.service.queue(input()), { code: 'CLASSIC_DEPLOY_UNCERTAIN' });
        assert.ok(h.state().replacementReservation); assert.ok(h.state().classicLifecycleAttempt);
        assert.equal(h.calls.updates.length, 1);
        assert.deepEqual(Object.keys(h.calls.diagnostic).sort(), ['event', 'internalCode', 'linkId', 'operationId', 'phase']);
        assert.equal(h.calls.diagnostic.internalCode, code); assert.equal(h.calls.diagnostic.linkId, LINK);
        assert.equal(h.calls.diagnostic.phase, 'held-dispatch-or-settlement');
        assert.doesNotMatch(JSON.stringify(h.calls.diagnostic), /password|secret|notDispatched/);
    }
});

module.exports = { harness, input, completed, LINK, A, B, C, NEIGHBOR, PENDING, FOREIGN };
