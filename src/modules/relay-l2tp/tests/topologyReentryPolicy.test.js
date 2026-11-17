'use strict';
process.env.PANEL_DOMAIN ||= 'test.infograd.online';
process.env.ACME_EMAIL ||= 'test@example.invalid';
process.env.ENCRYPTION_KEY ||= 'test-encryption-key-32-characters-long';
process.env.SESSION_SECRET ||= 'local-reentry-test';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const policy = require('../services/topologyReentryPolicy');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST, PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const { createTopologyTestActivationRouter } = require('../../../routes/topologyTestActivation');
const { createCascadeTopologyDeployRouter } = require('../../../routes/cascadeTopologyDeploy');
test.after(() => require('../../../services/sshPoolService').closeAll());
const node = '111111111111111111111111';
const query = value => ({ select() { return this; }, read(v) { assert.equal(v, 'primary'); return this; },
    readConcern(v) { assert.equal(v, 'majority'); return this; }, maxTimeMS(v) { assert.equal(v, 5000); return this; },
    lean: async () => structuredClone(value) });
function models(owner, { binding = false, operation = false } = {}) {
    return { TopologyConfigOwner: { find: () => query([owner]), findOne: () => query(owner) },
        TopologyExecutionBinding: { findOne: filter => { assert.equal(filter.nodeId, node); return query(binding ? { _id: 'history-binding' } : null); } },
        TopologyOperation: { findOne: filter => { assert.deepEqual(filter, { $or: [{ 'nodes.node': node }, { resourceNodeIds: node }] }); return query(operation ? { _id: 'history-operation' } : null); } } };
}
const handedBack = () => ({ node, owner: 'classic', handbackReceipt: { fromGeneration: 'prior', toGeneration: 'current' } });

test('first active epoch and fresh classic are not blocked by historical work', async () => {
    for (const owner of [{ node, owner: 'topology' }, { node, owner: 'classic' }]) {
        assert.deepEqual(await policy.readOwnerReentryRestriction(owner, models(owner, { binding: true, operation: true })), { blocked: false });
    }
});
test('zero-business public handback remains eligible without deleting any history', async () => {
    const owner = handedBack(), before = structuredClone(owner), m = models(owner);
    assert.deepEqual(await policy.readBusinessReentryRestriction({ executionContext: TEST, ...m }), { blocked: false });
    await policy.assertOwnerReentryAllowed(owner, m);
    assert.deepEqual(owner, before);
});
test('settled metadata, immutable binding or accepted operation after handback each prohibit reentry', async () => {
    for (const change of ['settled', 'binding', 'operation']) {
        const owner = { ...handedBack(), ...(change === 'settled' ? { lastSettledOperation: 'old-operation' } : {}) };
        const before = structuredClone(owner), m = models(owner, { [change]: true });
        assert.deepEqual(await policy.readOwnerReentryRestriction(owner, m), { blocked: true, code: policy.CODE, message: policy.MESSAGE });
        await assert.rejects(policy.assertOwnerReentryAllowed(owner, m), { code: policy.CODE, message: policy.MESSAGE });
        assert.deepEqual(owner, before, 'the restriction cannot reset ownership or history');
    }
});
test('normal production entry rejects business reentry before capture or public adoption', async () => {
    const owner = { ...handedBack(), executionContext: PROD, generation: 'classic-generation', nodeIdentity: { machineId: 'existing' }, lastSettledOperation: 'existing-operation' };
    const m = { ...models(owner), TopologyExecutionEnrollment: { findOne: () => query({ _id: 'permanent-alias' }) } };
    const plan = { executionContext: PROD, mode: 'enroll', nodes: [{ nodeId: node, targetProfile: 'xray-main',
        acceptedOwner: { owner: 'classic', generation: owner.generation }, nodeIdentity: owner.nodeIdentity }] };
    const lifecycle = { executionContext: PROD, withVerifiedMaintenance() { assert.fail('adoption forbidden'); },
        run() { assert.fail('business reentry refusal must not acquire physical exclusion'); }, withCapturedOwnerEnrollment: async (work, preflight) => {
            await preflight(plan, async () => {}); assert.fail('capture forbidden');
        } };
    await assert.rejects(require('../services/productionOwnerEntry').enrollProductionOwners({ lifecycle, store: {}, models: m }), { code: policy.CODE });
});
for (const lateBusiness of [false, true]) test(`ordinary production ROOT checks real policy before first physical attach and rechecks entry: late=${lateBusiness}`, async t => {
    const owner = { ...handedBack(), ...(lateBusiness ? {} : { lastSettledOperation: 'historical-operation' }) };
    const m = models(owner), events = [], counts = { factory: 0, enter: 0, attach: 0, capture: 0 };
    const Owner = require('../../../models/topologyConfigOwnerModel');
    t.mock.method(Owner, 'find', () => { events.push('policy'); return query([owner]); });
    const Operation = require('../models/topologyOperationModel'), Binding = require('../models/topologyExecutionBindingModel');
    t.mock.method(Operation, 'findOne', () => query(null));
    t.mock.method(Binding, 'findOne', () => query(null));
    t.mock.method(require('../services/productionAdmissionReadiness'), 'verifyProductionStartupSchema', async () => {
        events.push('schema'); owner.lastSettledOperation = 'arrived-after-preflight';
    });
    const lifecycle = { async enrollProductionOwners() {
        return require('../services/productionOwnerEntry').enrollProductionOwners({ models: m, store: {}, lifecycle: {
            executionContext: PROD, withVerifiedMaintenance() {}, run() { counts.capture++; assert.fail('ban before capture'); },
        } });
    }, start() { assert.fail('ban before consumers'); }, async stop() {} };
    const root = require('../../../modules/l2tpRuntimeLifecycleHook').createL2tpRootLifecycle({
        env: { PANEL_DOMAIN: PROD.hostIdentity, L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true' },
        createTopologyExecutionAuthority() { counts.factory++; return { admission: {}, async withHeldAuthority(_context, work) {
            counts.enter++; counts.attach++; events.push('attach'); return work({ async assertHeld() {} });
        }, close() {} }; }, productionDatabase: () => ({}), createRuntimeLifecycleHook: () => lifecycle,
    });
    try { await assert.rejects(root.startAfterDatabase(), { code: policy.CODE }); }
    finally { await root.stop(); }
    assert.equal(counts.capture, 0);
    if (!lateBusiness) assert.deepEqual(counts, { factory: 0, enter: 0, attach: 0, capture: 0 });
    else { assert.deepEqual(counts, { factory: 1, enter: 1, attach: 1, capture: 0 }); assert.equal(events[0], 'policy'); }
});
const env = { PANEL_DOMAIN: TEST.hostIdentity, L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true',
    TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', TOPOLOGY_TEST_STARTUP_MODE: 'dedicated-runtime-v1' };
const next = (req, res, next) => next();
const auth = Object.assign(next, { requireScope: () => next });
async function httpFixture(owner, history, work) {
    const m = models(owner, history), read = () => policy.readBusinessReentryRestriction({ executionContext: TEST, ...m });
    let started = 0;
    const app = express(); app.use(express.json());
    app.use('/topology', createCascadeTopologyDeployRouter({ deploymentEnv: env, models: m,
        topologyDeploymentService: { deploy() { assert.fail('policy read cannot deploy'); } },
        requireAuth: auth, requireScope: auth.requireScope, csrf: next, deployRateLimiter: next, operationStatusRateLimiter: next }));
    app.use('/activation', createTopologyTestActivationRouter({ env, auth, csrf: next,
        activeHostProvider: { getActiveHost: () => ({ readBusinessReentryRestriction: read,
            beginTestActivation() { started++; return { status: 'active' }; } }) } }));
    const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
    try { await work(async (method, route) => {
        const r = await fetch('http://127.0.0.1:' + server.address().port + route, { method,
            ...(method === 'POST' ? { headers: { 'content-type': 'application/json' }, body: '{}' } : {}) });
        return { status: r.status, body: await r.json(), headers: r.headers };
    }, () => started); } finally { await new Promise(resolve => server.close(resolve)); }
}
test('GET policy and POST activate/resume expose the same stable Russian refusal without starting work', async () => {
    await httpFixture(handedBack(), { operation: true }, async (request, started) => {
        const s = await request('GET', '/topology/activation-policy');
        assert.equal(s.status, 200); assert.equal(s.headers.get('cache-control'), 'no-store');
        assert.deepEqual(s.body, { blocked: true, code: policy.CODE, message: policy.MESSAGE });
        for (const action of ['activate', 'resume']) {
            const r = await request('POST', '/activation/' + action);
            assert.equal(r.status, 409); assert.equal(r.body.code, policy.CODE); assert.equal(r.body.message, policy.MESSAGE);
        }
        assert.equal(started(), 0);
    });
});
test('activation API preserves first-active and zero-business cases', async () => {
    for (const [owner, history] of [[{ node, owner: 'topology' }, { operation: true }], [handedBack(), {}]]) {
        await httpFixture(owner, history, async (request, started) => {
            assert.deepEqual((await request('GET', '/topology/activation-policy')).body, { blocked: false });
            assert.equal((await request('POST', '/activation/activate')).status, 200);
            assert.equal(started(), 1);
        });
    }
});
test('UI disables only repeat activation and shows safe Russian explanation in both network views', () => {
    const network = require('../../../../public/js/network');
    const button = { disabled: false }, text = { textContent: '' };
    const notice = { hidden: true, querySelector: key => key === 'button' ? button : text };
    const document = { getElementById: key => key === 'topologyReentryNotice' ? notice : null };
    network.renderBusinessReentryRestriction({ blocked: true, code: policy.CODE, message: '<script>private</script>' }, document);
    assert.equal(notice.hidden, false); assert.equal(button.disabled, true); assert.equal(text.textContent, policy.MESSAGE);
    network.renderBusinessReentryRestriction({ blocked: false }, document);
    assert.equal(notice.hidden, true); assert.equal(text.textContent, '');
    for (const view of ['network', 'nodes']) {
        const source = fs.readFileSync(path.join(__dirname, '../../../..', 'views', view + '.ejs'), 'utf8');
        assert.match(source, /id="topologyReentryNotice" hidden/);
        assert.match(source, /disabled>Повторно включить any-order<\/button>/);
    }
});
