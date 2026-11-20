'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const generator = require('../configGenerator');
const { createRebuildService } = require('../rebuildService');
const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');

// Exercise the actual builder and protected-interface gate; only inventory and
// transport are in memory. No saved node config or real subscription is used.
function fixture(t, tag = 'vless-in') {
    t.mock.method(generator, 'buildPanelInlineCertificate', () => null);
    const node = { _id: 'exit', type: 'xray', active: true, cascadeRole: 'bridge', port: 24443,
        xray: { inboundTag: tag, apiPort: 23001, security: 'reality', transport: 'tcp',
            realityDest: 'cover.invalid:443', realitySni: ['cover.invalid'],
            realityPrivateKey: Buffer.alloc(32, 1).toString('base64url'), realityShortIds: ['aabb'] } };
    const original = JSON.parse(generator.generateXrayConfigWithApi(node, []));
    const model = rows => ({ find: () => ({ select() { return this; }, lean: async () => structuredClone(rows) }) });
    const f = { original, writes: 0 };
    const write = () => { f.writes++; assert.fail('unexpected dispatch'); };
    const service = createRebuildService({ Node: model([node]), Link: model([]), State: model([]),
        locks: { run: fn => fn(async () => {}) }, assertNoRelayAccountIntent: async () => {},
        env: { C3_REBUILD_ENABLED: 'true' }, cache: {},
        sync: { _getUsersForNode: async () => [] }, connect: () => ({ requireSupportedCore: async () => {},
            read: async profile => profile === 'main' ? structuredClone(original) : null,
            stagePair: write, putPair: write, close: async () => {} }),
        compose(input) {
            const profiles = composeRebuildProfiles(input);
            f.candidate = profiles.find(p => p.profile === 'main').config;
            return profiles;
        } });
    return Object.assign(f, { execute: preview => service.execute({ nodeId: node._id, preview }) });
}

for (const tag of ['vless-in', 'subscriber-custom']) {
    test(`empty subscriber list preserves the managed bridge MAIN ${tag}`, async t => {
        const f = fixture(t, tag);
        const result = await f.execute(true);
        const main = result.nodes[0].profiles.find(p => p.profile === 'main');
        assert.equal(main.protectedChanged, false, `managed ${tag} must not be removed from MAIN`);
        assert.equal(result.allowed, true);
        assert.deepEqual(f.candidate.inbounds, f.original.inbounds);
        assert.equal(f.writes, 0);
    });
}

test('bridge with only local API does not acquire a port even with complete REALITY settings', async t => {
    const f = fixture(t);
    f.original.inbounds = f.original.inbounds.filter(i => i.tag === 'API_INBOUND');
    assert.equal((await f.execute(true)).allowed, true);
    assert.deepEqual(f.candidate.inbounds.map(i => [i.tag, i.listen, i.port]), [['API_INBOUND', '127.0.0.1', 23001]]);
    assert.equal(f.writes, 0);
});

test('bridge MAIN drift is not adopted as desired state and vetoes every write', async t => {
    const f = fixture(t);
    const served = f.original.inbounds.find(i => i.tag === 'vless-in');
    const desired = structuredClone(served);
    for (const change of [i => { i.port++; }, i => { i.streamSettings.realitySettings.shortIds = ['ccdd']; },
        i => { i.streamSettings.realitySettings.privateKey = Buffer.alloc(32, 2).toString('base64url'); },
        i => { i.settings.clients = [{ id: '00000000-0000-4000-8000-000000000001', email: 'fixture' }]; }]) {
        Object.assign(served, structuredClone(desired));
        change(served);
        const result = await f.execute(true);
        assert.equal(result.allowed, false);
        assert.equal(result.nodes[0].profiles.find(p => p.profile === 'main').protectedChanged, true);
        assert.deepEqual(f.candidate.inbounds.find(i => i.tag === desired.tag), desired);
        await assert.rejects(f.execute(false), { code: 'REBUILD_CLIENT_CHANGE' });
        assert.equal(f.writes, 0);
    }
});

test('unmanaged VLESS inbound is not a source for the generated MAIN', async t => {
    const f = fixture(t);
    f.original.inbounds.find(i => i.tag === 'vless-in').tag = 'foreign';
    assert.equal((await f.execute(true)).allowed, false);
    assert.deepEqual(f.candidate.inbounds.map(i => i.tag), ['API_INBOUND']);
    await assert.rejects(f.execute(false), { code: 'REBUILD_CLIENT_CHANGE' });
    assert.equal(f.writes, 0);
});
