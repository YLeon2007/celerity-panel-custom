'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { fixture, withEnv, node, link, MAIN, BRIDGE } = require('./cascadeLegacyWriterFixture');
const TEST = { PANEL_DOMAIN: 'test.infograd.online', L2TP_PRODUCTION_EXECUTION_ENABLED: 'false', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' };
for (const mode of ['reverse', 'forward']) {
    test(`post-handback explicit classic ${mode} deploy includes its own pending target, never saved-only peer`, async () => withEnv(TEST, async () => {
        const nodes = [node(1), node(2, 'bridge'), node(3, 'bridge')];
        const target = link(20, nodes[0], nodes[1], { mode, status: 'pending' });
        const saved = link(21, nodes[0], nodes[2], { mode, status: 'pending' });
        const f = fixture({ nodes, links: [target, saved] });
        const before = JSON.parse(f.generator.generateXrayConfigWithApi(nodes[0], f.users));
        f.generator.ensurePrivateIpBlock(before);f.files.set(f.key(nodes[0]._id, MAIN), JSON.stringify(before));
        const side = f.files.get(f.key(nodes[0]._id, BRIDGE));
        assert.equal(await f.cascade._deployPortalConfig(nodes[0], { selectedLinkIds: [target._id] }), true);
        const after = JSON.parse(f.files.get(f.key(nodes[0]._id, MAIN)));
        if (mode === 'reverse') {
            assert.ok(after.inbounds.some(x => x.port === target.tunnelPort), 'selected pending reverse listener must not disappear');
            assert.equal(after.inbounds.some(x => x.port === saved.tunnelPort), false);
        } else {
            assert.ok(JSON.stringify(after).includes(target.tunnelUuid), 'selected pending forward transport must not disappear');
            assert.equal(JSON.stringify(after).includes(saved.tunnelUuid), false);
        }
        assert.deepEqual(f.links.map(x => x.status), ['pending', 'pending']);
        assert.equal(f.files.get(f.key(nodes[0]._id, BRIDGE)), side);
        assert.ok(after.inbounds.some(x => x.settings?.clients?.some(u => u.id === f.users[0].xrayUuid)));
        assert.equal(f.locks.size, 0);
    }));
}
test('ordinary TEST classic Sync without an explicit selection still cannot consume saved-only pending links', async () => withEnv(TEST, async () => {
    const nodes=[node(1),node(2,'bridge')],pending=link(20,nodes[0],nodes[1],{status:'pending'}),f=fixture({nodes,links:[pending]});
    const base=JSON.parse(f.generator.generateXrayConfigWithApi(nodes[0],f.users));f.generator.ensurePrivateIpBlock(base);f.files.set(f.key(nodes[0]._id,MAIN),JSON.stringify(base));
    assert.equal(await f.cascade._deployPortalConfig(nodes[0]),true);
    assert.equal(JSON.parse(f.files.get(f.key(nodes[0]._id,MAIN))).inbounds.some(x=>x.port===pending.tunnelPort),false);
    assert.equal(f.locks.size,0);
}));
test('explicit classic selection never bypasses topology config ownership veto', async () => withEnv(TEST, async () => {
    const f=fixture();f.adopt(f.nodes[0]._id,'xray-main');
    try{await f.cascade._deployPortalConfig(f.nodes[0],{selectedLinkIds:[f.links[0]._id]});}catch{ /* checked ownership fence refusal */ }
    assert.equal(f.events.some(x=>x.kind==='upload'),false);
}));
