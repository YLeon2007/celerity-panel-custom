'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const configPath = require.resolve('../../../../config');
require.cache[configPath] = { id: configPath, filename: configPath, loaded: true, exports: { panel: { domain: 'fixture.invalid' }, xray: {} } };
const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');
const { compileTopology } = require('../domain/topologyCompiler');
const { cascadePathIngressPort } = require('../domain/cascadePathIngress');
const materializer = new TopologyOperationPlanMaterializer({ HyNode: { find() { assert.fail('no mutable node hydration'); } },
    CascadeLink: { find() { assert.fail('no mutable link hydration'); } } });
const configs = plan => new Map(plan.nodes.map(node => [node.node, JSON.parse(Buffer.from(node.candidate.bytes))]));
const ingress = config => config.inbounds.filter(item => item.tag === 'cascade-mine');
async function compose(before, after, installedPath) {
    return materializer.materialize({ target: 'test', hostIdentity: 'test.infograd.online', operationKind: 'link.delete',
        baselineTopology: before, effectiveTopology: after, installedPath,
        pinnedSnapshot: { revision: 7, topology: after, compiled: compileTopology(after) } });
}
function graph(modes) {
    const nodes = [['p', 'portal'], ['r1', 'relay'], ['r2', 'relay'], ['b', 'bridge'], ['geo-b', 'bridge']]
        .map(([id, role], i) => ({ id, role, type: 'xray', active: true, ip: `192.0.2.${i + 1}`, port: 24440 + i,
            xray: { security: 'none', transport: 'tcp', inboundTag: 'client-' + id, extraInbounds: [] } }));
    const links = [['input', 'p', 'r1'], ['middle', 'r1', 'r2'], ['exit', 'r2', 'b'], ['geo', 'r1', 'geo-b']]
        .map(([id, source, target], i) => ({ id, source, target, mode: modes[i], tunnelPort: 25000 + i,
            tunnelUuid: `${String(i + 1).repeat(8)}-1111-4111-8111-111111111111`, tunnelSecurity: 'none', tunnelTransport: 'tcp',
            ...(id === 'geo' ? { geoRouting: { enabled: true, domains: ['category-ru'], geoip: ['ru'] } } : {}) }));
    const groups = [{ _id: 'installed', mode: 'reverse', strategy: 'priority-failover', paths: [
        { pathKey: 'mine', linkIds: ['middle', 'exit'], priority: 1, enabled: true },
        { pathKey: 'peer', linkIds: ['geo'], priority: 2, enabled: true },
    ] }];
    return { nodes, links, groups };
}
function owner(before, after) {
    return { groupId: 'installed', pathKey: 'mine', ownerNodeId: 'r1', ownerTopologyRevision: 5,
        ownerCredentialRevision: 41, oldPathLinkIds: before.groups[0].paths[0].linkIds,
        newPathLinkIds: after.groups[0].paths[0].linkIds, groupBefore: before.groups[0], kind: 'link.delete' };
}
function assertBlocked(config) {
    assert.equal(ingress(config).length, 1, 'stable installed PPP listener must survive repeated empty-path cleanup');
    assert.equal(ingress(config)[0].port, cascadePathIngressPort('installed', 'mine'));
    const rules = config.routing.rules.filter(rule => rule.inboundTag?.includes('cascade-mine'));
    assert.deepEqual(rules, [{ type: 'field', inboundTag: ['cascade-mine'], outboundTag: 'block' }]);
    assert.equal(config.routing.rules.indexOf(rules[0]), 0, 'unconditional owned block precedes global reverse/geo rules');
    assert.equal(config.outbounds.find(item => item.tag === 'block').protocol, 'blackhole');
    for (const bridge of config.reverse?.bridges || []) {
        const full = `full:${bridge.domain}`;
        const first = config.routing.rules.find(rule => (!rule.inboundTag || rule.inboundTag.includes('cascade-mine'))
            && (!rule.domain || rule.domain.includes(full)) && !rule.ip);
        assert.equal(first, rules[0], 'reverse control domain cannot bypass the PPP block');
        assert.ok(config.routing.rules.some(rule => rule.domain?.includes(full) && rule.outboundTag.startsWith('tunnel-')),
            'other reverse control remains configured');
    }
}
for (const modes of [['reverse', 'reverse', 'reverse', 'reverse'], ['forward', 'forward', 'forward', 'forward'],
    ['reverse', 'forward', 'reverse', 'reverse'], ['forward', 'reverse', 'forward', 'reverse']]) {
    for (const order of [['middle', 'exit', 'input'], ['exit', 'middle', 'input']]) {
        test(`G5 intermediate installed PPP ${modes.join('/')} empty path survives ${order.join('->')}`, async () => {
            let before = graph(modes);
            let plan = await compose({ nodes: [], links: [], groups: [] }, before);
            const installedListener = ingress(configs(plan).get('r1'))[0];
            const peer = structuredClone(before.groups[0].paths[1]);
            for (const removed of order) {
                // Match the ordinary selected reader's preceding committed
                // candidate, including exact domain-routing listener bytes.
                for (const node of before.nodes) node.profileConfig = configs(plan).get(node.id);
                const after = structuredClone(before);
                after.links = after.links.filter(link => link.id !== removed);
                after.groups[0].paths[0].linkIds = [];
                const saved = structuredClone({ before, after });
                plan = await compose(before, after, owner(before, after));
                const config = configs(plan).get('r1');
                assertBlocked(config);
                assert.deepEqual(ingress(config), [installedListener]);
                assert.deepEqual(after.groups[0].paths[1], peer);
                const geo = config.routing.rules.filter(rule => rule.domain?.includes('geosite:category-ru'));
                if (removed !== 'input') {
                    assert.ok(geo.length > 0, 'ordinary transit retains its geo policy');
                    assert.ok(geo.every(rule => rule.outboundTag !== 'block' && !rule.inboundTag.includes('cascade-mine')));
                }
                assert.deepEqual({ before, after }, saved);
                before = after;
            }
        });
    }
}
test('verified persistent empty-path readback is retained first without an installed-path input and later attach removes its block', async () => {
    const full = graph(['reverse', 'reverse', 'reverse', 'reverse']);
    const emptyPath = structuredClone(full); emptyPath.links = emptyPath.links.filter(link => link.id !== 'middle'); emptyPath.groups[0].paths[0].linkIds = [];
    const first = await compose(full, emptyPath, owner(full, emptyPath));
    for (const node of emptyPath.nodes) node.profileConfig = configs(first).get(node.id);
    const next = structuredClone(emptyPath); next.links = next.links.filter(link => link.id !== 'exit');
    const second = await compose(emptyPath, next);
    assertBlocked(configs(second).get('r1'));
    for (const node of next.nodes) node.profileConfig = configs(second).get(node.id);
    const attached = await compose(next, full, owner(next, full));
    const config = configs(attached).get('r1');
    assert.equal(ingress(config).length, 1);
    assert.equal(config.routing.rules.some(rule => rule.inboundTag?.includes('cascade-mine') && rule.outboundTag === 'block'), false);
});

for (const [label, change] of [
    ['foreign group', value => { value.groupId = 'foreign'; }],
    ['foreign key', value => { value.pathKey = 'foreign'; }],
    ['non-relay owner', value => { value.ownerNodeId = 'b'; }],
    ['changed old path', value => { value.oldPathLinkIds = ['input']; }],
    ['changed new path', value => { value.newPathLinkIds = ['input']; }],
]) test(`installed empty ingress propagation rejects ${label}`, async () => {
    const before = graph(['reverse', 'reverse', 'reverse', 'reverse']), after = structuredClone(before);
    after.links = after.links.filter(link => link.id !== 'middle'); after.groups[0].paths[0].linkIds = [];
    const value = structuredClone(owner(before, after)); change(value);
    await assert.rejects(compose(before, after, value), { code: 'TOPOLOGY_INSTALLED_PATH_MISMATCH' });
});

test('an arbitrary empty peer path without checked owner identity cannot create installed PPP ingress', async () => {
    const before = graph(['reverse', 'reverse', 'reverse', 'reverse']);
    before.links = before.links.filter(link => link.id !== 'middle'); before.groups[0].paths[0].linkIds = [];
    const after = structuredClone(before);
    const plan = await compose(before, after);
    assert.equal(ingress(configs(plan).get('r1')).length, 0);
    assert.equal(ingress(configs(plan).get('r2')).length, 0);
});
