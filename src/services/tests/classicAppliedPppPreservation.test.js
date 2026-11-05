'use strict';
// Corrected independent regression: generate the installed PPP profile once,
// including its real scoped refusal (do not insert a duplicate fixture rule).
const test = require('node:test');
const assert = require('node:assert/strict');
const { fixture, withEnv, node, link, MAIN, BRIDGE } = require('./cascadeLegacyWriterFixture');
const { buildL2tpXrayFragment } = require('../../modules/relay-l2tp/services/l2tpXrayFragmentProvider');
const { applyClassicL2tpPathIngress, finishClassicConfigRouting } = require('../classicL2tpConfigComposition');

for (const writer of ['sync', 'cascade']) {
    test(`${writer} preserves installed PPP and manual scoped private-network refusals on successful rewrites`, async () => withEnv({}, async () => {
        const nodes = [node(1, 'relay'), node(2, 'bridge')];
        const f = fixture({ nodes, links: [link(20, nodes[0], nodes[1], { mode: 'forward', status: 'online' })], installedL2tp: true });
        const fragment = buildL2tpXrayFragment({
            plan: { relay: { controlPlaneIps: [nodes[0].ip] }, group: { id: 'modeled-group' },
                paths: [{ pathKey: 'main', healthy: true, outboundTag: 'cascade-main' }], selectedPathKey: 'main' },
            tags: { inbound: 'relay-l2tp-modeled', blockOutbound: 'block' }, tproxyPort: 12345,
        });
        const current = JSON.parse(f.generator.generateXrayConfigWithApi(nodes[0], f.users, { fragments: [fragment] }));
        const populated = { ...f.links[0], bridgeNode: nodes[1] };
        f.generator.applyForwardChain(current, [populated], ['clients']);
        applyClassicL2tpPathIngress(current, { nodeId: nodes[0]._id, mode: 'forward', links: [populated],
            groups: [{ _id: 'modeled-group', mode: 'forward', paths: [{ pathKey: 'main', linkIds: [populated._id], enabled: true }] }] });
        const manual = { type: 'field', inboundTag: ['clients'], ip: ['geoip:private'], outboundTag: 'block' };
        current.routing.rules.unshift(manual);
        finishClassicConfigRouting(current);
        const scoped = rule => rule.inboundTag?.length && rule.ip?.length === 1 && rule.ip[0] === 'geoip:private';
        assert.equal(current.routing.rules.filter(rule => scoped(rule) && rule.inboundTag.includes('relay-l2tp-modeled')).length, 1);
        const beforeScoped = current.routing.rules.filter(scoped);
        f.files.set(f.key(nodes[0]._id, MAIN), JSON.stringify(current));
        const otherProfile = f.files.get(f.key(nodes[0]._id, BRIDGE));
        for (let repeat = 0; repeat < 2; repeat++) {
            assert.equal(await (writer === 'sync' ? f.sync.updateXrayNodeConfig(nodes[0]) : f.cascade._deployPortalConfig(nodes[0])), true);
            const after = JSON.parse(f.files.get(f.key(nodes[0]._id, MAIN)));
            assert.deepEqual(after.routing.rules.filter(scoped), beforeScoped,
                'ordinary full rewrite must retain the working PPP and manual private-network refusals');
            for (const inbound of current.inbounds) assert.deepEqual(after.inbounds.find(row => row.tag === inbound.tag), inbound);
            for (const outbound of fragment.outbounds) assert.deepEqual(after.outbounds.find(row => row.tag === outbound.tag), outbound);
            assert.deepEqual(after.inbounds.find(row => row.tag === 'cascade-main'), current.inbounds.find(row => row.tag === 'cascade-main'));
            assert.equal(f.files.get(f.key(nodes[0]._id, BRIDGE)), otherProfile);
            assert.equal(f.locks.size, 0);
        }
    }));
}
