'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { fixture, withEnv, node, link, MAIN, BRIDGE } = require('./cascadeLegacyWriterFixture');
const { finishClassicConfigRouting } = require('../classicL2tpConfigComposition');
const statuses = ['pending', 'offline', 'error', undefined];
const read = (f, target, profile = MAIN) => JSON.parse(f.files.get(f.key(target._id, profile)));
const run = (f, writer, target) => writer === 'sync' ? f.sync.updateXrayNodeConfig(target) : f.cascade._deployPortalConfig(target);
function inventory(status) {
    const nodes = [node(1), node(2, 'standalone'), node(3, 'bridge'), node(4, 'bridge')];
    const upstream = link(20, nodes[0], nodes[1], { status });
    const downstream = link(21, nodes[1], nodes[2], { status });
    return { nodes, upstream, downstream };
}
for (const writer of ['sync', 'cascade']) {
    test(`${writer}: checked legacy transit bytes, not status or role, remove exact duplicate MAIN listeners`, async () => withEnv({}, async () => {
        for (const status of statuses) {
            const { nodes, upstream, downstream } = inventory(status);
            const f = fixture({ nodes, links: [upstream, downstream], onExec({ node: target, command, locks }) {
                if (/cat \/usr\/local\/etc\/xray(?:-bridge)?\/config.json/.test(command)) assert(locks.has(target._id), 'read both profiles inside the held node generation');
            } });
            f.links.push(link(22, nodes[0], nodes[1], { status: 'pending' }), link(23, nodes[1], nodes[3], { status: 'pending' }));
            const main = read(f, nodes[1]);
            const manual = { type: 'field', inboundTag: ['clients'], ip: ['geoip:private'], outboundTag: 'block' };
            f.generator.applyReversePortal(main, [downstream], ['clients']);
            main.routing.rules.unshift(manual);
            finishClassicConfigRouting(main);
            f.files.set(f.key(nodes[1]._id, MAIN), JSON.stringify(main));
            const secondary = f.generator.generateRelayConfig(upstream, nodes[0], [downstream]);
            f.files.set(f.key(nodes[1]._id, BRIDGE), secondary);
            for (let repeat = 0; repeat < 2; repeat++) {
                assert.equal(await run(f, writer, nodes[1]), true);
                const after = read(f, nodes[1]);
                assert.equal(after.reverse?.portals?.length || 0, 0);
                assert.equal([...after.inbounds, ...JSON.parse(secondary).inbounds].filter(row => row.port === downstream.tunnelPort).length, 1);
                assert(after.routing.rules.some(row => JSON.stringify(row) === JSON.stringify(manual)));
                assert(after.inbounds.some(row => row.settings?.clients?.some(client => client.id === f.users[0].xrayUuid)));
                assert(!JSON.stringify(after).includes(f.links[3].tunnelUuid));
                assert.equal(f.files.get(f.key(nodes[1]._id, BRIDGE)), secondary);
                assert.equal(f.locks.size, 0);
            }
        }
    }));

    test(`${writer}: absent or terminal-only sidecar cannot move installed MAIN listeners because of a saved upstream`, async () => withEnv({}, async () => {
        for (const status of statuses) for (const installedUpstream of [false, true]) {
            const { nodes, upstream, downstream } = inventory(status);
            const f = fixture({ nodes, links: [downstream] });
            f.links.push(upstream, link(23, nodes[1], nodes[3], { status: 'pending' }));
            if (installedUpstream) f.files.set(f.key(nodes[1]._id, BRIDGE), f.generator.generateCombinedBridgeConfig([{ ...upstream, portalNode: nodes[0] }]));
            const secondary = f.files.get(f.key(nodes[1]._id, BRIDGE));
            assert.equal(await run(f, writer, nodes[1]), true);
            const after = read(f, nodes[1]);
            assert.equal(after.inbounds.filter(row => row.port === downstream.tunnelPort).length, 1);
            assert(!JSON.stringify(after).includes(f.links[2].tunnelUuid));
            assert.equal(f.files.get(f.key(nodes[1]._id, BRIDGE)), secondary);
            assert.equal(f.locks.size, 0);
        }
    }));

    test(`${writer}: unrecognized transit sidecar refuses before MAIN upload instead of deleting a working listener`, async () => withEnv({}, async () => {
        const { nodes, upstream, downstream } = inventory('pending');
        const f = fixture({ nodes, links: [downstream] });
        f.links.push(upstream);
        const secondary = JSON.parse(f.generator.generateRelayConfig(upstream, nodes[0], [downstream]));
        secondary.outbounds.find(row => row.tag === 'tunnel-up').settings.vnext[0].users[0].id = 'changed-installed-key';
        f.files.set(f.key(nodes[1]._id, BRIDGE), JSON.stringify(secondary));
        const bytes = f.files.get(f.key(nodes[1]._id, MAIN));
        await assert.rejects(run(f, writer, nodes[1]), { code: 'CLASSIC_APPLIED_ARTIFACT_MISMATCH' });
        assert.equal(f.files.get(f.key(nodes[1]._id, MAIN)), bytes);
        assert(!f.events.some(row => row.kind === 'upload' || row.kind === 'exec' && /systemctl/.test(row.command)));
        assert.equal(f.locks.size, 1, 'existing conservative refusal fence is unchanged');
    }));
}
