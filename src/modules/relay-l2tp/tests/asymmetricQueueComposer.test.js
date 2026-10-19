'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const root = require('node:path').resolve(__dirname, '../../../..');
const { TopologyOperationCoordinator } = require(`${root}/src/modules/relay-l2tp/services/topologyOperationCoordinator`);
const { composeFrozenTopologyDeploymentPlan } = require(`${root}/src/modules/relay-l2tp/services/frozenTopologyDeploymentPlanComposer`);

test('queue -> real staged composer -> frozen configs retain asymmetric relay identity', async () => {
    const nodes = [['pa', 'portal'], ['pb', 'portal'], ['rb', 'relay'], ['rm', 'relay']]
        .map(([id, role], index) => ({ _id: id, cascadeRole: role,
            type: 'xray', active: true, ip: `192.0.2.${index + 1}`, port: 24001 + index,
            xray: { inboundTag: `client-${id}`, transport: 'tcp', security: 'none', extraInbounds: [] } }));
    const links = [
        { _id: 'a', portalNode: 'pa', bridgeNode: 'rm', mode: 'forward', status: 'deployed', active: true, tunnelPort: 10101 },
        { _id: 'b', portalNode: 'pb', bridgeNode: 'rb', mode: 'reverse', status: 'pending', active: true, tunnelPort: 10102 },
        { _id: 'c', portalNode: 'rb', bridgeNode: 'rm', mode: 'forward', status: 'deployed', active: true, tunnelPort: 10103 },
    ];
    const snapshot = { revision: 7, deployedRevision: 5, nodes, links, groups: [] };
    let frozen;
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: { async admitTopology({ prepare, admit }) {
            const session = { inTransaction: () => true };
            const prepared = await prepare(snapshot, session);
            const pinned = { revision: 7, deployedRevision: 5, ...prepared };
            await admit(pinned, session);
            return pinned;
        } },
        planMaterializer: { async materialize({ pinnedSnapshot }) {
            return composeFrozenTopologyDeploymentPlan({
                snapshot: pinnedSnapshot.topology,
                nodeMetadata: nodes.map(node => ({ ...node, id: node._id, role: node.cascadeRole })),
                linkMetadata: links.map(link => ({ ...link, id: link._id })),
                compiledTopology: { valid: true, relays: [{ nodeId: 'rb' }, { nodeId: 'rm' }] },
                staged: true,
            });
        } },
        operationRepository: { async createFrozen(value) { frozen = value; return { _id: value.operationId }; } },
        validator: () => ({ valid: true }), compiler: () => ({ valid: true }),
        idFactory: () => 'operation-asymmetric',
    });
    await coordinator.queue({ expectedTopologyRevision: 7, scope: { kind: 'link.apply', linkId: 'b', linkIds: ['a', 'b', 'c'] } });
    assert.equal(frozen.staged, true);
    const byNode = new Map(frozen.nodes.map(node => [node.node, JSON.parse(Buffer.from(node.candidate.bytes))]));
    assert.deepEqual(byNode.get('rm').inbounds.filter(inbound => inbound.tag.startsWith('fwd-hop-'))
        .map(inbound => inbound.port).sort(), [10101, 10103], 'rm must terminate both fan-in links, not receive rb config');
    const rb = byNode.get('rb');
    assert.equal(rb.outbounds.find(outbound => outbound.tag.startsWith('tunnel-')).settings.vnext[0].address, '192.0.2.2');
    assert.equal(rb.outbounds.find(outbound => outbound.tag.startsWith('fwd-')).settings.vnext[0].address, '192.0.2.4');
    for (const config of byNode.values()) assert.equal(config.routing.rules.some(rule => ['direct', 'freedom'].includes(rule.outboundTag)), false);
});
