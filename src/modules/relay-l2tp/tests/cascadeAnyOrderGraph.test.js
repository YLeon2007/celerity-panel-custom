'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { compileTopology } = require('../domain/topologyCompiler');
const { composeFrozenTopologyDeploymentPlan } = require('../services/frozenTopologyDeploymentPlanComposer');
const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');

// Local generation only: actual compiler/materializer/composer/generators,
// query-aware metadata fixtures, no database, transport or client readiness.
function fixture(modes = ['reverse', 'reverse', 'reverse']) {
    const nodes = [['p', 'portal'], ['r', 'relay'], ['b1', 'bridge'], ['b2', 'bridge']]
        .map(([id, role], index) => ({
            id, role, type: 'xray', active: true, ip: `192.0.2.${index + 1}`,
            port: 24001 + index,
            xray: { inboundTag: `client-${id}`, transport: 'tcp', security: 'none', extraInbounds: [] },
        }));
    const links = [['pr', 'p', 'r'], ['rb1', 'r', 'b1'], ['rb2', 'r', 'b2']]
        .map(([id, source, target], index) => ({
            id, source, target, active: true, mode: modes[index], tunnelPort: 12001 + index,
            tunnelSecurity: 'none', tunnelTransport: 'tcp',
            ...(id === 'rb2' ? { geoRouting: { enabled: true, geoip: ['ru'], domains: ['category-ru'] } } : {}),
        }));
    return { nodes, links };
}

function topologyFor(data, linkIds, { keepDetachedNodes = false, groups = [] } = {}) {
    const links = data.links.filter(link => linkIds.includes(link.id));
    const used = new Set(links.flatMap(link => [link.source, link.target]));
    return {
        nodes: data.nodes.filter(node => keepDetachedNodes || used.has(node.id))
            .map(({ id, role }) => ({ id, role })),
        links: links.map(({ id, source, target, mode }) => ({ id, source, target, mode })),
        groups,
    };
}

function compose(data, linkIds, options = {}) {
    const snapshot = topologyFor(data, linkIds, options);
    return composeFrozenTopologyDeploymentPlan({
        snapshot, nodeMetadata: data.nodes, linkMetadata: data.links,
        compiledTopology: compileTopology(snapshot), staged: true,
    });
}

function materializerFor(data) {
    const reads = [];
    const model = rows => ({
        find(filter) {
            reads.push(structuredClone(filter));
            return {
                select() { return this; },
                async lean() {
                    return structuredClone(rows.filter(row => filter._id.$in.includes(row.id)
                        && row.active === true));
                },
            };
        },
    });
    return { reads, materializer: new TopologyOperationPlanMaterializer({
        HyNode: model(data.nodes), CascadeLink: model(data.links),
    }) };
}

async function materialize(data, linkIds, options = {}) {
    const topology = topologyFor(data, linkIds, options);
    const { materializer, reads } = materializerFor(data);
    const plan = await materializer.materialize({
        target: 'test', hostIdentity: 'test.infograd.online', operationKind: 'link.apply',
        pinnedSnapshot: { revision: 7, topology, compiled: compileTopology(topology) },
    });
    return { plan, reads };
}

function configsOf(plan) {
    return new Map(plan.nodes.map(node => [node.nodeRef, JSON.parse(Buffer.from(node.candidate.bytes))]));
}

for (const [name, ids] of [
    ['source-less G2 R->B', ['rb1']],
    ['source-less G3 R->B1,R->B2', ['rb1', 'rb2']],
]) {
    test(`${name} composes through the existing frozen composer`, () => {
        const plan = compose(fixture(), ids);
        assert.equal(plan.staged, true, 'no portal path is not client-ready');
        assert.equal(plan.nodes.filter(node => node.role === 'relay').length, 1);
        assert.equal(plan.nodes.filter(node => node.role === 'bridge').length, ids.length);
        assert.equal(plan.nodes.some(node => node.role === 'portal'), false);
    });
    test(`${name} materializes as explicit link.apply`, async () => {
        const { plan } = await materialize(fixture(), ids);
        assert.equal(plan.staged, true);
        assert.equal(plan.nodes.length, ids.length + 1);
    });
}

test('R->B1; R->B2; P->R completes without dropping either bridge', async () => {
    const data = fixture();
    const first = await materialize(data, ['rb1']);
    const second = await materialize(data, ['rb1', 'rb2']);
    const final = await materialize(data, ['rb1', 'rb2', 'pr']);
    assert.equal(first.plan.staged, true);
    assert.equal(second.plan.staged, true);
    assert.equal(final.plan.staged, undefined);
    assert.deepEqual([...configsOf(final.plan).keys()].sort(), ['bridge', 'bridge-2', 'portal', 'relay-1']);
});
