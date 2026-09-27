'use strict';

process.env.PANEL_DOMAIN = process.env.PANEL_DOMAIN || 'panel.example.test';
process.env.ACME_EMAIL = process.env.ACME_EMAIL || 'test@example.test';
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || '01234567890123456789012345678901';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    TopologyDomainSyncPlanner,
    TopologyDomainSyncPlannerError,
    defaultIsDeployedLink,
    domainScopeKey,
} = require('../services/topologyDomainSyncPlanner');

function nodeDoc(id, role) {
    return { _id: id, cascadeRole: role };
}

function linkDoc(id, source, target, extra = {}) {
    return {
        _id: id,
        portalNode: source,
        bridgeNode: target,
        mode: 'forward',
        active: true,
        status: 'online',
        ...extra,
    };
}

function nodeMeta(id, role, index) {
    return {
        id,
        role,
        type: 'xray',
        active: true,
        cascadeRole: role,
        ip: `192.0.2.${index}`,
        port: 24000 + index,
        xray: {
            accessLogs: { enabled: false },
            apiPort: 61000 + index,
            inboundTag: `client-${role}-${index}`,
            transport: 'tcp',
            security: 'none',
            extraInbounds: [],
        },
    };
}

function linkMeta(id, tunnelPort, extra = {}) {
    return { id, tunnelPort, ...extra };
}

// Domain A: node-p1 -> node-r1 -> node-b1
// Domain B: node-p2 -> node-r2 -> node-b2
function twoDomainInput(overrides = {}) {
    return {
        snapshot: {
            revision: 8,
            nodes: [
                nodeDoc('node-p1', 'portal'),
                nodeDoc('node-r1', 'relay'),
                nodeDoc('node-b1', 'bridge'),
                nodeDoc('node-p2', 'portal'),
                nodeDoc('node-r2', 'relay'),
                nodeDoc('node-b2', 'bridge'),
            ],
            links: [
                linkDoc('link-a1', 'node-p1', 'node-r1'),
                linkDoc('link-a2', 'node-r1', 'node-b1'),
                linkDoc('link-b1', 'node-p2', 'node-r2'),
                linkDoc('link-b2', 'node-r2', 'node-b2'),
            ],
            groups: [],
            ...overrides.snapshot,
        },
        nodeMetadata: [
            nodeMeta('node-p1', 'portal', 1),
            nodeMeta('node-r1', 'relay', 2),
            nodeMeta('node-b1', 'bridge', 3),
            nodeMeta('node-p2', 'portal', 4),
            nodeMeta('node-r2', 'relay', 5),
            nodeMeta('node-b2', 'bridge', 6),
        ],
        linkMetadata: [
            linkMeta('link-a1', 10101),
            linkMeta('link-a2', 10102),
            linkMeta('link-b1', 10201),
            linkMeta('link-b2', 10202),
        ],
        ...overrides.root,
    };
}

function createPlanner() {
    return new TopologyDomainSyncPlanner();
}

test('plans two independent domains (P1-R1-B1 and P2-R2-B2) separately in one sync', () => {
    const planner = createPlanner();
    const result = planner.planManualSync(twoDomainInput());

    assert.equal(result.topologyRevision, 8);
    assert.equal(result.status, 'ready');
    assert.equal(result.domains.length, 2);

    // Deterministic domain order: sorted by domain key.
    const keys = result.domains.map(domain => domain.key);
    assert.deepEqual(keys, [...keys].sort((left, right) => left.localeCompare(right, 'en')));
    assert.deepEqual(keys, ['node-b1', 'node-b2']);

    for (const domain of result.domains) {
        assert.equal(domain.status, 'planned');
        assert.equal(domain.mode, 'forward');
        assert.equal(domain.revision, 8);
        assert.deepEqual(domain.scope, { domainKey: domain.key, topologyRevision: 8 });
        assert.equal(domain.scopeKey, domainScopeKey(8, domain.key));
        assert.equal(domain.plan.nodes.length, 3);
        assert.deepEqual(
            domain.plan.nodes.map(node => node.nodeRef).sort(),
            ['bridge', 'portal', 'relay-1'],
        );
    }

    // Each domain is scoped to its own nodes/links — no cross-domain bleed.
    // (Plan entries are ref-keyed by design; node-id resolution against the
    // sliced topology is the integration layer's job.)
    const [first, second] = result.domains;
    assert.deepEqual(first.nodeIds, ['node-b1', 'node-p1', 'node-r1']);
    assert.deepEqual(second.nodeIds, ['node-b2', 'node-p2', 'node-r2']);
    assert.deepEqual(
        first.plan.nodes.map(node => node.role).sort(),
        ['bridge', 'portal', 'relay'],
    );
    assert.ok(first.linkIds.every(id => id.startsWith('link-a')));
    assert.ok(second.linkIds.every(id => id.startsWith('link-b')));

    // Deployed baseline covers both complete domains.
    assert.deepEqual(result.baseline.linkIds, ['link-a1', 'link-a2', 'link-b1', 'link-b2']);
    assert.equal(result.baseline.domains.length, 2);
});

test('incomplete pending draft is excluded from the deployed baseline and does not block other domains', () => {
    const planner = createPlanner();
    const input = twoDomainInput();
    // Domain B has only its first hop, still pending (never deployed).
    input.snapshot.links = input.snapshot.links.filter(link => link._id !== 'link-b2');
    input.linkMetadata = input.linkMetadata.filter(meta => meta.id !== 'link-b2');
    input.snapshot.links.find(link => link._id === 'link-b1').status = 'pending';

    const result = planner.planManualSync(input);

    assert.equal(result.status, 'partial');
    assert.equal(result.domains.length, 2);

    const complete = result.domains.find(domain => domain.key === 'node-b1');
    const incomplete = result.domains.find(domain => domain.key === 'node-p2');

    // The unrelated incomplete chain must not block the healthy domain.
    assert.equal(complete.status, 'planned');
    assert.equal(complete.plan.nodes.length, 3);

    // The incomplete domain is diagnosed per-domain, not thrown globally.
    assert.equal(incomplete.status, 'blocked');
    assert.deepEqual(incomplete.linkIds, ['link-b1']);
    assert.ok(Array.isArray(incomplete.errors) && incomplete.errors.length > 0);
    assert.ok(incomplete.errors.every(error => typeof error.code === 'string'));

    // Deployed baseline contains only confirmed-deployed links: the pending
    // draft hop is absent, and its nodes form no baseline domain.
    assert.deepEqual(result.baseline.linkIds, ['link-a1', 'link-a2']);
    assert.equal(result.baseline.domains.length, 1);
    assert.deepEqual(result.baseline.domains[0].nodeIds, ['node-b1', 'node-p1', 'node-r1']);
});

test('mixed forward/reverse links compose within a single domain', () => {
    const planner = createPlanner();
    const input = twoDomainInput();
    input.snapshot.links = input.snapshot.links.filter(link => link._id.startsWith('link-a'));
    input.linkMetadata = input.linkMetadata.filter(meta => meta.id.startsWith('link-a'));
    // portal -> relay forward; relay -> bridge reverse (bridge dials relay).
    input.snapshot.links.find(link => link._id === 'link-a2').mode = 'reverse';

    const result = planner.planManualSync(input);

    assert.equal(result.status, 'ready');
    assert.equal(result.domains.length, 1);
    assert.equal(result.domains[0].status, 'planned');
    assert.equal(result.domains[0].mode, 'mixed');
});

test('plan is deterministic regardless of input ordering', () => {
    const planner = createPlanner();
    const first = planner.planManualSync(twoDomainInput());
    const second = planner.planManualSync(twoDomainInput());

    const shuffled = twoDomainInput();
    shuffled.snapshot.nodes = [...shuffled.snapshot.nodes].reverse();
    shuffled.snapshot.links = [...shuffled.snapshot.links].reverse();
    shuffled.nodeMetadata = [...shuffled.nodeMetadata].reverse();
    shuffled.linkMetadata = [...shuffled.linkMetadata].reverse();
    const third = planner.planManualSync(shuffled);

    assert.equal(JSON.stringify(second), JSON.stringify(first));
    assert.equal(JSON.stringify(third), JSON.stringify(first));
});

test('scoped revision fencing rejects a stale expected revision', () => {
    const planner = createPlanner();

    assert.throws(
        () => planner.planManualSync({
            ...twoDomainInput(),
            expectedTopologyRevision: 9,
        }),
        error => error instanceof TopologyDomainSyncPlannerError
            && error.code === 'STALE_TOPOLOGY_REVISION'
            && error.topologyRevision === 8,
    );

    // A matching expected revision pins every planned domain to it.
    const result = planner.planManualSync({
        ...twoDomainInput(),
        expectedTopologyRevision: 8,
    });
    assert.equal(result.status, 'ready');
    for (const domain of result.domains) {
        assert.equal(domain.revision, 8);
        assert.equal(domain.scope.topologyRevision, 8);
    }
});

test('invalid expected revision values are rejected before planning', () => {
    const planner = createPlanner();
    for (const expectedTopologyRevision of [-1, 1.5, '8', NaN]) {
        assert.throws(
            () => planner.planManualSync({ ...twoDomainInput(), expectedTopologyRevision }),
            error => error.code === 'INVALID_TOPOLOGY_REVISION',
        );
    }
});

test('empty graph yields an empty report instead of an error', () => {
    const planner = createPlanner();
    const result = planner.planManualSync({
        snapshot: { revision: 3, nodes: [nodeDoc('node-p1', 'portal')], links: [], groups: [] },
        nodeMetadata: [],
        linkMetadata: [],
    });

    assert.equal(result.status, 'empty');
    assert.deepEqual(result.domains, []);
    assert.deepEqual(result.baseline.linkIds, []);
    assert.deepEqual(result.baseline.domains, []);
});

test('default deployed-link policy treats only confirmed links as deployed', () => {
    assert.equal(defaultIsDeployedLink({ active: true, status: 'online' }), true);
    assert.equal(defaultIsDeployedLink({ active: true, status: 'deployed' }), true);
    // A staged hop was physically applied, but is not client-ready.
    assert.equal(defaultIsDeployedLink({ active: true, status: 'staged' }), true);
    assert.equal(defaultIsDeployedLink({ active: true, status: 'pending' }), false);
    assert.equal(defaultIsDeployedLink({ active: true, status: 'error' }), false);
    assert.equal(defaultIsDeployedLink({ active: true, status: 'offline' }), false);
    // Legacy rows predate per-link deploy state: no status means deployed.
    assert.equal(defaultIsDeployedLink({ active: true }), true);
    // Inactive links never belong to the baseline.
    assert.equal(defaultIsDeployedLink({ active: false, status: 'online' }), false);
});

test('domain scope key is deterministic and revision-scoped', () => {
    assert.equal(domainScopeKey(8, 'node-b1'), 'topology:8:domain:node-b1');
    assert.notEqual(domainScopeKey(8, 'node-b1'), domainScopeKey(9, 'node-b1'));
});
