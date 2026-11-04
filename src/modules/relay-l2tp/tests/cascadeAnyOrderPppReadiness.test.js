'use strict';

// Isolated local orchestration evidence: real composer, PPP gate, execution
// resolver and verifier transport; persistence and SSH output are modeled.
// No application .env, network, real PPP client or installed-route publication.
process.env.PANEL_DOMAIN ||= 'panel.example.test';
process.env.ACME_EMAIL ||= 'admin@example.test';
process.env.ENCRYPTION_KEY ||= '01234567890123456789012345678901';
process.env.SESSION_SECRET ||= 'test-session-secret';

const assert = require('node:assert/strict');
const test = require('node:test');
const { compileTopology } = require('../domain/topologyCompiler');
const { deriveAttachTopology, deriveReplacementTopology } = require('../domain/topologyReplacement');
const { cascadePathIngressTag } = require('../domain/cascadePathIngress');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');
const { composeFrozenTopologyDeploymentPlan } = require('../services/frozenTopologyDeploymentPlanComposer');
const { createTopologyPppReadinessGate } = require('../services/topologyPppReadinessGate');

const OPERATION = 'abcdef012345abcdef012345';
const query = read => ({
    select() { return this; },
    sort() { return this; },
    async lean() { return structuredClone(await read()); },
});

function composedPlan({ sourceLess = true, noExit = false, mode = 'reverse', topology } = {}) {
    const nodes = [{ id: 'r', role: 'relay' },
        ...(!sourceLess ? [{ id: 'p', role: 'portal' }] : []),
        ...(!noExit ? [{ id: 'b', role: 'bridge' }] : [])];
    const links = [...(!sourceLess ? [{ id: 'input', source: 'p', target: 'r', mode }] : []),
        ...(!noExit ? [{ id: 'exit', source: 'r', target: 'b', mode }] : [])];
    const snapshot = topology || { nodes, links, groups: [] };
    const plan = composeFrozenTopologyDeploymentPlan({ snapshot,
        compiledTopology: compileTopology(snapshot), staged: true,
        nodeMetadata: snapshot.nodes.map((node, index) => ({ ...node, type: 'xray', active: true,
            ip: `192.0.2.${index + 1}`, domain: `${node.id}.example.test`, port: 24000 + index,
            xray: { apiPort: 61000 + index, inboundTag: `client-${node.id}`, transport: 'tcp', security: 'none' },
        })),
        linkMetadata: snapshot.links.map((link, index) => ({ ...link,
            ...(link.geo ? { geoRouting: { enabled: true, domains: ['geo.example.test'], geoip: [] } } : {}),
            tunnelPort: 12000 + index,
            tunnelUuid: `uuid-${link.id}`, tunnelDomain: 'reverse.example.test',
            tunnelProtocol: 'vless', tunnelSecurity: 'none', tunnelTransport: 'tcp',
        })),
    });
    // Explicit test hydration seam: the separately owned coordinator must bind
    // these refs to the same pinned node identities in real operation plans.
    const byRef = { portal: 'p', 'relay-1': 'r', bridge: 'b', 'bridge-2': 'geo-b' };
    return { ...plan, nodes: plan.nodes.map(node => ({ ...node, node: byRef[node.nodeRef] })) };
}

function fixture(options = {}) {
    const calls = [];
    let reads = 0;
    const installed = { node: 'r', status: 'installed', desiredState: 'installed', secretRevision: 41 };
    const state = Object.hasOwn(options, 'state') ? options.state : installed;
    const users = Object.hasOwn(options, 'users') ? options.users
        : state?.status === 'installed' ? [{ relayNode: 'r', enabled: true, desiredRevision: 41,
            appliedRevision: 41, syncStatus: 'synced', syncOperationId: OPERATION }] : [];
    const readback = Object.hasOwn(options, 'readback') ? options.readback
        : { ok: true, code: 'USERS_VERIFIED', credentialRevision: 41,
            enabledUserCount: 1, managedUserCount: 1 };
    const gate = createTopologyPppReadinessGate({ executionContext: TEST, readOnly: true,
        RelayL2tpState: { findOne: filter => query(() => {
            calls.push(['state', filter]);
            reads += 1;
            return reads > 1 && Object.hasOwn(options, 'current') ? options.current : state;
        }) },
        L2tpUser: { find: filter => query(() => { calls.push(['users', filter]); return users; }) },
        L2tpOperation: { findOne: filter => query(() => {
            calls.push(['operation', filter]);
            if (filter.status?.$in) return options.activeOperation || null;
            return options.noSyncProof ? null : { _id: OPERATION, node: 'r', kind: 'sync_users',
                status: 'succeeded', plan: { operationId: OPERATION, relayId: 'r',
                    desired: { credentialRevision: 41 } } };
        }) },
        HyNode: { findById: nodeId => query(() => {
            calls.push(['node', nodeId]);
            return { _id: nodeId, active: true, type: 'xray', cascadeRole: 'relay', ssh: {} };
        }) },
        NodeSSH: class ModeledReadOnlySSH {
            async exec(command, execOptions) {
                calls.push(['exec', command, execOptions]);
                if (options.unavailable) throw new Error('modeled private transport diagnostic');
                return { code: readback?.ok ? 0 : 65, stderr: '', stdout: `${JSON.stringify(readback)}\n` };
            }
        },
    });
    return { gate, calls };
}

const verified = { ok: true, verifiedRelayCount: 1,
    relayRevisions: [{ relayNode: 'r', credentialRevision: 41 }] };

function assertReadback(calls) {
    assert.deepEqual(calls.filter(([kind]) => kind === 'state').map(([, value]) => value),
        [{ node: 'r' }, { node: 'r' }], 'credential epoch is reread after the modeled remote verifier');
    const commands = calls.filter(([kind]) => kind === 'exec');
    assert.equal(commands.length, 1, 'installed PPP cannot be skipped because the plan is staged');
    assert.equal(commands[0][1], `test -d /var/lib/celerity/l2tp/operations/${OPERATION}`
        + ' && test -f /usr/local/lib/celerity/relay-l2tp/verify-users.sh'
        + ' && test -x /usr/local/lib/celerity/relay-l2tp/verify-users.sh'
        + ` && /usr/local/lib/celerity/relay-l2tp/verify-users.sh /var/lib/celerity/l2tp/operations/${OPERATION}`);
    assert.deepEqual(commands[0][2], { timeout: 120000 });
}

test('source-less staged R-to-B verifies installed PPP through the real read-only transport for either mode', async () => {
    for (const mode of ['forward', 'reverse']) {
        const plan = composedPlan({ mode });
        assert.equal(plan.staged, true);
        assert.ok(plan.nodes.some(node => node.role === 'bridge'));
        assert.ok(plan.nodes.every(node => node.role !== 'portal'));
        const { gate, calls } = fixture();
        assert.deepEqual(await gate.verifyPlan(plan), verified);
        assertReadback(calls);
    }
});

test('source-less suffix with explicitly uninstalled PPP proves zero users, no work and a stable absence epoch', async () => {
    for (const desiredState of ['absent', 'not_installed']) {
        const state = { node: 'r', status: 'not_installed', desiredState, secretRevision: 0 };
        const { gate, calls } = fixture({ state });
        assert.deepEqual(await gate.verifyPlan(composedPlan()), {
            ok: true, verifiedRelayCount: 0, relayRevisions: [], skippedRelayRevisions: [
                { relayNode: 'r', state: 'not_installed', desiredState, credentialRevision: 0 }],
        }, 'no terminal skip: missing portal input does not remove the bridge egress');
        assert.deepEqual(calls.filter(([kind]) => kind === 'users'), [['users', { relayNode: 'r' }]]);
        assert.deepEqual(calls.filter(([kind]) => kind === 'operation'), [['operation', {
            node: 'r', status: { $in: ['queued', 'running', 'rolling_back'] },
        }]]);
        assert.equal(calls.filter(([kind]) => kind === 'state').length, 2);
        assert.ok(!calls.some(([kind]) => kind === 'node' || kind === 'exec'));
    }
});

test('source-less does not turn missing PPP state into a bridge-less terminal exemption', async () => {
    for (const state of [null, { node: 'r', desiredState: 'absent' },
        { node: 'r', status: 'not_installed', desiredState: 'installed', secretRevision: 0 }]) {
        const { gate, calls } = fixture({ state });
        assert.deepEqual(await gate.verifyPlan(composedPlan()),
            { ok: false, verifiedRelayCount: 0, reason: 'PPP_NOT_INSTALLED' });
        assert.ok(calls.some(([kind]) => kind === 'state'), 'classify the suffix before reading actual PPP state');
        assert.ok(!calls.some(([kind]) => kind === 'exec'));
    }
});

test('source-less explicit absence still refuses users, active install/sync work and changed epochs', async () => {
    const state = { node: 'r', status: 'not_installed', desiredState: 'absent', secretRevision: 4 };
    for (const options of [
        { users: [{ relayNode: 'r' }] },
        { activeOperation: { _id: OPERATION } },
        { current: { ...state, secretRevision: 5 } },
        { current: { ...state, status: 'installed', desiredState: 'installed' } },
        { state: { ...state, secretRevision: undefined } },
    ]) {
        const { gate, calls } = fixture({ state, ...options });
        assert.deepEqual(await gate.verifyPlan(composedPlan()),
            { ok: false, verifiedRelayCount: 0, reason: 'PPP_UNKNOWN' });
        assert.ok(!calls.some(([kind]) => kind === 'exec'));
    }
});

test('source-less installed PPP retains drift, sync proof, verifier and fresh credential epoch guards', async () => {
    const cases = [
        { options: { users: [{ relayNode: 'r', enabled: true, desiredRevision: 41,
            appliedRevision: 40, syncStatus: 'synced', syncOperationId: OPERATION }] }, reason: 'PPP_DRIFT', remote: false },
        { options: { noSyncProof: true }, reason: 'PPP_UNKNOWN', remote: false },
        { options: { unavailable: true }, reason: 'PPP_UNAVAILABLE', remote: true },
        // The actual verifier transport rejects expectation-mismatched JSON
        // before the gate can classify it: this is unavailable, never drift.
        { options: { readback: { ok: true, code: 'USERS_VERIFIED', credentialRevision: 41,
            enabledUserCount: 0, managedUserCount: 0 } }, reason: 'PPP_UNAVAILABLE', remote: true },
        { options: { readback: { ok: false, code: 'MANAGED_USERS_MISSING', credentialRevision: 41,
            enabledUserCount: 1, managedUserCount: 0 } }, reason: 'PPP_DRIFT', remote: true },
        { options: { current: { status: 'installed', desiredState: 'installed', secretRevision: 42 } },
            reason: 'PPP_UNKNOWN', remote: true },
    ];
    for (const { options, reason, remote } of cases) {
        const { gate, calls } = fixture(options);
        assert.deepEqual(await gate.verifyPlan(composedPlan()), {
            ok: false, verifiedRelayCount: 0, reason,
            ...(reason === 'PPP_DRIFT' ? { relayNode: 'r', credentialRevision: 41 } : {}),
        });
        assert.equal(calls.some(([kind]) => kind === 'exec'), remote);
    }
});

test('bridge-less staged prefix keeps block routing while still verifying installed PPP users', async () => {
    for (const mode of ['forward', 'reverse']) {
        const plan = composedPlan({ sourceLess: false, noExit: true, mode });
        const relay = plan.nodes.find(node => node.role === 'relay');
        const config = JSON.parse(Buffer.from(relay.candidate.bytes).toString('utf8'));
        assert.equal(config.routing.rules.at(-1).outboundTag, 'block');
        assert.equal(config.outbounds.find(outbound => outbound.tag === 'block')?.protocol, 'blackhole');
        const { gate, calls } = fixture();
        assert.deepEqual(await gate.verifyPlan(plan), verified, 'user readback is not a PPP Internet proof');
        assertReadback(calls);
    }
});

test('bridge-less uninstalled terminal is explicitly skipped but its absence proof stays fenced', async () => {
    const state = { node: 'r', status: 'not_installed', desiredState: 'absent', secretRevision: 9 };
    const { gate, calls } = fixture({ state });
    assert.deepEqual(await gate.verifyPlan(composedPlan({ sourceLess: false, noExit: true })), {
        ok: true, verifiedRelayCount: 0, skippedRelayCount: 1, relayRevisions: [], skippedRelayRevisions: [
            { relayNode: 'r', state: 'not_installed', desiredState: 'absent', credentialRevision: 9 }],
    });
    assert.equal(calls.filter(([kind]) => kind === 'state').length, 2);
    assert.ok(!calls.some(([kind]) => kind === 'exec'));
});

test('malformed source-less refs still fail before persistence or transport', async () => {
    const plan = composedPlan();
    const relay = plan.nodes.find(node => node.role === 'relay');
    const bridge = plan.nodes.find(node => node.role === 'bridge');
    for (const nodes of [
        [relay, relay, bridge],
        [{ ...relay, nodeRef: 'relay-2' }, bridge],
        [{ ...relay, nodeRef: 'relay-01' }, bridge],
        [relay, { ...bridge, nodeRef: 'bridge-2' }],
        [relay, bridge, bridge],
        [relay, bridge, { role: 'portal', nodeRef: 'portal', node: 'p' }],
    ]) {
        const { gate, calls } = fixture();
        assert.deepEqual(await gate.verifyPlan({ ...plan, nodes }),
            { ok: false, verifiedRelayCount: 0, reason: 'PPP_UNKNOWN' });
        assert.deepEqual(calls, []);
    }
});

test('relay-root attach and replacement candidates carry real path ingress into staged PPP verification', async () => {
    for (const replacing of [false, true]) {
        const snapshot = {
            nodes: [{ _id: 'r', cascadeRole: 'relay' }, { _id: 'b', cascadeRole: 'bridge' }],
            links: [...(replacing ? [{ _id: 'old-exit', portalNode: 'r', bridgeNode: 'b',
                mode: 'reverse', active: true, status: 'online' }] : []),
            { _id: 'new-exit', portalNode: 'r', bridgeNode: 'b', mode: 'reverse', active: true, status: 'pending' }],
            groups: [{ _id: 'g', mode: 'reverse', strategy: 'priority-failover', paths: [
                { pathKey: 'mine', linkIds: replacing ? ['old-exit'] : [], priority: 4, enabled: true }],
            }], activeRouteGroupIds: ['g'], installedRouteGroupIds: ['g'],
            installedRouteOwners: [{ groupId: 'g', nodeId: 'r', pathKey: 'mine' }],
        };
        const before = structuredClone(snapshot);
        const { topology } = replacing ? deriveReplacementTopology(snapshot, {
            groupId: 'g', pathKey: 'mine', oldLinkId: 'old-exit', newLinkId: 'new-exit',
        }) : deriveAttachTopology(snapshot, { groupId: 'g', pathKey: 'mine', linkId: 'new-exit' });
        const plan = composedPlan({ topology });
        const relay = plan.nodes.find(node => node.role === 'relay');
        const config = JSON.parse(Buffer.from(relay.candidate.bytes).toString('utf8'));
        assert.ok(config.inbounds.some(inbound => inbound.tag === cascadePathIngressTag('mine')
            && inbound.protocol === 'socks'));
        assert.equal(plan.staged, true);
        const { gate, calls } = fixture();
        assert.deepEqual(await gate.verifyPlan(plan), verified);
        assertReadback(calls);
        assert.deepEqual(snapshot, before, 'readiness does not publish the proposed installed path');
    }
});

test('a geo bridge without default egress remains a blocked staged prefix, not an exemption from installed PPP checks', async () => {
    const topology = { nodes: [{ id: 'p', role: 'portal' }, { id: 'r', role: 'relay' },
        { id: 'geo-b', role: 'bridge' }], links: [
        { id: 'input', source: 'p', target: 'r', mode: 'reverse' },
        { id: 'geo', source: 'r', target: 'geo-b', mode: 'reverse', geo: true }], groups: [] };
    const plan = composedPlan({ topology });
    assert.equal(plan.staged, true);
    assert.ok(plan.nodes.some(node => node.role === 'bridge' && node.nodeRef === 'bridge-2'));
    const relay = plan.nodes.find(node => node.role === 'relay');
    const config = JSON.parse(Buffer.from(relay.candidate.bytes).toString('utf8'));
    assert.equal(config.routing.rules.at(-1).outboundTag, 'block');
    const { gate, calls } = fixture();
    assert.deepEqual(await gate.verifyPlan(plan), verified);
    assertReadback(calls);
});
