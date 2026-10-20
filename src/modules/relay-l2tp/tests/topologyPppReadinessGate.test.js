'use strict';
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');

const assert = require('node:assert/strict');
const test = require('node:test');
const { TopologyPppReadinessGate, createTopologyPppReadinessGate } = require('../services/topologyPppReadinessGate');

function fixture(overrides = {}) {
    const calls = [];
    const state = { node: 'node-r', status: 'installed', desiredState: 'installed', secretRevision: 41 };
    const users = [{ relayNode: 'node-r', login: 'alice', enabled: true, desiredRevision: 41,
        appliedRevision: 41, syncStatus: 'synced', syncOperationId: 'abcdef012345abcdef012345' }];
    const operation = { _id: 'abcdef012345abcdef012345', node: 'node-r', kind: 'sync_users',
        status: 'succeeded', plan: { operationId: 'abcdef012345abcdef012345', relayId: 'node-r',
            desired: { credentialRevision: 41 } } };
    const deps = {
        RelayL2tpState: { findOne: () => ({ select: () => ({ lean: async () => state }) }) },
        L2tpUser: { find: () => ({ select: () => ({ lean: async () => users }) }) },
        L2tpOperation: { findOne: () => ({ sort: () => ({ select: () => ({ lean: async () => operation }) }) }) },
        transportResolver: async ({ nodeId }) => {
            calls.push(['resolve', nodeId]);
            return { runArtifactCommand: async request => {
                calls.push(['verify', request]);
                return { ok: true, code: 'USERS_VERIFIED', credentialRevision: 41,
                    enabledUserCount: 1, managedUserCount: 1 };
            } };
        },
    };
    return { gate: new TopologyPppReadinessGate({ ...deps, ...overrides }), calls, deps };
}

const plan = { nodes: [{ role: 'portal', node: 'node-p' }, { role: 'relay', node: 'node-r' }] };

test('read-only gate selects only direct verifier and never falls back to runner', async () => {
    const calls = [];
    const { gate } = fixture({
        readOnly: true,
        transportResolver: async () => ({
            runArtifactCommand() { throw new Error('runner must not be called'); },
            async verifyUsersReadOnly(request) {
                calls.push(request);
                throw new Error('missing pre-installed verifier');
            },
        }),
    });
    assert.deepEqual(await gate.verifyPlan(plan),
        { ok: false, verifiedRelayCount: 0, reason: 'PPP_UNAVAILABLE' });
    assert.deepEqual(calls, [{ operationId: 'abcdef012345abcdef012345',
        expectedCredentialRevision: 41, expectedEnabledUserCount: 1 }]);
});

test('factory opts in to read-only mode without changing default mode', () => {
    const deps = { RelayL2tpState: { findOne() {} }, L2tpUser: { find() {} },
        L2tpOperation: { findOne() {} }, HyNode: { findById() {} }, NodeSSH: class {} };
    assert.equal(createTopologyPppReadinessGate({ ...deps, executionContext: TEST }).readOnly, false);
    assert.equal(createTopologyPppReadinessGate({ executionContext: TEST, ...deps, readOnly: true }).readOnly, true);
});

test('factory read-only gate uses pre-installed verifier without runner or bootstrap', async () => {
    const { deps } = fixture();
    const calls = [];
    const gate = createTopologyPppReadinessGate({ executionContext: TEST,
        ...deps,
        readOnly: true,
        HyNode: { findById: () => ({ select: () => ({ lean: async () => ({
            _id: 'node-r', active: true, type: 'xray', cascadeRole: 'relay', ssh: {},
        }) }) }) },
        NodeSSH: class {
            async exec(command, options) {
                calls.push({ command, options });
                return { code: 0, stderr: '', stdout: `${JSON.stringify({
                    ok: true, code: 'USERS_VERIFIED', credentialRevision: 41,
                    enabledUserCount: 1, managedUserCount: 1,
                })}\n` };
            }
        },
    });
    assert.deepEqual(await gate.verifyPlan(plan), { ok: true, verifiedRelayCount: 1,
        relayRevisions: [{ relayNode: 'node-r', credentialRevision: 41 }] });
    assert.deepEqual(calls, [{
        command: 'test -d /var/lib/celerity/l2tp/operations/abcdef012345abcdef012345'
            + ' && test -f /usr/local/lib/celerity/relay-l2tp/verify-users.sh'
            + ' && test -x /usr/local/lib/celerity/relay-l2tp/verify-users.sh'
            + ' && /usr/local/lib/celerity/relay-l2tp/verify-users.sh /var/lib/celerity/l2tp/operations/abcdef012345abcdef012345',
        options: { timeout: 120000 },
    }]);
});

test('read-only installed verifier preserves a proven PPP drift for retry', async () => {
    const { deps } = fixture();
    const gate = createTopologyPppReadinessGate({ executionContext: TEST,
        ...deps, readOnly: true,
        HyNode: { findById: () => ({ select: () => ({ lean: async () => ({
            _id: 'node-r', active: true, type: 'xray', cascadeRole: 'relay', ssh: {},
        }) }) }) },
        NodeSSH: class {
            async exec() {
                return { code: 65, stderr: '', stdout: `${JSON.stringify({
                    ok: false, code: 'MANAGED_USERS_MISSING', credentialRevision: 41,
                    enabledUserCount: 1, managedUserCount: 0,
                })}\n` };
            }
        },
    });
    assert.deepEqual(await gate.verifyPlan(plan), {
        ok: false, verifiedRelayCount: 0, reason: 'PPP_DRIFT',
        relayNode: 'node-r', credentialRevision: 41,
    });
});

test('installed relay is ready only after SSH artifact verification of persisted synced snapshot', async () => {
    const { gate, calls } = fixture();
    assert.deepEqual(await gate.verifyPlan(plan), { ok: true, verifiedRelayCount: 1, relayRevisions: [{ relayNode: 'node-r', credentialRevision: 41 }] });
    assert.deepEqual(calls, [
        ['resolve', 'node-r'],
        ['verify', { operationId: 'abcdef012345abcdef012345', command: 'verify-users',
            expectedCredentialRevision: 41, expectedEnabledUserCount: 1 }],
    ]);
});

test('staged relay without installed PPP is skipped, never claimed node-verified', async () => {
    const { gate, calls } = fixture({ RelayL2tpState: { findOne: () => ({ select: () => ({ lean: async () => null }) }) } });
    assert.deepEqual(await gate.verifyPlan({ staged: true, nodes: [
        { ...plan.nodes[0], nodeRef: 'portal' }, { ...plan.nodes[1], nodeRef: 'relay-1' },
    ] }),
        { ok: true, verifiedRelayCount: 0, skippedRelayCount: 1, relayRevisions: [], skippedRelayRevisions: [{ relayNode: 'node-r', state: 'unfenced' }] });
    assert.deepEqual(calls, []);
});

test('staged fan-in with two portals and one absent terminal relay remains blocked without PPP', async () => {
    const { gate, calls } = fixture({
        RelayL2tpState: { findOne: () => ({ select: () => ({ lean: async () =>
            ({ status: 'not_installed', desiredState: 'not_installed', secretRevision: 59 }) }) }) },
        L2tpUser: { find: () => ({ select: () => ({ lean: async () => [] }) }) },
        L2tpOperation: { findOne: () => ({ select: () => ({ lean: async () => null }) }) },
    });
    const nodes = [
        { role: 'portal', node: 'node-p1', nodeRef: 'portal-1' },
        { role: 'portal', node: 'node-p2', nodeRef: 'portal-2' },
        { role: 'relay', node: 'node-r', nodeRef: 'relay-1' },
    ];
    assert.deepEqual(await gate.verifyPlan({ staged: true, nodes }),
        { ok: true, verifiedRelayCount: 0, skippedRelayCount: 1, relayRevisions: [], skippedRelayRevisions: [
            { relayNode: 'node-r', state: 'not_installed', desiredState: 'not_installed', credentialRevision: 59 }] });
    assert.deepEqual(calls, []);
    for (const bad of [
        [nodes[0], { ...nodes[1], nodeRef: 'portal-3' }, nodes[2]],
        [nodes[0], { ...nodes[1], nodeRef: 'portal-1' }, nodes[2]],
        [nodes[0], { ...nodes[1], nodeRef: 'portal' }, nodes[2]],
    ]) {
        assert.deepEqual(await gate.verifyPlan({ staged: true, nodes: bad }),
            { ok: false, verifiedRelayCount: 0, reason: 'PPP_UNKNOWN' });
    }
});

const stagedTwoRelayPlan = { staged: true, nodes: [
    { role: 'relay', node: 'node-t', nodeRef: 'relay-2', checks: [] },
    { role: 'portal', node: 'node-p', nodeRef: 'portal' },
    { role: 'relay', node: 'node-r', nodeRef: 'relay-1', checks: [] },
] };

test('staged intermediate without PPP fails even without L2TP ingress and terminal PPP', async () => {
    const { gate, calls } = fixture({ RelayL2tpState: { findOne: () => ({ select: () => ({ lean: async () => null }) }) } });
    assert.deepEqual(await gate.verifyPlan(stagedTwoRelayPlan), { ok: false, verifiedRelayCount: 0, reason: 'PPP_NOT_INSTALLED' });
    assert.deepEqual(calls, []);
});

test('staged intermediate with desired-absent PPP fails despite a canonical terminal', async () => {
    const { gate, calls } = fixture({ RelayL2tpState: { findOne: () => ({ select: () => ({ lean: async () => (
        { node: 'node-r', desiredState: 'absent' }
    ) }) }) } });
    assert.deepEqual(await gate.verifyPlan(stagedTwoRelayPlan), { ok: false, verifiedRelayCount: 0, reason: 'PPP_NOT_INSTALLED' });
    assert.deepEqual(calls, []);
});

test('staged explicit non-PPP transit with zero users allows an absent terminal relay', async () => {
    const byNode = node => node === 'node-r'
        ? { node, status: 'not_installed', desiredState: 'absent', secretRevision: 9 }
        : { node, status: 'not_installed', desiredState: 'absent', secretRevision: 4 };
    const { gate, calls } = fixture({
        RelayL2tpState: { findOne: ({ node }) => ({ select: () => ({ lean: async () => byNode(node) }) }) },
        L2tpUser: { find: () => ({ select: () => ({ lean: async () => [] }) }) },
        L2tpOperation: { findOne: () => ({ select: () => ({ lean: async () => null }) }) },
    });
    assert.deepEqual(await gate.verifyPlan(stagedTwoRelayPlan),
        { ok: true, verifiedRelayCount: 0, skippedRelayCount: 1, relayRevisions: [], skippedRelayRevisions: [
            { relayNode: 'node-t', state: 'not_installed', desiredState: 'absent', credentialRevision: 4 },
            { relayNode: 'node-r', state: 'not_installed', desiredState: 'absent', credentialRevision: 9 }] });
    assert.deepEqual(calls, []);
});

test('staged non-PPP transit rejects users, active work and revision drift', async () => {
    for (const failure of ['users', 'active', 'drift']) {
        let reads = 0;
        const { gate } = fixture({
            RelayL2tpState: { findOne: ({ node }) => ({ select: () => ({ lean: async () => {
                if (node === 'node-t') return { status: 'not_installed', desiredState: 'absent', secretRevision: 4 };
                reads += 1;
                return { status: 'not_installed', desiredState: 'absent',
                    secretRevision: failure === 'drift' && reads > 1 ? 10 : 9 };
            } }) }) },
            L2tpUser: { find: () => ({ select: () => ({ lean: async () =>
                failure === 'users' ? [{ relayNode: 'node-r' }] : [] }) }) },
            L2tpOperation: { findOne: () => ({ select: () => ({ lean: async () =>
                failure === 'active' ? { _id: 'busy' } : null }) }) },
        });
        assert.deepEqual(await gate.verifyPlan(stagedTwoRelayPlan),
            { ok: false, verifiedRelayCount: 0, reason: 'PPP_UNKNOWN' }, failure);
    }
});

test('staged verified intermediate and absent terminal allows exactly one skip regardless of deployment order', async () => {
    const { gate, calls } = fixture({ RelayL2tpState: { findOne: ({ node }) => ({ select: () => ({
        lean: async () => node === 'node-r'
            ? { node, status: 'installed', desiredState: 'installed', secretRevision: 41 }
            : { node, desiredState: 'absent' },
    }) }) } });
    assert.deepEqual(await gate.verifyPlan(stagedTwoRelayPlan),
        { ok: true, verifiedRelayCount: 1, skippedRelayCount: 1,
            relayRevisions: [{ relayNode: 'node-r', credentialRevision: 41 }],
            skippedRelayRevisions: [{ relayNode: 'node-t', state: 'unfenced' }] });
    assert.deepEqual(calls.map(([action, value]) => [action, value?.command ?? value]),
        [['resolve', 'node-r'], ['verify', 'verify-users']]);
});

test('staged installed owner accepts verified legacy non-PPP terminal without direct egress', async () => {
    const { gate, calls } = fixture({
        RelayL2tpState: { findOne: ({ node }) => ({ select: () => ({ lean: async () =>
            node === 'node-r'
                ? { node, status: 'installed', desiredState: 'installed', secretRevision: 41 }
                : { node, status: 'not_installed', desiredState: 'not_installed', secretRevision: 9 }
        }) }) },
        L2tpUser: { find: ({ relayNode }) => ({ select: () => ({ lean: async () =>
            relayNode === 'node-r' ? [{ relayNode, enabled: true, desiredRevision: 41,
                appliedRevision: 41, syncStatus: 'synced', syncOperationId: 'abcdef012345abcdef012345' }] : []
        }) }) },
        L2tpOperation: { findOne: filter => {
            if (filter.status?.$in) return { select: () => ({ lean: async () => null }) };
            const operation = { _id: 'abcdef012345abcdef012345', node: 'node-r',
                kind: 'sync_users', status: 'succeeded', plan: {
                    operationId: 'abcdef012345abcdef012345', relayId: 'node-r',
                    desired: { credentialRevision: 41 },
                } };
            return { sort: () => ({ select: () => ({ lean: async () => operation }) }) };
        } },
    });
    assert.deepEqual(await gate.verifyPlan(stagedTwoRelayPlan),
        { ok: true, verifiedRelayCount: 1, skippedRelayCount: 1,
            relayRevisions: [{ relayNode: 'node-r', credentialRevision: 41 }],
            skippedRelayRevisions: [{ relayNode: 'node-t', state: 'not_installed', desiredState: 'not_installed', credentialRevision: 9 }] });
    assert.deepEqual(calls.map(([action, value]) => [action, value?.command ?? value]),
        [['resolve', 'node-r'], ['verify', 'verify-users']]);
});

test('installed staged terminal still requires node-side verify-users', async () => {
    const calls = [];
    const { gate } = fixture({
        RelayL2tpState: { findOne: ({ node }) => ({ select: () => ({ lean: async () => (
            { node, status: 'installed', desiredState: 'installed', secretRevision: 41 }
        ) }) }) },
        L2tpUser: { find: ({ relayNode }) => ({ select: () => ({ lean: async () => ([{
            relayNode, enabled: true, desiredRevision: 41, appliedRevision: 41,
            syncStatus: 'synced', syncOperationId: 'abcdef012345abcdef012345',
        }]) }) }) },
        L2tpOperation: { findOne: ({ node }) => ({ sort: () => ({ select: () => ({ lean: async () => ({
            _id: 'abcdef012345abcdef012345', node, kind: 'sync_users', status: 'succeeded',
            plan: { operationId: 'abcdef012345abcdef012345', relayId: node,
                desired: { credentialRevision: 41 } },
        }) }) }) }) },
        transportResolver: async ({ nodeId }) => ({ runArtifactCommand: async request => {
            calls.push([nodeId, request.command]);
            return nodeId === 'node-t' ? { ok: false } : {
                ok: true, code: 'USERS_VERIFIED', credentialRevision: 41,
                enabledUserCount: 1, managedUserCount: 1,
            };
        } }),
    });
    assert.deepEqual(await gate.verifyPlan(stagedTwoRelayPlan), { ok: false, verifiedRelayCount: 0, reason: 'PPP_UNKNOWN' });
    assert.deepEqual(calls, [['node-t', 'verify-users']]);
});

test('malformed staged refs and extra roles fail before any PPP or remote verification', async () => {
    const checkedNodes = [];
    const { gate, calls } = fixture({ RelayL2tpState: { findOne: ({ node }) => {
        checkedNodes.push(node);
        throw new Error('must reject staged shape before readback');
    } } });
    const [terminal, portal, intermediate] = stagedTwoRelayPlan.nodes;
    const invalidNodes = [
        [terminal, portal, { ...intermediate, nodeRef: 'relay-2' }], // duplicate
        [terminal, portal, { ...intermediate, nodeRef: 'relay-3' }], // gap
        [terminal, portal, { ...intermediate, nodeRef: 'relay-01' }], // malformed
        [terminal, portal, { ...intermediate, nodeRef: 'relay-9007199254740992' }],
        [terminal, intermediate], // no portal
        [terminal, portal, intermediate, { role: 'portal', nodeRef: 'portal' }],
        [terminal, portal, intermediate, { role: 'bridge', nodeRef: 'bridge' }],
    ];
    for (const nodes of invalidNodes) {
        assert.deepEqual(await gate.verifyPlan({ staged: true, nodes }),
            { ok: false, verifiedRelayCount: 0, reason: 'PPP_UNKNOWN' });
    }
    assert.deepEqual(checkedNodes, []);
    assert.deepEqual(calls, []);
});

test('non-staged relay without installed PPP fails closed rather than claiming readiness', async () => {
    const { gate, calls } = fixture({ RelayL2tpState: { findOne: () => ({ select: () => ({ lean: async () => null }) }) } });
    assert.deepEqual(await gate.verifyPlan(plan), { ok: false, verifiedRelayCount: 0, reason: 'PPP_NOT_INSTALLED' });
    assert.deepEqual(calls, []);
});

test('explicit non-PPP transit relay with no users or active L2TP work does not block installed owner readback', async () => {
    const stateByNode = node => node === 'node-r'
        ? { node, status: 'installed', desiredState: 'installed', secretRevision: 41 }
        : { node, status: 'not_installed', desiredState: 'not_installed', secretRevision: 9 };
    const baseOperation = { _id: 'abcdef012345abcdef012345', node: 'node-r', kind: 'sync_users',
        status: 'succeeded', plan: { operationId: 'abcdef012345abcdef012345', relayId: 'node-r',
            desired: { credentialRevision: 41 } } };
    const installedUser = { relayNode: 'node-r', enabled: true, desiredRevision: 41,
        appliedRevision: 41, syncStatus: 'synced', syncOperationId: 'abcdef012345abcdef012345' };
    const transitPlan = { nodes: [plan.nodes[0], plan.nodes[1],
        { role: 'relay', node: 'node-t' }, { role: 'bridge', node: 'node-b' }] };
    const make = (options = {}) => {
        const { users = [], active = false } = options;
        let transitReads = 0;
        return fixture({
            RelayL2tpState: { findOne: ({ node }) => ({ select: () => ({ lean: async () => {
                if (node !== 'node-t') return stateByNode(node);
                const state = Object.prototype.hasOwnProperty.call(options, 'transitState')
                    ? options.transitState : stateByNode(node);
                transitReads += 1;
                return state && options.driftRevision && transitReads > 1
                    ? { ...state, secretRevision: state.secretRevision + 1 } : state;
            } }) }) },
            L2tpUser: { find: ({ relayNode }) => ({ select: () => ({ lean: async () =>
                relayNode === 'node-t' ? users : [installedUser] }) }) },
            L2tpOperation: { findOne: filter => filter.status?.$in
                ? { select: () => ({ lean: async () => active ? { _id: 'busy' } : null }) }
                : { sort: () => ({ select: () => ({ lean: async () => baseOperation }) }) } },
        });
    };
    const ready = make();
    assert.deepEqual(await ready.gate.verifyPlan(transitPlan),
        { ok: true, verifiedRelayCount: 1, relayRevisions: [{ relayNode: 'node-r', credentialRevision: 41 }],
            skippedRelayRevisions: [{ relayNode: 'node-t', state: 'not_installed', desiredState: 'not_installed', credentialRevision: 9 }] });
    assert.deepEqual(ready.calls.map(([action, value]) => [action, value?.command ?? value]),
        [['resolve', 'node-r'], ['verify', 'verify-users']]);
    assert.deepEqual(await make({ transitState: {
        status: 'not_installed', desiredState: 'absent', secretRevision: 9,
    } }).gate.verifyPlan(transitPlan), { ok: true, verifiedRelayCount: 1, relayRevisions: [{ relayNode: 'node-r', credentialRevision: 41 }],
            skippedRelayRevisions: [{ relayNode: 'node-t', state: 'not_installed', desiredState: 'absent', credentialRevision: 9 }] });
    const stagedTransit = { staged: true, nodes: [
        { ...plan.nodes[0], nodeRef: 'portal' },
        { ...plan.nodes[1], nodeRef: 'relay-1' },
        { role: 'relay', node: 'node-t', nodeRef: 'relay-2' },
    ] };
    assert.deepEqual(await make().gate.verifyPlan(stagedTransit),
        { ok: true, verifiedRelayCount: 1, skippedRelayCount: 1,
            relayRevisions: [{ relayNode: 'node-r', credentialRevision: 41 }],
            skippedRelayRevisions: [{ relayNode: 'node-t', state: 'not_installed', desiredState: 'not_installed', credentialRevision: 9 }] });
    for (const options of [
        { users: [{ relayNode: 'node-t' }] },
        { active: true },
        { driftRevision: true },
    ]) {
        assert.deepEqual(await make(options).gate.verifyPlan(stagedTransit),
            { ok: false, verifiedRelayCount: 1, reason: 'PPP_UNKNOWN' });
    }
    for (const options of [
        { users: [{ relayNode: 'node-t' }] },
        { active: true },
        { driftRevision: true },
        { transitState: { status: 'not_installed', desiredState: 'not_installed' } },
        { transitState: { status: 'installed', desiredState: 'not_installed' } },
        { transitState: null },
    ]) {
        const { gate } = make(options);
        assert.deepEqual(await gate.verifyPlan(transitPlan),
            { ok: false, verifiedRelayCount: 1,
                reason: options.transitState === null || options.transitState?.status === 'installed'
                    ? 'PPP_NOT_INSTALLED' : 'PPP_UNKNOWN' });
    }
});

test('runner unavailable fails closed without leaking remote diagnostics', async () => {
    const { gate } = fixture({ transportResolver: async () => ({ runArtifactCommand: async () => {
        throw new Error('private-ppp-password');
    } }) });
    const result = await gate.verifyPlan(plan);
    assert.deepEqual(result, { ok: false, verifiedRelayCount: 0, reason: 'PPP_UNAVAILABLE' });
    assert.doesNotMatch(JSON.stringify(result), /private-ppp-password/);
});

test('Mongo-only success cannot pass without a valid node response', async () => {
    const { gate } = fixture({ transportResolver: async () => ({ runArtifactCommand: async () => ({
        ok: true, code: 'USERS_VERIFIED', credentialRevision: 41, enabledUserCount: 0, managedUserCount: 0,
    }) }) });
    assert.deepEqual(await gate.verifyPlan(plan), { ok: false, verifiedRelayCount: 0, reason: 'PPP_UNKNOWN' });
});

test('unavailable or stale durable sync operation cannot pass', async () => {
    const { gate, calls } = fixture({ L2tpOperation: { findOne: () => ({ sort: () => ({ select: () => ({ lean: async () => null }) }) }) } });
    assert.deepEqual(await gate.verifyPlan(plan), { ok: false, verifiedRelayCount: 0, reason: 'PPP_UNKNOWN' });
    assert.deepEqual(calls, []);
});

test('verified node-side managed-user drift alone is sync eligible', async () => {
    const { gate } = fixture({ transportResolver: async () => ({ runArtifactCommand: async () => ({
        ok: false, code: 'MANAGED_USERS_ALTERED', credentialRevision: 41,
        enabledUserCount: 1, managedUserCount: 1,
    }) }) });
    assert.deepEqual(await gate.verifyPlan(plan),
        { ok: false, verifiedRelayCount: 0, reason: 'PPP_DRIFT',
            relayNode: 'node-r', credentialRevision: 41 });
});

test('node-side drift against a superseded state snapshot is not sync eligible', async () => {
    let reads = 0;
    const { gate } = fixture({
        RelayL2tpState: { findOne: () => ({ select: () => ({ lean: async () => {
            reads += 1;
            return { status: 'installed', desiredState: 'installed',
                secretRevision: reads === 1 ? 41 : 42 };
        } }) }) },
        transportResolver: async () => ({ runArtifactCommand: async () => ({
            ok: false, code: 'MANAGED_USERS_MISSING', credentialRevision: 41,
            enabledUserCount: 1, managedUserCount: 0,
        }) }),
    });
    assert.deepEqual(await gate.verifyPlan(plan),
        { ok: false, verifiedRelayCount: 0, reason: 'PPP_UNKNOWN' });
});

test('SSH or agent failure is unavailable, not sync eligible or diagnostic-bearing', async () => {
    for (const transportResolver of [
        async () => { throw new Error('private-ppp-password'); },
        async () => ({ runArtifactCommand: async () => { throw new Error('private-ppp-password'); } }),
    ]) {
        const { gate } = fixture({ transportResolver });
        assert.deepEqual(await gate.verifyPlan(plan),
            { ok: false, verifiedRelayCount: 0, reason: 'PPP_UNAVAILABLE' });
    }
});

test('absent and not-installed PPP are never mistaken for credential drift', async () => {
    for (const state of [null, { status: 'not_installed', desiredState: 'installed', secretRevision: 0 }]) {
        const { gate, calls } = fixture({ RelayL2tpState: { findOne: () => ({
            select: () => ({ lean: async () => state }),
        }) } });
        assert.deepEqual(await gate.verifyPlan(plan),
            { ok: false, verifiedRelayCount: 0, reason: 'PPP_NOT_INSTALLED' });
        assert.deepEqual(calls, []);
    }
});

test('ambiguous remote failures, malformed replies and missing sync proof stay unknown', async () => {
    for (const actual of [
        null,
        { ok: false, code: 'MANAGED_USERS_ALTERED', credentialRevision: 40,
            enabledUserCount: 1, managedUserCount: 1 },
        { ok: false, code: 'MANAGED_USERS_ALTERED', credentialRevision: 41,
            enabledUserCount: 0, managedUserCount: 1 },
        { ok: false, code: 'CHAP_SECRETS_INVALID', credentialRevision: 41,
            enabledUserCount: 1, managedUserCount: 0 },
        { ok: false, code: 'UNMANAGED_USERS_COLLISION', credentialRevision: 41,
            enabledUserCount: 1, managedUserCount: 0 },
        { ok: false, code: 'invented-sensitive-error' },
        { ok: true, code: 'USERS_VERIFIED', credentialRevision: 41,
            enabledUserCount: 0, managedUserCount: 0 },
    ]) {
        const { gate } = fixture({ transportResolver: async () => ({
            runArtifactCommand: async () => actual,
        }) });
        assert.deepEqual(await gate.verifyPlan(plan),
            { ok: false, verifiedRelayCount: 0, reason: 'PPP_UNKNOWN' });
    }
    const { gate } = fixture({ L2tpOperation: { findOne: () => ({
        sort: () => ({ select: () => ({ lean: async () => null }) }),
    }) } });
    assert.deepEqual(await gate.verifyPlan(plan),
        { ok: false, verifiedRelayCount: 0, reason: 'PPP_UNKNOWN' });
});

test('freshly verified relays expose ordered revision proof, excluding staged skip', async () => {
    const byNode = node => node === 'node-r'
        ? { node, status: 'installed', desiredState: 'installed', secretRevision: 41 }
        : node === 'node-s'
            ? { node, status: 'installed', desiredState: 'installed', secretRevision: 42 }
            : { node, desiredState: 'absent' };
    const operationId = 'abcdef012345abcdef012345';
    const { gate } = fixture({
        RelayL2tpState: { findOne: ({ node }) => ({ select: () => ({ lean: async () => byNode(node) }) }) },
        L2tpUser: { find: ({ relayNode }) => ({ select: () => ({ lean: async () => [{
            relayNode, enabled: true, desiredRevision: byNode(relayNode).secretRevision,
            appliedRevision: byNode(relayNode).secretRevision, syncStatus: 'synced', syncOperationId: operationId,
        }] }) }) },
        L2tpOperation: { findOne: ({ node }) => ({ sort: () => ({ select: () => ({ lean: async () => ({
            _id: operationId, node, kind: 'sync_users', status: 'succeeded', plan: {
                operationId, relayId: node, desired: { credentialRevision: byNode(node).secretRevision },
            },
        }) }) }) }) },
        transportResolver: async ({ nodeId }) => ({ async runArtifactCommand() {
            return { ok: true, code: 'USERS_VERIFIED', credentialRevision: byNode(nodeId).secretRevision,
                enabledUserCount: 1, managedUserCount: 1 };
        } }),
    });
    assert.deepEqual(await gate.verifyPlan({ staged: true, nodes: [
        { role: 'portal', node: 'node-p', nodeRef: 'portal' },
        { role: 'relay', node: 'node-r', nodeRef: 'relay-1' },
        { role: 'relay', node: 'node-s', nodeRef: 'relay-2' },
        { role: 'relay', node: 'node-t', nodeRef: 'relay-3' },
    ] }), { ok: true, verifiedRelayCount: 2, skippedRelayCount: 1,
        relayRevisions: [{ relayNode: 'node-r', credentialRevision: 41 },
            { relayNode: 'node-s', credentialRevision: 42 }],
        skippedRelayRevisions: [{ relayNode: 'node-t', state: 'unfenced' }] });
});

test('persisted desired/applied credential revision mismatch is drift', async () => {
    const { gate, calls } = fixture({ L2tpUser: { find: () => ({ select: () => ({ lean: async () => ([{
        relayNode: 'node-r', enabled: true, desiredRevision: 41, appliedRevision: 40,
        syncStatus: 'synced', syncOperationId: 'abcdef012345abcdef012345',
    }]) }) }) } });
    assert.deepEqual(await gate.verifyPlan(plan),
        { ok: false, verifiedRelayCount: 0, reason: 'PPP_DRIFT',
            relayNode: 'node-r', credentialRevision: 41 });
    assert.deepEqual(calls, []);
});
