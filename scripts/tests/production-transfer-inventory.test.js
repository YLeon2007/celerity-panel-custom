'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const path = require('node:path');

// Load inside the test so RED is an assertion failure, not a loader crash.
const modulePath = path.resolve(__dirname, '../production-transfer-inventory.js');
const H = 'a'.repeat(64);
const U = 'b'.repeat(64);

function fixture() {
    const nodes = [
        { _id: 'p1', cascadeRole: 'portal' },
        { _id: 'b1', cascadeRole: 'bridge' },
    ].map(node => ({ ...node, type: 'xray', active: true, status: 'online',
        executionHostId: `host-${node._id}`, profileIds: [`profile-${node._id}`] }));
    const links = [{ _id: 'l1', portalNode: 'p1', bridgeNode: 'b1',
        mode: 'reverse', tunnelPort: 10086, active: true, status: 'online' }];
    const profiles = nodes.map(node => ({ _id: `profile-${node._id}`, nodeId: node._id,
        targetProfile: 'xray-main', ownedLinkIds: ['l1'],
        config: { path: '/usr/local/etc/xray/config.json', sha256: H },
        unit: { name: 'xray.service', sha256: U, configPath: '/usr/local/etc/xray/config.json' },
        serviceState: { loadState: 'loaded', activeState: 'active', subState: 'running',
            configSha256: H, unitSha256: U },
        egress: node.cascadeRole === 'bridge'
            ? { kind: 'direct', configSha256: H }
            : { kind: 'links', linkIds: ['l1'], configSha256: H },
    }));
    return { schemaVersion: 1, snapshotId: 'export-1', serverIdentity: 'prod',
        capturedAt: '2026-10-19T10:00:00.000Z',
        completeness: { links: true, nodes: true, profiles: true, listeners: true },
        nodes, links, profiles,
        listeners: [{ linkId: 'l1', nodeId: 'p1', profileId: 'profile-p1', port: 10086,
            network: 'tcp', bindAddress: '0.0.0.0', configSha256: H, unitSha256: U }] };
}

function expected(api, records) {
    return { linkIds: records.links.map(link => link._id),
        linkFingerprints: Object.fromEntries(records.links.map(link => [link._id, api.fingerprintLink(link)])) };
}

test('builds an exact reverse-listener preflight without authorizing execution or client readiness', () => {
    let api;
    assert.doesNotThrow(() => { api = require(modulePath); }, 'inventory module must exist');
    const records = fixture();
    const before = JSON.stringify(records);
    const result = api.buildTransferManifest(records, expected(api, records));
    assert.equal(result.inventoryReady, true);
    assert.deepEqual(result.reasons, []);
    assert.equal(result.clientReady, false);
    assert.equal(result.executionAuthorized, false);
    assert.match(result.inputSha256, /^[a-f0-9]{64}$/);
    assert.equal(JSON.stringify(records), before);
    assert.deepEqual(result.manifest.affectedNodeIds, ['b1', 'p1']);
    assert.deepEqual(result.manifest.affectedProfileIds, ['profile-b1', 'profile-p1']);
    assert.deepEqual(result.manifest.components, [{ nodeIds: ['b1', 'p1'], linkIds: ['l1'],
        bridgeNodeIds: ['b1'], staged: false }]);
    const listener = result.manifest.listenerTransfers[0];
    assert.equal(listener.listenerNodeId, 'p1');
    assert.equal(listener.dialerNodeId, 'b1');
    assert.equal(listener.profileId, 'profile-p1');
    assert.equal(listener.mode, 'reverse');
    assert.equal(listener.action, 'preserve-exact-listener');
    assert.ok(Object.isFrozen(result.manifest));
});

function hasReason(result, code) {
    assert.equal(result.inventoryReady, false);
    assert.equal(result.manifest, null);
    assert.ok(result.reasons.some(reason => reason.code === code), JSON.stringify(result.reasons));
}

test('fails closed on missing, duplicate, changed and unpinned expected active/online links', () => {
    const api = require(modulePath);
    const cases = [
        ['EXPECTED_LINK_MISSING', records => { records.links = []; }],
        ['DUPLICATE_LINK', records => { records.links.push({ ...records.links[0] }); }],
        ['LINK_NOT_ACTIVE_ONLINE', records => { records.links[0].active = false; }],
        ['LINK_NOT_ACTIVE_ONLINE', records => { records.links[0].status = 'offline'; }],
        ['LINK_CHANGED', records => { records.links[0].tunnelPort += 1; }],
        ['LINK_CHANGED', records => { records.links[0].tunnelUuid = 'changed-private-value'; }],
    ];
    for (const [code, mutate] of cases) {
        const records = fixture();
        const pinned = expected(api, records);
        mutate(records);
        hasReason(api.buildTransferManifest(records, pinned), code);
    }
    const records = fixture();
    hasReason(api.buildTransferManifest(records, { linkIds: ['l1'] }), 'LINK_BASELINE_REQUIRED');
    const pinned = expected(api, records);
    pinned.linkIds.push('l1');
    hasReason(api.buildTransferManifest(records, pinned), 'DUPLICATE_EXPECTED_LINK');
    hasReason(api.buildTransferManifest(records, { linkIds: [], linkFingerprints: {} }), 'EXPECTED_LINK_IDS_REQUIRED');
});

function mixedFixture() {
    const records = fixture();
    const pairs = [['p1', 'b1'], ['p2', 'b1'], ['p1', 'b2'], ['p3', 'b3'],
        ['p4', 'b4'], ['p5', 'b5'], ['p6', 'b6'], ['p7', 'b7'], ['p8', 'b8'], ['p8', 'b9']];
    records.links = pairs.map(([portalNode, bridgeNode], index) => ({
        _id: `l${String(index + 1).padStart(2, '0')}`, portalNode, bridgeNode,
        mode: index < 8 ? 'reverse' : 'forward', tunnelPort: 11000 + index,
        active: true, status: 'online', tunnelUuid: 'synthetic-secret-never-emit',
    }));
    const ids = [...new Set(pairs.flat())];
    records.nodes = ids.map(_id => ({ ...fixture().nodes[0], _id,
        cascadeRole: _id.startsWith('p') ? 'portal' : 'bridge',
        executionHostId: `host-${_id}`, profileIds: [`profile-${_id}`] }));
    records.profiles = records.nodes.map(node => ({ ...structuredClone(fixture().profiles[0]),
        _id: `profile-${node._id}`, nodeId: node._id,
        ownedLinkIds: records.links.filter(link => [link.portalNode, link.bridgeNode].includes(node._id)).map(link => link._id),
        egress: node.cascadeRole === 'bridge' ? { kind: 'direct', configSha256: H }
            : { kind: 'links', configSha256: H, linkIds: records.links.filter(link => link.portalNode === node._id).map(link => link._id) },
    }));
    records.listeners = records.links.map(link => ({ ...fixture().listeners[0], linkId: link._id,
        nodeId: link.mode === 'reverse' ? link.portalNode : link.bridgeNode,
        profileId: `profile-${link.mode === 'reverse' ? link.portalNode : link.bridgeNode}`, port: link.tunnelPort }));
    return records;
}

test('ten mixed links retain shared bridge and exact profiles, with deterministic connected components', () => {
    const api = require(modulePath);
    const records = mixedFixture();
    // Inventory may include unrelated active nodes: never silently adopt them.
    records.nodes.push({ _id: 'unused', cascadeRole: 'standalone', active: true });
    const pins = expected(api, records);
    const result = api.buildTransferManifest(records, pins);
    assert.equal(result.inventoryReady, true, JSON.stringify(result.reasons));
    assert.equal(result.manifest.linkIds.length, 10);
    assert.equal(result.manifest.affectedNodeIds.length, 17);
    assert.equal(result.manifest.affectedProfileIds.length, 17);
    assert.equal(result.manifest.components.length, 7);
    assert.deepEqual(result.manifest.components[0].nodeIds, ['b1', 'b2', 'p1', 'p2']);
    assert.equal(result.manifest.affectedNodeIds.includes('unused'), false);
    assert.equal(result.manifest.listenerTransfers.filter(row => row.mode === 'reverse').length, 8);
    for (const row of result.manifest.listenerTransfers.filter(row => row.mode === 'forward')) {
        const link = records.links.find(link => link._id === row.linkId);
        assert.equal(row.listenerNodeId, link.bridgeNode);
        assert.equal(row.dialerNodeId, link.portalNode);
    }
    const reordered = structuredClone(records);
    for (const key of ['nodes', 'links', 'profiles', 'listeners']) reordered[key].reverse();
    for (const profile of reordered.profiles) {
        profile.ownedLinkIds.reverse();
        profile.egress.linkIds?.reverse();
    }
    const reorderedPins = { ...pins, linkIds: [...pins.linkIds].reverse() };
    assert.deepEqual(api.buildTransferManifest(reordered, reorderedPins), result);
    assert.ok(result.manifest.profiles.every(profile => profile.configSha256 === H));
    assert.equal(result.manifest.linkFingerprints.l01, pins.linkFingerprints.l01);
    assert.equal(JSON.stringify(result).includes('synthetic-secret-never-emit'), false);
});

test('requires node, profile, config, unit, service-state and complete-export evidence', () => {
    const api = require(modulePath);
    const cases = [
        ['EXPORT_EVIDENCE_REQUIRED', records => { delete records.completeness.listeners; }],
        ['NODE_MISSING', records => { records.nodes.pop(); }],
        ['DUPLICATE_NODE', records => { records.nodes.push({ ...records.nodes[0] }); }],
        ['UNKNOWN_NODE_ROLE', records => { records.nodes[0].cascadeRole = 'standalone'; }],
        ['NODE_NOT_ACTIVE_ONLINE_XRAY', records => { records.nodes[0].status = 'offline'; }],
        ['NODE_EXECUTION_HOST_REQUIRED', records => { delete records.nodes[0].executionHostId; }],
        ['NODE_PROFILES_UNKNOWN', records => { delete records.nodes[0].profileIds; }],
        ['PROFILE_SET_MISMATCH', records => { records.profiles.pop(); }],
        ['DUPLICATE_PROFILE', records => { records.profiles.push({ ...records.profiles[0] }); }],
        ['CONFIG_EVIDENCE_REQUIRED', records => { delete records.profiles[0].config; }],
        ['UNIT_EVIDENCE_REQUIRED', records => { delete records.profiles[0].unit; }],
        ['UNIT_CONFIG_MISMATCH', records => { records.profiles[0].unit.configPath = '/other/config.json'; }],
        ['SERVICE_STATE_UNPROVEN', records => { delete records.profiles[0].serviceState; }],
        ['SERVICE_STATE_UNPROVEN', records => { records.profiles[0].serviceState.activeState = 'inactive'; }],
        ['SERVICE_STATE_UNPROVEN', records => { records.profiles[0].serviceState.configSha256 = U; }],
        ['PROFILE_LINK_OWNERSHIP_UNPROVEN', records => { records.profiles[0].ownedLinkIds = []; }],
    ];
    for (const [code, mutate] of cases) {
        const records = fixture();
        const pinned = expected(api, records);
        mutate(records);
        hasReason(api.buildTransferManifest(records, pinned), code);
    }
});

test('rejects unresolved direction, listener ownership, and unselected shared-node legacy links', () => {
    const api = require(modulePath);
    const cases = [
        ['LINK_DIRECTION_UNRESOLVED', records => { delete records.links[0].mode; }],
        ['LINK_DIRECTION_UNRESOLVED', records => { records.links[0].bridgeNode = 'p1'; }],
        ['LISTENER_OWNERSHIP_UNPROVEN', records => { records.listeners = []; }],
        ['LISTENER_OWNERSHIP_UNPROVEN', records => { records.listeners.push({ ...records.listeners[0] }); }],
        ['LISTENER_OWNERSHIP_UNPROVEN', records => { records.listeners[0].nodeId = 'b1'; }],
        ['LISTENER_OWNERSHIP_UNPROVEN', records => { records.listeners[0].profileId = 'profile-b1'; }],
        ['LISTENER_OWNERSHIP_UNPROVEN', records => { records.listeners[0].configSha256 = U; }],
        ['LISTENER_OWNERSHIP_UNPROVEN', records => { records.listeners[0].port += 1; }],
        ['LISTENER_OWNERSHIP_UNPROVEN', records => { delete records.listeners[0].bindAddress; }],
    ];
    for (const [code, mutate] of cases) {
        const records = fixture();
        mutate(records);
        hasReason(api.buildTransferManifest(records, expected(api, records)), code);
    }
    const records = fixture();
    const pinned = expected(api, records);
    records.links.push({ ...records.links[0], _id: 'outside-scope', status: 'deployed' });
    hasReason(api.buildTransferManifest(records, pinned), 'ACTIVE_LINK_OUTSIDE_EXPLICIT_SCOPE');
});

test('unknown or contradictory egress fails closed; a bridge-less fan-in is staging only', () => {
    const api = require(modulePath);
    for (const mutate of [
        records => { delete records.profiles[1].egress; },
        records => { records.profiles[1].egress.kind = 'unknown'; },
        records => { records.profiles[1].egress.configSha256 = U; },
        records => { records.profiles[0].egress.linkIds = []; },
        records => { records.profiles[0].egress = { kind: 'direct', configSha256: H }; },
    ]) {
        const records = fixture();
        mutate(records);
        hasReason(api.buildTransferManifest(records, expected(api, records)), 'EGRESS_UNPROVEN');
    }
    const records = fixture();
    records.nodes[1].cascadeRole = 'relay';
    records.profiles[1].egress = { kind: 'staged', configSha256: H };
    const p2 = { ...structuredClone(records.nodes[0]), _id: 'p2', executionHostId: 'host-p2', profileIds: ['profile-p2'] };
    records.nodes.push(p2);
    records.links.push({ ...records.links[0], _id: 'l2', portalNode: 'p2' });
    records.profiles.push({ ...structuredClone(records.profiles[0]), _id: 'profile-p2', nodeId: 'p2',
        ownedLinkIds: ['l2'], egress: { kind: 'links', linkIds: ['l2'], configSha256: H } });
    records.profiles[1].ownedLinkIds.push('l2');
    records.listeners.push({ ...records.listeners[0], linkId: 'l2', nodeId: 'p2', profileId: 'profile-p2' });
    const result = api.buildTransferManifest(records, expected(api, records));
    assert.equal(result.inventoryReady, true, JSON.stringify(result.reasons));
    assert.equal(result.clientReady, false);
    assert.equal(result.executionAuthorized, false);
    assert.equal(result.manifest.components[0].staged, true);
    assert.deepEqual(result.manifest.components[0].bridgeNodeIds, []);
    assert.equal(result.manifest.profiles.some(row => row.egressKind === 'direct'), false);
    assert.ok(result.nonReadyReasons.includes('BRIDGELESS_OR_INCOMPLETE_COMPONENT_STAGING_ONLY'));
    assert.ok(result.nonReadyReasons.includes('CLIENT_PATH_NOT_PROVEN_FROM_RECORDS'));
});

test('only profiles owning selected links are affected, and ambiguous shared writers/listeners are refused', () => {
    const api = require(modulePath);
    const records = fixture();
    records.nodes[0].profileIds.push('profile-unrelated');
    const unrelated = { ...structuredClone(records.profiles[0]), _id: 'profile-unrelated', ownedLinkIds: [],
        targetProfile: 'xray-other', config: { path: '/etc/xray/other.json', sha256: H },
        unit: { name: 'xray-other.service', sha256: U, configPath: '/etc/xray/other.json' } };
    records.profiles.push(unrelated);
    const result = api.buildTransferManifest(records, expected(api, records));
    assert.equal(result.inventoryReady, true, JSON.stringify(result.reasons));
    assert.deepEqual(result.manifest.affectedProfileIds, ['profile-b1', 'profile-p1']);
    unrelated.config.path = records.profiles[0].config.path;
    unrelated.unit.configPath = unrelated.config.path;
    hasReason(api.buildTransferManifest(records, expected(api, records)), 'PROFILE_WRITER_ALIAS_UNPROVEN');

    const shared = mixedFixture();
    shared.nodes.find(node => node._id === 'p2').executionHostId = 'host-p1';
    hasReason(api.buildTransferManifest(shared, expected(api, shared)), 'PROFILE_WRITER_ALIAS_UNPROVEN');
    const p2Profile = shared.profiles.find(profile => profile.nodeId === 'p2');
    p2Profile.config.path = '/etc/xray/p2.json';
    p2Profile.unit.configPath = '/etc/xray/p2.json';
    p2Profile.unit.name = 'xray-p2.service';
    assert.equal(api.buildTransferManifest(shared, expected(api, shared)).inventoryReady, true);
    shared.links[1].tunnelPort = shared.links[0].tunnelPort;
    shared.listeners.find(row => row.linkId === 'l02').port = shared.links[0].tunnelPort;
    hasReason(api.buildTransferManifest(shared, expected(api, shared)), 'LISTENER_COLLISION_UNPROVEN');
});

function chainFixture() {
    const records = mixedFixture();
    const ids = ['p1', 'r1', 'r2', 'r3', 'b1'];
    records.nodes = ids.map(_id => ({ ...fixture().nodes[0], _id,
        cascadeRole: _id.startsWith('p') ? 'portal' : _id.startsWith('b') ? 'bridge' : 'relay',
        executionHostId: `host-${_id}`, profileIds: [`profile-${_id}`] }));
    records.links = ids.slice(0, -1).map((portalNode, index) => ({ ...fixture().links[0],
        _id: `l${index + 1}`, portalNode, bridgeNode: ids[index + 1],
        mode: index % 2 ? 'forward' : 'reverse', tunnelPort: 12000 + index }));
    records.profiles = records.nodes.map(node => ({ ...structuredClone(fixture().profiles[0]),
        _id: `profile-${node._id}`, nodeId: node._id,
        ownedLinkIds: records.links.filter(link => [link.portalNode, link.bridgeNode].includes(node._id)).map(link => link._id),
        egress: node.cascadeRole === 'bridge' ? { kind: 'direct', configSha256: H }
            : { kind: 'links', configSha256: H, linkIds: records.links.filter(link => link.portalNode === node._id).map(link => link._id) },
    }));
    records.listeners = records.links.map(link => ({ ...fixture().listeners[0], linkId: link._id,
        nodeId: link.mode === 'reverse' ? link.portalNode : link.bridgeNode,
        profileId: `profile-${link.mode === 'reverse' ? link.portalNode : link.bridgeNode}`, port: link.tunnelPort }));
    return records;
}

test('a four-link mixed chain is inventoried without turning relay stages into direct exits; cycles are refused', () => {
    const api = require(modulePath);
    const records = chainFixture();
    const result = api.buildTransferManifest(records, expected(api, records));
    assert.equal(result.inventoryReady, true, JSON.stringify(result.reasons));
    assert.equal(result.manifest.components.length, 1);
    assert.equal(result.manifest.components[0].staged, false);
    assert.deepEqual(result.manifest.profiles.filter(row => row.egressKind === 'direct').map(row => row.nodeId), ['b1']);
    assert.deepEqual(result.manifest.listenerTransfers.map(row => row.dialerProfileId),
        ['profile-r1', 'profile-r1', 'profile-r3', 'profile-r3']);
    // Explicit relay-only cycle, with otherwise consistent profile/listener data.
    records.links = [
        { ...records.links[0], _id: 'l1', portalNode: 'r1', bridgeNode: 'r2' },
        { ...records.links[1], _id: 'l2', portalNode: 'r2', bridgeNode: 'r3' },
        { ...records.links[2], _id: 'l3', portalNode: 'r3', bridgeNode: 'r1' },
    ];
    records.nodes = records.nodes.filter(node => node.cascadeRole === 'relay');
    records.profiles = records.profiles.filter(profile => profile.nodeId.startsWith('r'));
    for (const profile of records.profiles) {
        profile.ownedLinkIds = records.links.filter(link => [link.portalNode, link.bridgeNode].includes(profile.nodeId)).map(link => link._id);
        profile.egress.linkIds = records.links.filter(link => link.portalNode === profile.nodeId).map(link => link._id);
    }
    records.listeners = records.links.map(link => ({ ...fixture().listeners[0], linkId: link._id,
        nodeId: link.mode === 'reverse' ? link.portalNode : link.bridgeNode,
        profileId: `profile-${link.mode === 'reverse' ? link.portalNode : link.bridgeNode}`, port: link.tunnelPort }));
    hasReason(api.buildTransferManifest(records, expected(api, records)), 'GRAPH_CYCLE_UNPROVEN');
});

test('malformed exports/identifiers fail closed instead of throwing or coercing; full snapshot pins detect drift', () => {
    const api = require(modulePath);
    for (const records of [null, undefined, [], 'bad', { ...fixture(), links: {} },
        { ...fixture(), nodes: [null] }, { ...fixture(), profiles: 'bad' }]) {
        let result;
        assert.doesNotThrow(() => { result = api.buildTransferManifest(records, { linkIds: ['l1'] }); });
        assert.equal(result.inventoryReady, false);
        assert.equal(result.manifest, null);
    }
    const nonJson = fixture();
    nonJson.links[0].active = NaN;
    hasReason(api.buildTransferManifest(nonJson, { linkIds: ['l1'] }), 'INVALID_JSON_INPUT');
    const malformedId = fixture();
    malformedId.links[0]._id = ' l1';
    hasReason(api.buildTransferManifest(malformedId, { linkIds: [' l1'], linkFingerprints: {} }), 'INVALID_IDENTIFIER');
    const records = fixture();
    const pins = expected(api, records);
    const result = api.buildTransferManifest(records, pins);
    const frozen = structuredClone(records);
    Object.freeze(frozen);
    assert.deepEqual(api.buildTransferManifest(frozen, pins), result);
    const pinnedSnapshot = { ...pins, inputSha256: result.inputSha256 };
    assert.deepEqual(api.buildTransferManifest(records, pinnedSnapshot), result);
    records.profiles[0].config.opaquePrivateMaterial = 'synthetic-private-value';
    hasReason(api.buildTransferManifest(records, pinnedSnapshot), 'SNAPSHOT_CHANGED');
    const changed = api.buildTransferManifest(records, pins);
    assert.notEqual(changed.inputSha256, result.inputSha256);
    assert.notEqual(changed.manifestSha256, result.manifestSha256);
    assert.equal(JSON.stringify(changed).includes('synthetic-private-value'), false);
});

test('stdin-only CLI emits deterministic safe JSON, refuses unknown input, and never echoes secrets/errors', () => {
    const { spawnSync } = require('node:child_process');
    const api = require(modulePath);
    const records = mixedFixture();
    records.nodes[0].ssh = { password: 'DO-NOT-PRINT-password', privateKey: 'DO-NOT-PRINT-private-key' };
    const envelope = { records, expected: expected(api, records) };
    function run(input, args = []) {
        return spawnSync(process.execPath, [modulePath, ...args], { input, encoding: 'utf8', timeout: 5000 });
    }
    const first = run(JSON.stringify(envelope));
    assert.equal(first.status, 0, first.stderr);
    assert.equal(first.stderr, '');
    const parsed = JSON.parse(first.stdout);
    assert.equal(parsed.inventoryReady, true);
    assert.equal(parsed.manifest.linkIds.length, 10);
    assert.equal(first.stdout.includes('DO-NOT-PRINT'), false);
    assert.equal(run(JSON.stringify(envelope)).stdout, first.stdout);
    delete envelope.records.profiles[0].serviceState;
    const notReady = run(JSON.stringify(envelope));
    assert.equal(notReady.status, 2);
    hasReason(JSON.parse(notReady.stdout), 'SERVICE_STATE_UNPROVEN');
    for (const input of ['DO-NOT-PRINT malformed json', '', '{"records": {"password": "DO-NOT-PRINT"}}']) {
        const refused = run(input);
        assert.equal(refused.status, 2);
        assert.equal(refused.stderr, '');
        assert.equal(refused.stdout.includes('DO-NOT-PRINT'), false);
        assert.equal(JSON.parse(refused.stdout).inventoryReady, false);
    }
    const unexpectedArg = run('{}', ['--deploy']);
    assert.equal(unexpectedArg.status, 2);
    hasReason(JSON.parse(unexpectedArg.stdout), 'CLI_ARGUMENTS_NOT_ALLOWED');
});

test('unexpected online links and extra listener ownership never silently widen the exact scope', () => {
    const api = require(modulePath);
    const records = fixture();
    const pinned = expected(api, records);
    records.links.push({ ...records.links[0], _id: 'unexpected', portalNode: 'elsewhere-p', bridgeNode: 'elsewhere-b' });
    hasReason(api.buildTransferManifest(records, pinned), 'UNEXPECTED_ACTIVE_ONLINE_LINK');
    records.links.pop();
    records.listeners.push({ ...records.listeners[0], linkId: 'unknown-link', port: 12345 });
    hasReason(api.buildTransferManifest(records, pinned), 'LISTENER_SCOPE_UNPROVEN');
    records.listeners.pop();
    pinned.linkFingerprints.extra = H;
    hasReason(api.buildTransferManifest(records, pinned), 'LINK_BASELINE_SCOPE_MISMATCH');
});

test('a staged sink in a component that also has a bridge remains explicitly incomplete', () => {
    const api = require(modulePath);
    const records = mixedFixture();
    // Component 0 has both a proven direct bridge and an explicitly staged relay.
    records.nodes.find(node => node._id === 'b2').cascadeRole = 'relay';
    records.profiles.find(profile => profile.nodeId === 'b2').egress.kind = 'staged';
    const result = api.buildTransferManifest(records, expected(api, records));
    assert.equal(result.inventoryReady, true, JSON.stringify(result.reasons));
    assert.equal(result.manifest.components[0].staged, true);
    assert.deepEqual(result.manifest.components[0].bridgeNodeIds, ['b1']);
    assert.ok(result.nonReadyReasons.includes('BRIDGELESS_OR_INCOMPLETE_COMPONENT_STAGING_ONLY'));
});

test('manifest and listener fingerprints independently bind exact evidence, not just graph roles', () => {
    const api = require(modulePath);
    const { createHash } = require('node:crypto');
    const canonicalize = value => Array.isArray(value) ? value.map(canonicalize)
        : value && typeof value === 'object'
            ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])])) : value;
    const digest = value => createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex');
    const records = fixture();
    const result = api.buildTransferManifest(records, expected(api, records));
    assert.equal(result.manifestSha256, digest(result.manifest));
    assert.equal(result.manifest.inputSha256, result.inputSha256);
    assert.equal(result.manifest.listenerTransfers[0].listenerFingerprint, digest(records.listeners[0]));
    const changed = structuredClone(records);
    changed.listeners[0].bindAddress = '127.0.0.1';
    const next = api.buildTransferManifest(changed, expected(api, changed));
    assert.notEqual(next.manifestSha256, result.manifestSha256);
    assert.notEqual(next.manifest.listenerTransfers[0].listenerFingerprint,
        result.manifest.listenerTransfers[0].listenerFingerprint);
    assert.equal(JSON.stringify(next).includes('127.0.0.1'), false);
});

module.exports = { fixture, expected, H, U };
