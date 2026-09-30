'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { TopologyClientProofExecutor } = require('../services/topologyClientProofExecutor');
const { TopologyPublishedProfileSource } = require('../services/topologyPublishedProfileSource');
const { TopologyClientProfileProbe } = require('../services/topologyClientProfileProbe');
const { spawn } = require('node:child_process');

const IP = '198.51.100.10';
const UUID = '11111111-1111-4111-8111-111111111111';
const TOKEN = 'secretSubscriptionToken';
const PORTAL_IDS = ['0123456789abcdef01234567', 'fedcba9876543210fedcba98'];
const portal = id => ({ _id: id, name: id, type: 'xray', active: true, cascadeRole: 'portal', domain: `${id}.example`, port: 443, xray: { transport: 'tcp', security: 'reality', realityPublicKey: 'public-key', realitySni: ['front.example'], realityShortIds: ['01234567'] } });
const nodes = [portal(PORTAL_IDS[0]), portal(PORTAL_IDS[1]), { _id: 'r', type: 'xray', active: true, cascadeRole: 'relay' }, { _id: 'b', type: 'xray', active: true, cascadeRole: 'bridge', ip: IP, ssh: { port: 22, username: 'root', password: 'ENCRYPTED' } }, { _id: 'geo', type: 'xray', active: true, cascadeRole: 'bridge', ip: '203.0.113.20' }];
const links = [
    { _id: 'l1', portalNode: PORTAL_IDS[0], bridgeNode: 'r', active: true, status: 'online' },
    { _id: 'l2', portalNode: PORTAL_IDS[1], bridgeNode: 'r', active: true, status: 'online' },
    { _id: 'main', portalNode: 'r', bridgeNode: 'b', active: true, status: 'online' },
    { _id: 'geolink', portalNode: 'r', bridgeNode: 'geo', active: true, status: 'online', geoRouting: { enabled: true } },
];
const group = { _id: 'g', paths: [{ pathKey: 'main', enabled: true, linkIds: ['main'], priority: 1 }] };
const op = { status: 'succeeded', staged: false, linkIds: ['l1', 'l2', 'main', 'geolink'], nodes: [
    { node: PORTAL_IDS[0], role: 'portal', state: 'committed' }, { node: PORTAL_IDS[1], role: 'portal', state: 'committed' },
    { node: 'r', role: 'relay', state: 'committed' }, { node: 'b', role: 'bridge', state: 'committed' },
    { node: 'geo', role: 'bridge', state: 'committed' },
] };
function profile(n) { return { remarks: n.name, outbounds: [{ protocol: 'vless', tag: 'proxy', settings: { vnext: [{ address: n.domain, port: 443, users: [{ id: UUID, encryption: 'none' }] }] }, streamSettings: { network: 'tcp', security: 'reality', realitySettings: { publicKey: 'public-key', serverName: 'front.example', shortId: '01234567' } } }] }; }
function query(rows) { return { select() { return { lean: async () => rows }; } }; }
function fixture({ operation = op, nodeRows = nodes, linkRows = links, groups = [group], states = [{ node: 'r', desiredState: 'installed', status: 'installed', routeGroup: 'g', activePathKey: 'main' }], sshResult = { code: 0, stdout: `${IP}\n`, stderr: '' }, hang = false, profiles = [profile(nodes[0]), profile(nodes[1])], probeResult = `${IP}\nPROBE_STATUS:200`, timeoutMs = 1000 } = {}) {
    const calls = { ssh: [], curl: [], consumed: [] };
    const HyNode = { find: () => query(nodeRows), findById: id => query(nodeRows.find(n => n._id === id)) };
    const CascadeLink = { find: () => query(linkRows) };
    const CascadeRouteGroup = { find: () => query(groups) };
    const RelayL2tpState = { find: () => query(states) };
    class NodeSSH {
        constructor(n) { calls.ssh.push({ node: n._id }); }
        async connect() { calls.ssh.push({ connect: true }); }
        async exec(command) { calls.ssh.push({ command }); return hang ? new Promise(() => {}) : sshResult; }
        disconnect() { calls.ssh.push({ disconnect: true }); }
    }
    const profileSource = new TopologyPublishedProfileSource({ HyUser: { findOne: () => query({ enabled: true, subscriptionToken: TOKEN, xrayUuid: UUID }) }, probeUserId: 'test', fetchImpl: async () => ({ ok: true, status: 200, headers: { get: () => 'application/json' }, text: async () => JSON.stringify(profiles) }) });
    const profileProbe = new TopologyClientProfileProbe({ spawnClient: (binary, args, opts) => spawn(process.execPath, ['-e', `const net=require('node:net'),fs=require('node:fs');const c=JSON.parse(fs.readFileSync(process.argv[1]));net.createServer(s=>s.end()).listen(c.inbounds[0].port,'127.0.0.1');`, args[2]], opts), runCurl: async (_binary, args) => { calls.curl.push(args); return { stdout: probeResult, stderr: '' }; } });
    return { executor: new TopologyClientProofExecutor({ HyNode, CascadeLink, CascadeRouteGroup, RelayL2tpState, NodeSSH, profileSource, profileProbe, timeoutMs }), calls, operation };
}
test('published profiles for every operation portal are client-probed against installed main bridge egress', async () => {
    const { executor, calls, operation } = fixture();
    assert.deepEqual(await executor.probeOperation(operation), { passed: true });
    assert.deepEqual(calls.ssh.filter(c => c.node).map(c => c.node), ['b']);
    assert.equal(calls.curl.length, 2);
    assert(calls.curl.every(args => args.at(-1) === 'https://api.ipify.org'));
});
test('portal joining downstream of the L2TP owner still proves its unambiguous default exit', async () => {
    const nodeRows = [...nodes, { _id: 'r2', type: 'xray', active: true, cascadeRole: 'relay' }];
    const linkRows = links.map(link => link._id === 'l2'
        ? { ...link, bridgeNode: 'r2' }
        : link._id === 'main' || link._id === 'geolink'
            ? { ...link, portalNode: 'r2' } : link);
    linkRows.push({ _id: 'middle', portalNode: 'r', bridgeNode: 'r2', active: true, status: 'online' });
    const operation = { ...op, linkIds: [...op.linkIds, 'middle'], nodes: [
        ...op.nodes, { node: 'r2', role: 'relay', state: 'committed' },
    ] };
    const { executor, calls } = fixture({ operation, nodeRows, linkRows,
        groups: [{ ...group, paths: [{ ...group.paths[0], linkIds: ['middle', 'main'] }] }] });
    assert.deepEqual(await executor.probeOperation(operation), { passed: true });
    assert.equal(calls.curl.length, 2);
});

test('scoped portal path without an L2TP owner still proves its actual published exit', async () => {
    const nodeRows = [nodes[1], { _id: 'r2', type: 'xray', active: true, cascadeRole: 'relay' }, nodes[3]];
    const linkRows = [
        { ...links[1], bridgeNode: 'r2' },
        { ...links[2], portalNode: 'r2' },
    ];
    const operation = { ...op, linkIds: ['l2', 'main'], nodes: [
        { node: PORTAL_IDS[1], role: 'portal', state: 'committed' },
        { node: 'r2', role: 'relay', state: 'committed' },
        { node: 'b', role: 'bridge', state: 'committed' },
    ] };
    const { executor, calls } = fixture({ operation, nodeRows, linkRows, groups: [], states: [],
        profiles: [profile(nodes[1])] });
    assert.deepEqual(await executor.probeOperation(operation), { passed: true });
    assert.equal(calls.curl.length, 1);
});

test('ObjectId-like HyNode portal IDs are normalized before published profile validation', async () => {
    const nodeRows = nodes.map((node, i) => i < PORTAL_IDS.length
        ? { ...node, _id: { toHexString: () => PORTAL_IDS[i] } } : node);
    const { executor, calls } = fixture({ nodeRows });
    const result = await executor.probeOperation(op);
    assert(calls.ssh.some(call => call.connect === true), 'graph reaches bridge SSH before source loading');
    assert.deepEqual(result, { passed: true });
    assert.equal(calls.curl.length, 2);
});
test('portal ObjectId normalization never bypasses graph identity or canonical-ID fences', async () => {
    const wrongRows = nodes.map((node, i) => i === 0
        ? { ...node, _id: { toHexString: () => 'aaaaaaaaaaaaaaaaaaaaaaaa' } } : node);
    const wrong = fixture({ nodeRows: wrongRows });
    assert.deepEqual(await wrong.executor.probeOperation(op), { passed: false });
    assert.equal(wrong.calls.ssh.length, 0);
    assert.equal(wrong.calls.curl.length, 0);

    const uppercaseId = PORTAL_IDS[1].toUpperCase();
    const uppercase = fixture({
        nodeRows: nodes.map((node, i) => i === 1
            ? { ...node, _id: { toHexString: () => uppercaseId } } : node),
        linkRows: links.map(link => link.portalNode === PORTAL_IDS[1]
            ? { ...link, portalNode: uppercaseId } : link),
        operation: { ...op, nodes: op.nodes.map(entry => entry.node === PORTAL_IDS[1]
            ? { ...entry, node: uppercaseId } : entry) },
    });
    assert.deepEqual(await uppercase.executor.probeOperation(uppercase.operation), { passed: false });
    assert(uppercase.calls.ssh.some(call => call.connect === true));
    assert.equal(uppercase.calls.curl.length, 0);
});
test('staged, missing, disabled, ambiguous and unconfirmed main routes fail closed before probing', async () => {
    for (const overrides of [
        { operation: { ...op, staged: true } },
        { states: [{ node: 'r', desiredState: 'installed', status: 'installed', routeGroup: 'missing', activePathKey: 'main' }] },
        { groups: [{ ...group, paths: [{ ...group.paths[0], enabled: false }] }] },
        { groups: [{ ...group, paths: [...group.paths, { ...group.paths[0], pathKey: 'main' }] }] },
        { linkRows: links.map(l => l._id === 'main' ? { ...l, status: 'pending' } : l) },
        { linkRows: links.concat({ _id: 'other', portalNode: 'r', bridgeNode: 'geo', active: true, status: 'online' }), operation: { ...op, linkIds: [...op.linkIds, 'other'] } },
        { operation: { ...op, nodes: op.nodes.filter(n => n.node !== 'b') } },
    ]) {
        const { executor, calls, operation } = fixture(overrides);
        assert.deepEqual(await executor.probeOperation(operation), { passed: false });
        assert.equal(calls.curl.length, 0);
    }
});
test('SSH timeout, wrong bridge egress, missing published portal, and failed client egress never pass or leak', async () => {
    for (const overrides of [{ hang: true, timeoutMs: 15 }, { sshResult: { code: 0, stdout: '203.0.113.20\n', stderr: '' } }, { profiles: [profile(nodes[0])] }, { probeResult: '203.0.113.20\nPROBE_STATUS:200' }]) {
        const { executor, operation } = fixture(overrides);
        const result = await executor.probeOperation(operation);
        assert.deepEqual(result, { passed: false });
        assert(!JSON.stringify(result).includes(TOKEN));
        assert(!JSON.stringify(result).includes(UUID));
    }
});
