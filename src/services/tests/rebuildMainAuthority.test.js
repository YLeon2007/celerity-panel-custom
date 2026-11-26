'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { createHash } = require('node:crypto');
const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');
const { planSerialScopedTransition } = require('../rebuildTransitActivationPlan');
const { createSerialMainAuthority, mainCardIdentity } = require('../rebuildMainAuthority');

const id = n => n.toString(16).padStart(24, '0');
const sha = value => createHash('sha256').update(value).digest('hex');
const refused = { code: 'REBUILD_MAIN_AUTHORITY_UNPROVED' };
const directModule = require.resolve('../rebuildRelayDirect');
require.cache[directModule] = { exports: { bundledMainReceiverCommand() { assert.fail('authority must not run the receiver'); } } };

function fixture() {
    const nodes = ['portal', 'relay', 'relay', 'bridge', 'bridge'].map((cascadeRole, i) => ({ _id: id(i+1), cascadeRole,
        type: 'xray', active: true, ip: `192.0.2.${i+1}`, port: 22001+i,
        xray: { security: 'none', agentTls: false, agentToken: 'synthetic-agent-token' } }));
    const ids = nodes.map(node => node._id);
    const links = [1, 2, 3, 4].map(n => ({ _id: id(100+n), portalNode: id(n === 4 ? 3 : n), bridgeNode: id(n+1), active: true,
        priority: n, mode: n === 2 ? 'forward' : 'reverse', tunnelProtocol: 'vless', tunnelTransport: 'tcp', tunnelPort: 24000+n,
        tunnelUuid: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`, tunnelEncryption: 'none',
        ...(n === 1 && { rebuildExit: { nodeId: id(5), relayGeo: false } }) }));
    const relay = id(2), machineId = 'a'.repeat(32);
    const network = { clientCidr: '198.51.100.0/24', tproxyPort: 20443, fwmark: 120, routeTable: 120 };
    const state = { ...network, node: relay, rebuildMachineId: machineId, backupId: 'c'.repeat(32),
        status: 'installed', desiredState: 'installed', routingMode: 'follow-relay', routingVersion: 1,
        secretRevision: 1, routeGroup: id(80) };
    nodes[1].xray.inboundTag = 'relay-clients';
    nodes[1].xray.extraInbounds = [{ inboundTag: 'relay-extra', port: 22090, security: 'none', transport: 'ws' }];
    nodes[2].xray.inboundTag = 'transit-clients';
    nodes[2].aclRules = ['reject(::/0)', 'reject(geoip:cn)', 'reject(geoip:private)'];
    const composition = { nodes, links, followRelayStates: [state], controlPlaneAddresses: nodes.map(node => node.ip) };
    const before = composeRebuildProfiles({ ...composition, links: links.map(({ rebuildExit, ...link }) => link) });
    const after = composeRebuildProfiles(composition);
    const steps = planSerialScopedTransition({ before, after, composition, allowMainRestart: true });
    const entries = new Map(ids.map(n => {
        const data = Buffer.from(JSON.stringify(before.find(row => row.nodeId === n && row.profile === 'main').config));
        return [n, { snap: { data: data.toString('base64'), metadata: [0o640, 0, 34],
            generation: ['4','5','6'], xray: [14, '2'.repeat(32)] }, observationCount: 0, opens: [] }];
    }));
    const bindings = new Map(), states = new Map();
    assert.ok(steps.some(step => step.nodeId === relay));
    bindings.set(relay, { binding: { machineId, sshHostKeySha256: 'b'.repeat(64), host: nodes[1].ip, port: 22, username: 'root' } });
    states.set(relay, state);
    const transports = new Map(ids.map(n => {
        const entry = entries.get(n), xray = nodes.find(node => node._id === n).xray;
        entry.flows = [xray.inboundTag ?? 'vless-in', ...(xray.extraInbounds ?? []).map(row => row.inboundTag)].map(tag => [tag, '']);
        return [n, { async verifyMainConnection() { return true; }, async readMainSha256() {
            return sha(Buffer.from(entry.snap.data, 'base64'));
        }, async read(profile) {
            assert.equal(profile, 'main');
            return JSON.parse(Buffer.from(entry.snap.data, 'base64'));
        }, async observeMain(command) {
            entry.observationCount++;
            assert.match(command, /^exec \/usr\/bin\/timeout -k 1s 10s \/usr\/bin\/env -i LC_ALL=C \/usr\/bin\/python3 -I -B -c /);
            assert.ok(!command.includes('synthetic-agent-token'));
            const { data, ...snap } = entry.snap;
            return { code: 0, stderr: '', stdout: JSON.stringify({ ...snap, main: sha(Buffer.from(data, 'base64')),
                token: sha('synthetic-agent-token'), tls: false, flows: entry.flows,
                agent: [entry.agentPid ?? 13, '1'.repeat(32), 100], agentConfig: ['9','8',entry.agentConfig ?? '7'] }) };
        }, async openMainWindow(options) { entry.opens.push(options); return 'synthetic channel'; } }];
    }));
    const env = { C3_REBUILD_CHAIN_APPLY: '1', ENCRYPTION_KEY: 'synthetic-only'.repeat(3) };
    const admit = createSerialMainAuthority({ env, transports, bindings, composition, admittedNodes: nodes, admittedStates: states,
        async verifyApply() {}, confirmation: { before, after }, stores: { journal: {}, artifacts: {} } });
    return { admit, args: { ids, nodes, states, async verify() {} }, ids, steps, entries, states, relay, machineId, network, env };
}

test('stock authority derives the native option shapes and keeps untouched peers read-only', async () => {
    const f = fixture(), authority = await f.admit(f.args);
    const touched = new Set(f.steps.map(step => step.nodeId)), unchangedMainPins = new Map();
    for (const n of f.ids) {
        const entry = f.entries.get(n), peer = authority.peers.get(n);
        assert.match(peer.authoritySha256, /^[a-f0-9]{64}$/);
        assert.equal(await peer.verify(n, peer.authoritySha256), true);
        if (!touched.has(n)) {
            assert.equal(entry.observationCount, 0);
            unchangedMainPins.set(n, await peer.readMainSha256());
            await assert.rejects(authority.openWindow(n, {}), refused);
            continue;
        }
        assert.deepEqual(peer.managed, entry.flows.map(([tag]) => tag).sort());
        assert.deepEqual(entry.opens, []);
        assert.equal(await authority.openWindow(n, { maxFrameBytes: 64 }), 'synthetic channel');
        const { bootstrap } = entry.opens[0];
        assert.deepEqual(bootstrap.direct, n === f.relay ? { nodeId: n, backupId: 'c'.repeat(32), network: f.network } : null);
        assert.equal(bootstrap.machineId, n === f.relay ? f.machineId : null);
        assert.deepEqual(bootstrap.routes.map(route => route.inboundTag), peer.managed);
        assert.equal(bootstrap.routes[0].targetIP, '127.0.0.1');
        assert.equal(bootstrap.routes[0].targetDomain, undefined);
        assert.equal(await authority.verifySnapshot(n, 'before', entry.snap), true);
        const target = { nodeId: n, ip: f.args.nodes.find(node => node._id === n).ip, agentTls: false, agentPort: 62080 };
        assert.equal(await authority.verifyAgentEndpoint(n, target, entry.snap), true);
        entry.agentPid = 15;
        assert.equal(await authority.verifyAgentEndpoint(n, target, entry.snap), false);
        await assert.rejects(authority.readAgentManagedFlows(n, target, entry.snap), refused);
        entry.agentPid = 13;
        assert.deepEqual(await authority.readAgentManagedFlows(n, target, entry.snap), new Map(entry.flows));
        assert.equal(await authority.verifySnapshot(n, 'after', entry.snap), true);
    }
    const latest = new Map([...touched].map(n => [n, f.entries.get(n).snap]));
    assert.deepEqual((await authority.verifyTerminal({ direction: 'forward' }, latest)).unchangedMainPins, unchangedMainPins);
    const entry = f.entries.get(f.relay);
    entry.agentConfig = '999';
    await assert.rejects(authority.verifyTerminal({ direction: 'forward' }, latest), refused);
});

test('stock authority refuses without opt in or on stale DB state', async () => {
    const f = fixture();
    await assert.rejects(f.admit({ ...f.args, states: new Map() }), refused);
    const authority = await f.admit(f.args);
    delete f.env.C3_REBUILD_CHAIN_APPLY;
    await assert.rejects(f.admit(f.args), refused);
    await assert.rejects(authority.openWindow(f.relay, {}), refused);
    assert.deepEqual(f.entries.get(f.relay).opens, []);
    assert.deepEqual(mainCardIdentity({}), { machineId: null, sshHostKeySha256: null });
    assert.throws(() => mainCardIdentity({ machineId: 'x' }), refused);
    assert.throws(() => mainCardIdentity({ sshHostKeySha256: `${'a'.repeat(64)}\n` }), refused);
});

test('ordinary card identity accepts stored SSH leaves without requiring a pin', () => {
    const machineId = '4'.repeat(32), sshHostKeySha256 = '5'.repeat(64);
    assert.deepEqual(mainCardIdentity({ machineId, ssh: { hostKeySha256: sshHostKeySha256 } }), { machineId, sshHostKeySha256 });
    assert.deepEqual(mainCardIdentity({ ssh: { machineId } }), { machineId, sshHostKeySha256: null });
    assert.throws(() => mainCardIdentity({ machineId, ssh: { machineId: '6'.repeat(32) } }), refused);
});

test('relay VLESS tunnel listeners cannot be adopted as agent-managed subscribers', async () => {
    const f = fixture();
    const entry = f.entries.get(id(3));
    const cfg = JSON.parse(Buffer.from(entry.snap.data, 'base64'));
    const tunnel = cfg.inbounds.find(row => row.protocol === 'vless' && !entry.flows.some(([tag]) => row.tag === tag));
    assert(tunnel);
    entry.flows.push([tunnel.tag, '']);
    await assert.rejects(f.admit(f.args), refused);
});

test('an untouched peer cannot publish a digest for a different confirmed MAIN', async () => {
    const f = fixture(), authority = await f.admit(f.args);
    const n = f.ids.find(n => !f.steps.some(step => step.nodeId === n));
    const entry = f.entries.get(n);
    const cfg = JSON.parse(Buffer.from(entry.snap.data, 'base64'));
    entry.snap.data = Buffer.from(JSON.stringify({ ...cfg, log: { loglevel: 'error' } })).toString('base64');
    await assert.rejects(authority.peers.get(n).readMainSha256(), refused);
    assert.equal(entry.observationCount, 0);
    assert.deepEqual(entry.opens, []);
});
