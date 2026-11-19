'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { createHash } = require('node:crypto');
const { createRebuildRelayInstallSteps } = require('../rebuildRelayInstallSteps');
const { runFreshRelayInstall } = require('../rebuildRelayInstall');

const nodeId = 'a'.repeat(24);
const machineId = 'b'.repeat(32);
const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true',
    C3_REBUILD_L2TP_RELAY_ID: nodeId, C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId };
const sha256 = data => createHash('sha256').update(data).digest('hex');
const field = (inboundTag, outboundTag, extra) => ({ type: 'field', inboundTag, outboundTag, ...extra });
const marker = 'fixture-only-protected-profile-content';
const handoff = 'rebuild-relay-ingress';
const blocked = 'REBUILD_L2TP_STOCK_INSTALL_OUT_OF_SCOPE';

function fixture() {
    const main = {
        inbounds: [
            { tag: 'subscriber', port: 443, protocol: 'vless', settings: { clients: [{ id: marker }] } },
            { tag: 'fwd-hop-1234abcd', port: 22443, protocol: 'vless' },
            { tag: 'API_INBOUND', port: 61000, protocol: 'dokodemo-door', listen: '127.0.0.1' },
        ],
        outbounds: [{ tag: 'block', protocol: 'blackhole' }, { tag: 'fwd-1234abcd', protocol: 'vless' }],
        routing: { domainStrategy: 'IPOnDemand', rules: [
            field(['subscriber'], 'block', { ip: ['geoip:private'] }),
            field(['subscriber'], 'block', { ruleTag: 'acl-catch-all' }),
            field(['API_INBOUND'], 'API'),
            field(['subscriber', 'fwd-hop-1234abcd'], 'fwd-1234abcd', { ruleTag: 'rebuild-policy-geo-0-ip', ip: ['geoip:ru'] }),
            field(['subscriber', 'fwd-hop-1234abcd'], 'fwd-1234abcd', { ruleTag: 'rebuild-policy-default' }),
        ] },
    };
    const bridge = { inbounds: [], outbounds: [{ tag: 'block', protocol: 'blackhole' }], routing: { rules: [] } };
    const snapshot = { nodeId, machineId, ppp: true, masked: false, pristine: true,
        main: JSON.stringify(main), bridge: JSON.stringify(bridge) };
    return { main, bridge, args: { inventory: { nodeId, eligible: true, pristine: true }, snapshot,
        profilePins: { mainSha256: sha256(snapshot.main), bridgeSha256: sha256(snapshot.bridge) },
        tproxyPort: 12345, controlPlaneAddresses: ['panel.invalid'], carryDomain: false } };
}

function rebind(args, profile, config) {
    args.snapshot[profile] = config === null ? null : JSON.stringify(config);
    args.profilePins[`${profile}Sha256`] = config === null ? null : sha256(args.snapshot[profile]);
}

const steps = () => createRebuildRelayInstallSteps({ env });

test('materializes the fixed root-only MAIN artifact, not a replacement BRIDGE or subscriber policy', () => {
    const f = fixture();
    const original = structuredClone(f.args);
    const plan = steps().materialize(f.args);
    assert.deepEqual(f.args, original);
    assert.equal(plan.kind, 'rebuild-l2tp-first-install');
    assert.equal(plan.status, 'blocked');
    assert.equal(plan.blocker, blocked);
    assert.equal(plan.stockArtifacts.payloads.length, 19);
    assert.equal(plan.nodeId, nodeId);
    assert.deepEqual(plan.preconditions, f.args.profilePins);
    const serialized = JSON.stringify(plan);
    assert.ok(!serialized.includes(marker));
    assert.ok(!serialized.includes(machineId));
    const artifact = plan.getMainArtifact();
    const { content, ...descriptor } = artifact;
    assert.deepEqual(descriptor, { stepType: 'compose_xray_fragment', type: 'xrayCandidate',
        path: 'xray-candidate.json', owner: 'root', group: 'root', mode: 0o600 });
    assert.equal(plan.mainCandidateSha256, sha256(content));
    const config = JSON.parse(content);
    assert.deepEqual(config.inbounds.slice(0, 3), f.main.inbounds);
    assert.deepEqual(config.outbounds.slice(0, 2), f.main.outbounds);
    assert.equal(config.inbounds.find(i => i.tag === handoff).listen, '127.0.0.1');
    const ppp = config.inbounds.find(i => i.tag === `relay-l2tp-${nodeId}`);
    assert.equal(ppp.port, f.args.tproxyPort);
    assert.ok(config.routing.rules.some(rule => rule.inboundTag.includes(ppp.tag) && rule.ip?.includes('geoip:private')));
    const shared = config.routing.rules.filter(rule => rule.inboundTag.includes('subscriber'));
    assert.deepEqual(shared, f.main.routing.rules.filter(rule => rule.inboundTag.includes('subscriber'))
        .map(rule => ({ ...rule, inboundTag: [...rule.inboundTag, handoff] })));
    assert.deepEqual(config.routing.rules.find(rule => rule.inboundTag.includes('API_INBOUND')), f.main.routing.rules[2]);
    assert.ok(Object.isFrozen(plan) && Object.isFrozen(plan.stockArtifacts.payloads));
    assert.equal(steps().materialize(f.args).mainCandidateSha256, plan.mainCandidateSha256);
});

test('requires rebuild opt-in and rejects inventory, physical identity, PPP, and raw-profile drift', () => {
    const auth = createRebuildRelayInstallSteps({ env: { ...env, L2TP_EXECUTION_ENABLED: 'true' } });
    assert.throws(() => auth.materialize(fixture().args), { code: 'REBUILD_L2TP_INSTALL_DISABLED' });
    for (const [section, data, code] of [
        ['inventory', { nodeId: 'c'.repeat(24) }, 'REBUILD_L2TP_INSTALL_DISABLED'],
        ['inventory', { eligible: false }, 'REBUILD_L2TP_NOT_FRESH_RELAY'],
        ['inventory', { pristine: false }, 'REBUILD_L2TP_NOT_FRESH_RELAY'],
        ['snapshot', { pristine: false }, 'REBUILD_L2TP_NOT_FRESH_RELAY'],
        ['snapshot', { nodeId: 'c'.repeat(24) }, 'REBUILD_L2TP_INSTALL_IDENTITY_MISMATCH'],
        ['snapshot', { machineId: '0'.repeat(32) }, 'REBUILD_L2TP_INSTALL_IDENTITY_MISMATCH'],
        ['snapshot', { mocked: true, ppp: 'true' }, 'REBUILD_L2TP_HOST_NOT_READY'],
        ['snapshot', { masked: true }, 'REBUILD_L2TP_HOST_NOT_READY'],
        ['profilePins', { mainSha256: '0'.repeat(64) }, 'REBUILD_L2TP_PROFILE_PRECONDITION'],
        ['snapshot', { bridge: null }, 'REBUILD_L2TP_PROFILE_PRECONDITION'],
    ]) {
        const { args } = fixture();
        Object.assign(args[section], data);
        assert.throws(() => steps().materialize(args), { code });
    }
    const f = fixture();
    f.args.snapshot.main += '\n';
    assert.throws(() => steps().materialize(f.args), { code: 'REBUILD_L2TP_PROFILE_PRECONDITION' });
    rebind(f.args, 'bridge', null);
    rebind(f.args, 'main', f.main);
    assert.equal(steps().materialize(f.args).preconditions.bridgeSha256, null);
});

test('rejects preexisting L2TP ingress, cross-profile port collisions, and noncanonical policy', () => {
    for (const alter of [
        ({ main }) => main.inbounds.push({ tag: `relay-l2tp-${nodeId}`, port: 12345, protocol: 'dokodemo-door' }),
        ({ bridge }) => bridge.inbounds.push({ tag: 'other', port: '12344-12347' }),
        ({ main }) => { main.outbounds[1].protocol = 'freedom'; },
        ({ main }) => { delete main.routing.rules[0].inboundTag; },
        ({ main }) => { main.routing.rules[2].inboundTag.push('subscriber'); },
        ({ main }) => { main.routing.rules[0].user = ['subscriber']; },
        ({ main }) => { main.routing.rules.at(-1).inboundTag.push('API_INBOUND'); },
        ({ main }) => { main.routing.rules.at(-1).domain = ['full:not-a-default.invalid']; },
        ({ main }) => { main.routing.rules.at(-2).inboundTag = ['subscriber']; },
    ]) {
        const f = fixture();
        alter(f);
        rebind(f.args, 'main', f.main);
        rebind(f.args, 'bridge', f.bridge);
        assert.throws(() => steps().materialize(f.args), { code: 'REBUILD_L2TP_XRAY_BASELINE_UNSUPPORTED' });
    }
    const f = fixture();
    assert.throws(() => steps().materialize({ ...f.args, tproxyPort: 1701 }), { code: 'REBUILD_L2TP_INSTALL_INPUT_INVALID' });
});

test('mixed reverse/forward policy retains native control endpoints and a private-only loopback handoff', () => {
    const { main, args } = fixture();
    const nativeIngress = 'rebuild-rp-ingress-1234abcd';
    const nativeEgress = 'rebuild-rp-egress-4567abcd';
    const connector = { protocol: 'vless', tag: 'rebuild-rp-conn-4567abcd', port: 22444,
        settings: { clients: [{ reverse: { tag: nativeEgress } }] } };
    main.inbounds.push(connector);
    main.outbounds.push({ protocol: 'vless', tag: 'rebuild-rp-dial-1234abcd', settings: { reverse: { tag: nativeIngress } } });
    main.routing.rules.at(-2).inboundTag.push(nativeIngress);
    main.routing.rules.at(-1).inboundTag.push(nativeIngress);
    main.routing.rules.at(-1).outboundTag = nativeEgress;
    args.carryDomain = true;
    rebind(args, 'main', main);
    const candidate = JSON.parse(steps().materialize(args).getMainArtifact().content);
    assert.deepEqual(candidate.inbounds.find(row => row.tag === connector.tag), connector);
    assert.equal(candidate.inbounds.find(row => row.tag === handoff).sniffing.routeOnly, false);
    const shared = candidate.routing.rules.filter(row => row.ruleTag?.startsWith('rebuild-policy-'));
    assert.deepEqual(shared, main.routing.rules.slice(-2)
        .map(rule => ({ ...rule, inboundTag: [...rule.inboundTag, handoff] })));
});

test('parser errors and duplicate-key profile inputs fail closed without echoing raw bytes', () => {
    const valid = fixture().args.snapshot.main;
    for (const bytes of [`{"value":"${marker}"`, `{"inbounds":[],${valid.slice(1)}`]) {
        const { args } = fixture();
        args.snapshot.main = bytes;
        args.profilePins.mainSha256 = sha256(bytes);
        assert.throws(() => steps().materialize(args), error => error.code === 'REBUILD_L2TP_XRAY_BASELINE_UNSUPPORTED'
            && !String(error.stack).includes(marker) && !error.cause);
    }
});

test('checks the installer pin and actual local payload bytes without running the bundle', t => {
    const original = fs.readFileSync;
    for (const name of ['install.sh', 'verify.sh']) {
        const stub = t.mock.method(fs, 'readFileSync', (path, ...args) => String(path).endsWith(`/l2tp/${name}`)
            ? Buffer.from('fixture modified stock artifact') : original(path, ...args));
        try {
            assert.throws(() => steps().materialize(fixture().args), { code: 'REBUILD_L2TP_STOCK_ARTIFACT_MISMATCH' });
        } finally { stub.mock.restore(); }
    }
});

test('stock install refuses in runFreshRelayInstall before reserve; direct install/verify cannot dispatch', async () => {
    const adapter = steps();
    const calls = [];
    const mustNot = name => () => { calls.push(name); assert.fail(name); };
    const f = fixture();
    const remote = {
        preflight: async () => ({ ppp: true, masked: false }), close: async () => calls.push('close'),
        uploadRootFile: mustNot('upload'), runArtifactCommand: mustNot('dispatch'), exec: mustNot('exec'),
    };
    await assert.rejects(() => runFreshRelayInstall(nodeId, {
        ...adapter, authorize: () => true, lock: fn => fn(mustNot('verifyLock')),
        inventory: async () => f.args.inventory, connect: async () => remote,
        reserve: mustNot('reserve'), finish: mustNot('finish'), uncertain: mustNot('uncertain'),
    }), { code: blocked });
    const plan = adapter.materialize(f.args);
    await assert.rejects(() => adapter.install(plan, remote, mustNot('verifyLock')), { code: blocked });
    assert.equal(await adapter.verify(plan, remote), false);
    assert.deepEqual(calls, ['close']);
});
