'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { fixture, withEnv, node, link, MAIN, BRIDGE } = require('./cascadeLegacyWriterFixture');
const remote = (f, nodeId) => f.events.filter(event => event.node === nodeId && ['connect', 'exec', 'upload'].includes(event.kind));

test('legacy terminal cleanup refuses adopted bridge before SSH and preserves independent classic work', async () => withEnv({}, async () => {
    const f = fixture();
    f.adopt(f.nodes[1]._id);
    const owners = structuredClone(f.owners);
    await assert.rejects(f.cascade.undeployLink(f.links[0]), { code: 'CLASSIC_CONFIG_WRITE_OWNER_VETO' });
    assert.deepEqual(remote(f, f.nodes[1]._id), []);
    assert.deepEqual(f.owners, owners);
    assert.equal(await f.cascade._deployPortalConfig(f.nodes[2]), true);
    assert.ok(f.files.has(f.key(f.nodes[2]._id, MAIN)));
}));

test('legacy terminal cleanup preserves expired foreign bridge generation without SSH', async () => withEnv({}, async () => {
    const f = fixture();
    const winner = f.foreign(f.nodes[1]._id);
    await assert.rejects(f.cascade.undeployLink(f.links[0]), { code: 'NODE_OPERATION_LOCK_CONFLICT' });
    assert.deepEqual(remote(f, f.nodes[1]._id), []);
    assert.deepEqual(f.locks.get(f.nodes[1]._id), winner);
}));

test('stop/disable holds exact bridge generation until checked foreground acknowledgement', async () => withEnv({}, async () => {
    let finish, started;
    const ready = new Promise(resolve => { started = resolve; });
    const f = fixture({ onExec: async ({ command }) => {
        if (command.includes('systemctl stop')) { started(); await new Promise(resolve => { finish = resolve; }); }
    } });
    const operation = f.cascade.undeployLink(f.links[0]);
    await ready;
    try {
        const held = structuredClone(f.locks.get(f.nodes[1]._id));
        assert.equal(held?.remoteUncertain, true, 'direct cleanup must own the node while stop/disable is pending');
        const before = remote(f, f.nodes[1]._id).length;
        await assert.rejects(f.cascade._deployPortalConfig(f.nodes[1]), { code: 'NODE_OPERATION_LOCK_CONFLICT' });
        assert.equal(remote(f, f.nodes[1]._id).length, before);
        assert.deepEqual(f.locks.get(f.nodes[1]._id), held);
        assert.equal(await f.cascade._deployPortalConfig(f.nodes[2]), true);
    } finally { finish(); await operation; }
    assert.equal(f.locks.size, 0);
}));

test('bridge fence policy is selected before portal-side asynchronous work changes flags', async () => withEnv({}, async () => {
    const f = fixture({ onFindLinks: ({ filter }) => {
        if (filter.portalNode === f.nodes[0]._id) process.env.L2TP_EXECUTION_ENABLED = 'false';
    } });
    const winner = f.foreign(f.nodes[1]._id);
    await assert.rejects(f.cascade.undeployLink(f.links[0]), { code: 'NODE_OPERATION_LOCK_CONFLICT' });
    assert.deepEqual(remote(f, f.nodes[1]._id), []);
    assert.deepEqual(f.locks.get(f.nodes[1]._id), winner);
}));

test('ordinary dormant classic teardown retains checked stop/disable without optional lock activation', async () => withEnv({
    L2TP_EXECUTION_ENABLED: 'false', L2TP_MIGRATIONS_ENABLED: 'false', L2TP_PRODUCTION_EXECUTION_ENABLED: 'false',
}, async () => {
    const f = fixture();
    assert.deepEqual(await f.cascade.undeployLink(f.links[0]), { success: true, remoteQuiescent: true });
    assert.equal(f.events.some(event => event.kind === 'acquire'), false);
    const commands = remote(f, f.nodes[1]._id).filter(event => event.kind === 'exec');
    assert.equal(commands.length, 2);
    assert.match(commands[0].command, /cat \/usr\/local\/etc\/xray-bridge\/config.json/);
    assert.match(commands[1].command, /systemctl stop xray-bridge && systemctl disable xray-bridge/);
    assert.ok(commands.every(row => /C3_LEGACY_DONE_[a-f0-9]+/.test(row.command)));
}));

for (const failure of ['nonzero', 'missing-exit', 'missing-stderr', 'missing-receipt', 'stale-receipt', 'timeout']) {
    test(`stop/disable ${failure} retains its exact generation and excludes a successor`, async () => withEnv({}, async () => {
        let held, liveWriter = false;
        const f = fixture({ onExec: async ({ command, node: target, locks }) => {
            if (!command.includes('systemctl stop')) return;
            held = structuredClone(locks.get(target._id));
            liveWriter = true; // Transport refusal is not evidence the writer ended.
            if (failure === 'timeout') throw new Error('simulated transport timeout');
            const receipt = command.match(/C3_LEGACY_DONE_[a-f0-9]+/)[0];
            return { code: failure === 'nonzero' ? 1 : failure === 'missing-exit' ? undefined : 0,
                stdout: failure === 'missing-receipt' ? '' : `\n${failure === 'stale-receipt' ? 'C3_LEGACY_DONE_old' : receipt}\n`,
                ...(failure === 'missing-stderr' ? {} : { stderr: '' }) };
        } });
        await assert.rejects(f.cascade.undeployLink(f.links[0]));
        assert.equal(liveWriter, true);
        assert.equal(held?.remoteUncertain, true);
        assert.deepEqual(f.locks.get(f.nodes[1]._id), held);
        assert.equal(f.events.some(event => event.kind === 'release' && event.node === f.nodes[1]._id), false);
        const before = remote(f, f.nodes[1]._id).length;
        await assert.rejects(f.cascade._deployPortalConfig(f.nodes[1]), { code: 'NODE_OPERATION_LOCK_CONFLICT' });
        assert.equal(remote(f, f.nodes[1]._id).length, before);
        assert.deepEqual(f.locks.get(f.nodes[1]._id), held);
    }));
}

for (const guard of ['adopted', 'history', 'unreadable']) {
    test(`dormant authorization still vetoes ${guard} bridge before connect/stop`, async () => withEnv({
        L2TP_EXECUTION_ENABLED: 'false', L2TP_MIGRATIONS_ENABLED: 'false', L2TP_PRODUCTION_EXECUTION_ENABLED: 'false',
    }, async () => {
        const f = fixture({ onOwnerRead: ({ nodeId }) => {
            if (guard === 'unreadable' && nodeId === f.nodes[1]._id) throw new Error('owner read unavailable');
        } });
        if (guard === 'adopted') f.adopt(f.nodes[1]._id);
        if (guard === 'history') f.operations.push({ status: 'queued', nodes: [{ node: f.nodes[1]._id, state: 'pending' }] });
        await assert.rejects(f.cascade.undeployLink(f.links[0]));
        assert.deepEqual(remote(f, f.nodes[1]._id), []);
        assert.equal(f.events.some(event => event.kind === 'acquire'), false);
    }));
}

test('bridge neighbor selection occurs inside the acquired writer scope', async () => withEnv({}, async () => {
    const f = fixture({ onFindLinks: ({ filter, locks }) => {
        if (filter.bridgeNode && filter.mode?.$ne === 'forward') assert.equal(locks.get(String(filter.bridgeNode))?.remoteUncertain, true);
    } });
    assert.deepEqual(await f.cascade.undeployLink(f.links[0]), { success: true, remoteQuiescent: true });
    assert.equal(f.locks.size, 0);
    const bridgeEvents = f.events.filter(event => event.node === f.nodes[1]._id);
    assert.ok(bridgeEvents.findIndex(event => event.kind === 'disconnect') < bridgeEvents.findIndex(event => event.kind === 'release'));
}));

test('outer acquired bridge generation is borrowed, not double-acquired or released by cleanup', async () => withEnv({}, async () => {
    const f = fixture();
    await f.fence.withClassicNodeConfigWrite({ nodeId: f.nodes[1]._id, kind: 'outer-maintenance' }, async () => {
        const owner = structuredClone(f.locks.get(f.nodes[1]._id));
        await f.cascade.undeployLink(f.links[0]);
        assert.deepEqual(f.locks.get(f.nodes[1]._id), owner);
        assert.equal(f.events.some(event => event.kind === 'release' && event.node === f.nodes[1]._id), false);
        return true;
    });
    assert.equal(f.events.filter(event => event.kind === 'acquire' && event.node === f.nodes[1]._id).length, 1);
    assert.equal(f.events.filter(event => event.kind === 'release' && event.node === f.nodes[1]._id).length, 1);
    assert.equal(f.locks.size, 0);
}));

for (const mode of ['reverse', 'forward']) {
    test(`${mode} shared bridge cleanup preserves actual peer config, users and other profiles without double locking`, async () => withEnv({}, async () => {
        const nodes = [node(1), node(2, 'bridge'), node(3), node(4, 'bridge')];
        const removed = link(10, nodes[0], nodes[1], { mode });
        const peer = link(11, nodes[2], nodes[1], { mode });
        const f = fixture({ nodes, links: [removed, peer] });
        const untouched = mode === 'reverse' ? MAIN : BRIDGE;
        f.files.set(f.key(nodes[1]._id, untouched), 'unchanged other-profile bytes');
        f.files.set(f.key(nodes[3]._id, MAIN), 'independent bytes');
        const peersBefore = structuredClone(peer), usersBefore = structuredClone(f.users);
        await f.cascade.undeployLink(removed);
        const bridgeConfig = JSON.parse(f.files.get(f.key(nodes[1]._id, mode === 'reverse' ? BRIDGE : MAIN)));
        if (mode === 'reverse') {
            assert.deepEqual(bridgeConfig, JSON.parse(f.generator.generateCombinedBridgeConfig([{ ...peer, portalNode: nodes[2] }])));
        } else {
            assert.ok(bridgeConfig.inbounds.some(inbound => inbound.port === peer.tunnelPort));
            assert.ok(!bridgeConfig.inbounds.some(inbound => inbound.port === removed.tunnelPort));
            assert.ok(bridgeConfig.inbounds.some(inbound => inbound.settings?.clients?.some(client => client.id === f.users[0].xrayUuid)));
        }
        const portalConfig = JSON.parse(f.files.get(f.key(nodes[0]._id, MAIN)));
        assert.ok(portalConfig.inbounds.some(inbound => inbound.settings?.clients?.some(client => client.id === f.users[0].xrayUuid)));
        assert.equal(f.files.get(f.key(nodes[1]._id, untouched)), 'unchanged other-profile bytes');
        assert.equal(f.files.get(f.key(nodes[3]._id, MAIN)), 'independent bytes');
        assert.deepEqual(peer, peersBefore); assert.deepEqual(f.users, usersBefore);
        assert.equal(f.events.some(event => event.kind === 'exec' && event.command.includes('systemctl stop')), false);
        assert.equal(f.events.filter(event => event.kind === 'acquire' && event.node === nodes[1]._id).length, 1);
        assert.equal(f.events.filter(event => event.kind === 'release' && event.node === nodes[1]._id).length, 1);
        assert.equal(f.locks.size, 0);
    }));
}
