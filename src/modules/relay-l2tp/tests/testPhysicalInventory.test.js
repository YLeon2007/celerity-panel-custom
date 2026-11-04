'use strict';
// MODELLED physical/SSH/guard facts. No connection, DB or physical authority.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { createTestPhysicalController, createRootTestPhysicalAuthority } = require('../runtime/testPhysicalController');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');
const canonical = value => JSON.stringify(value, function (key, current) {
    return current && !Array.isArray(current) && typeof current === 'object'
        ? Object.fromEntries(Object.keys(current).sort().map(k => [k, current[k]])) : current;
});
function fixture() {
    const inventory = { version: 1, profile: 'accepted-test-v1', executionContext: TEST, sharedNodeId: 'aaaaaaaaaaaaaaaaaaaaaaa2', nodes: [1, 2].map(i => ({
        nodeId: 'aaaaaaaaaaaaaaaaaaaaaaa' + i, targetProfile: i === 1 ? 'xray-main' : 'xray-bridge',
        endpoint: { ip: `10.204.11.${i}`, port: 2222, username: 'c3-test-runner' },
        physical: { machineId: String(i).repeat(32), bootId: randomUUID(), sshHostKeySha256: String(i).repeat(64) },
        profiles: i === 1 ? ['xray-main'] : ['xray-main', 'xray-bridge'],
    })) };
    const config = { version: 2, inventorySha256: createHash('sha256').update(canonical(inventory)).digest('hex'), executionContext: TEST,
        nodes: inventory.nodes.map(pin => ({ ...structuredClone(pin), profiles: undefined, maintenanceId: randomUUID(), planHash: 'a'.repeat(64),
            guard: { pid: 100, start: '123', socket: '/var/lib/c3-test-node-isolation/recovery.sock' }, operatorKeyPath: '/etc/celerity/operator.key',
            originalSnapshot: { proofRef: 'fresh-original', configSha256: 'b'.repeat(64), unitSha256: 'c'.repeat(64), serviceActive: 'inactive', serviceEnabled: 'disabled' } })),
        host: { owner: randomUUID(), guard: { pid: 201, start: '124', socket: '/var/lib/c3-test-node-isolation/host.sock', owner: '', planHash: 'a'.repeat(64), session: { pid: 202, start: '125' } },
            backend: { instanceId: 'd'.repeat(64), pid: 203, processStartTime: '126' } } };
    for (const pin of config.nodes) delete pin.profiles;
    config.host.guard.owner = config.host.owner;
    return { config, inventory };
}
function observation(config, pin) {
    const { proofRef, ...readback } = pin.originalSnapshot;
    return { ...structuredClone(pin), host: pin.nodeId === 'aaaaaaaaaaaaaaaaaaaaaaa2' ? config.host : null,
        durableOriginals: { version: 1, bundleSha256: 'e'.repeat(64), readback: { source: 'node-readback', ...readback } },
        runnerState: { head: null, journal: 'absent', legacyState: 'absent', terminal: null } };
}
const env = { PANEL_DOMAIN: TEST.hostIdentity, L2TP_EXECUTION_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' };
test('fresh inventory accepts exact independently supplied pins and binds the shared old backend', async () => {
    const { config, inventory } = fixture(); let entered = 0;
    const controller = createTestPhysicalController({ config, inventory,
        openChannel: async pin => ({ alive: true, close() {}, request: async () => observation(config, pin) }) });
    try { await controller.withHeldAuthority(TEST, held => held.withVerifiedAuthority({ executionContext: TEST, action: 'enroll',
        enrollment: { nodeId: config.nodes[0].nodeId, targetProfile: config.nodes[0].targetProfile, endpoint: config.nodes[0].endpoint,
            nodeIdentity: { machineId: inventory.nodes[0].physical.machineId, sshHostKeySha256: inventory.nodes[0].physical.sshHostKeySha256 },
            bootId: inventory.nodes[0].physical.bootId, predecessorGeneration: 'none' } }, async proof => {
        entered++; assert.deepEqual(proof.oldBackend, { ...config.host.backend, processTree: 'stopped', dispatch: 'disabled' });
    })); } finally { controller.close(); }
    assert.equal(entered, 1);
});
test('ordinary root reads only the fixed private inventory and physical configs', async () => {
    const { config, inventory } = fixture(); const reads = [];
    const controller = createRootTestPhysicalAuthority({ env, read(file) {
        reads.push(file); assert.ok(['/etc/celerity/topology-test-physical.json', '/etc/celerity/topology-test-inventory.json'].includes(file));
        return Buffer.from(JSON.stringify(file.endsWith('inventory.json') ? inventory : config));
    }, openChannel: async pin => ({ alive: true, close() {}, request: async () => observation(config, pin) }),
    captureSpawn() { assert.fail('ordinary root must not recapture'); } });
    try { assert.equal(await controller.withHeldAuthority(TEST, async held => { await held.assertHeld(); return 11; }), 11); }
    finally { controller.close(); }
    assert.deepEqual(reads.sort(), ['/etc/celerity/topology-test-inventory.json', '/etc/celerity/topology-test-physical.json']);
});
test('fresh endpoint, key, boot, aliases, shared mapping and inventory digest refuse before any channel', () => {
    for (const fault of ['endpoint', 'key', 'boot', 'alias', 'shared', 'digest', 'unaccepted']) {
        const { config, inventory } = fixture(); let opens = 0;
        if (fault === 'endpoint') config.nodes[0].endpoint.ip = '10.204.11.99';
        if (fault === 'key') config.nodes[0].physical.sshHostKeySha256 = 'f'.repeat(64);
        if (fault === 'boot') config.nodes[0].physical.bootId = randomUUID();
        if (fault === 'alias') inventory.nodes[1].physical.machineId = inventory.nodes[0].physical.machineId;
        if (fault === 'shared') inventory.sharedNodeId = 'ffffffffffffffffffffffff';
        if (fault === 'digest') config.inventorySha256 = 'f'.repeat(64);
        assert.throws(() => createTestPhysicalController({ config, ...(fault !== 'unaccepted' ? { inventory } : {}),
            openChannel() { opens++; } }), /TEST_PHYSICAL_AUTHORITY/);
        assert.equal(opens, 0);
    }
});
test('fresh changed endpoint/host key/lost hold after entry permanently revoke, including after repair', async () => {
    for (const fault of ['endpoint', 'key', 'hold']) {
        const { config, inventory } = fixture(); const channels = []; let drift = false;
        const controller = createTestPhysicalController({ config, inventory, openChannel: async pin => {
            const channel = { get alive() { return !(drift && fault === 'hold'); }, close() {}, async request() {
                const value = observation(config, pin);
                if (drift && fault === 'endpoint') value.endpoint.ip = '10.204.11.99';
                if (drift && fault === 'key') value.physical.sshHostKeySha256 = 'f'.repeat(64);
                return value;
            } }; channels.push(channel); return channel;
        } });
        try { await assert.rejects(controller.withHeldAuthority(TEST, async held => {
            drift = true; await assert.rejects(held.assertHeld()); drift = false; await assert.rejects(held.assertHeld());
        })); await assert.rejects(controller.withHeldAuthority(TEST, () => assert.fail('revoked hold reused'))); }
        finally { controller.close(); }
        assert.equal(channels.length, 2);
    }
});
test('the actual Python contract reads the same canonical inventory digest', () => {
    const { inventory, config } = fixture();
    const { spawnSync } = require('node:child_process');
    const directory = require('node:path').resolve(__dirname, '../../../../scripts/test-node-isolation');
    const result = spawnSync('/usr/bin/python3', ['-B', '-c', `
import sys,json
import isolation as m
p=json.load(sys.stdin)
inventory=m.accepted_inventory(p['config'],read=lambda path:p['raw'].encode() if path==m.INVENTORY else None)
print(m.digest(json.dumps(inventory,sort_keys=True,separators=(',',':')).encode()))
`], { cwd: directory, input: JSON.stringify({ config, raw: canonical(inventory) }), encoding: 'utf8', timeout: 5000 });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), config.inventorySha256);
});
test('owner-enrollment root requires the same accepted inventory before any capture can spawn', () => {
    const { config, inventory } = fixture(); let spawns = 0;
    const read = file => Buffer.from(JSON.stringify(file.endsWith('inventory.json') ? inventory : config));
    const controller = createRootTestPhysicalAuthority({ env, read, ownerEnrollment: true,
        captureSpawn() { spawns++; assert.fail('construction cannot capture'); } });
    controller.close();
    config.inventorySha256 = 'f'.repeat(64);
    assert.throws(() => createRootTestPhysicalAuthority({ env, read, ownerEnrollment: true,
        captureSpawn() { spawns++; } }), /TEST_PHYSICAL_AUTHORITY/);
    assert.equal(spawns, 0);
});
