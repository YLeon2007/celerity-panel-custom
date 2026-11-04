'use strict';
// Pure construction/enrollment refusal: NO SSH, DB, endpoint execution or env file.
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { randomBytes, randomUUID, createHash } = require('node:crypto');
const root = process.env.C3_CANDIDATE_ROOT || path.resolve(__dirname, '../..');
const from = name => require(path.join(root, name));
const { createTestPhysicalController, createRootTestPhysicalAuthority } = from('src/modules/relay-l2tp/runtime/testPhysicalController');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = from('src/modules/relay-l2tp/domain/topologyExecutionContext');
const old = [
    ['6ab18adc63913ebd4a917471', '132.243.230.19', 'xray-main'],
    ['6ab93ad2646b4b7d2f43c907', '94.103.2.186', 'xray-main'],
    ['6ab18d9c63913ebd4a917670', '50.114.160.63', 'xray-bridge'],
    ['6ab4b53bc4c0304573e06c72', '104.143.201.72', 'xray-bridge'],
    ['6ab189dc63913ebd4a917399', '212.119.42.100', 'xray-bridge'],
];
const config = { version: 1, executionContext: TEST, nodes: old.map(([nodeId, ip, targetProfile], i) => ({
    nodeId, targetProfile, endpoint: { ip, port: 2222, username: 'c3-test-runner' },
    physical: { machineId: i === 4 ? '7fa266f995fe4aa69e96cf7d01359e34' : randomBytes(16).toString('hex'),
        bootId: randomUUID(), sshHostKeySha256: randomBytes(32).toString('hex') },
    maintenanceId: randomUUID(), planHash: 'a'.repeat(64),
    guard: { pid: 100 + i, start: '123', socket: '/var/lib/c3-test-node-isolation/recovery.sock' },
    operatorKeyPath: '/etc/celerity/SYNTHETIC-NEVER-READ.key',
    originalSnapshot: { proofRef: 'synthetic-never-used', configSha256: 'b'.repeat(64), unitSha256: 'c'.repeat(64),
        serviceActive: 'inactive', serviceEnabled: 'disabled' },
})), host: { owner: randomUUID(), guard: { pid: 200, start: '321', socket: '/var/lib/c3-test-node-isolation/host.sock',
    owner: '', planHash: 'a'.repeat(64), session: { pid: 201, start: '320' } },
    backend: { instanceId: 'd'.repeat(64), pid: 333, processStartTime: '42' } } };
config.host.guard.owner = config.host.owner;
let channels = 0, observations = 0, captureSpawns = 0;
const options = { openChannel: async () => { channels++; throw Error('NO_CHANNEL_MAY_OPEN'); },
    readObservations: async () => { observations++; throw Error('NO_OBSERVATIONS_MAY_BE_READ'); } };
const env = { PANEL_DOMAIN: TEST.hostIdentity, L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' };
async function main() {
    const control = createTestPhysicalController({ config, ...options });
    assert.equal(control.runnerTransport, 'preinstalled-attested-v1'); control.close();
    for (const ownerEnrollment of [false, true]) {
        const rootControl = createRootTestPhysicalAuthority({ env, read: () => Buffer.from(JSON.stringify(config)), ownerEnrollment,
            captureSpawn: () => { captureSpawns++; throw Error('NO_CAPTURE_MAY_SPAWN'); }, ...options });
        assert.equal(rootControl.runnerTransport, 'preinstalled-attested-v1'); rootControl.close();
    }
    const cases = [];
    const variants = [
        ['four-fresh-private-nodes', c => { c.nodes = c.nodes.slice(0, 4); c.nodes.forEach((p, i) => { p.nodeId = randomBytes(12).toString('hex'); p.endpoint = { ip: `10.203.118.${i + 11}`, port: 22, username: 'root' }; }); }],
        ['five-fresh-private-nodes', c => c.nodes.forEach((p, i) => { p.nodeId = randomBytes(12).toString('hex'); p.endpoint = { ip: `10.203.118.${i + 11}`, port: 22, username: 'root' }; })],
        ['historical-ids-private-endpoints', c => c.nodes.forEach((p, i) => { p.endpoint = { ip: `10.203.118.${i + 11}`, port: 22, username: 'root' }; })],
    ];
    for (const [name, mutate] of variants) {
        const fresh = structuredClone(config); mutate(fresh);
        assert.throws(() => createTestPhysicalController({ config: fresh, ...options }), { code: 'TEST_PHYSICAL_AUTHORITY_UNKNOWN_RETAINED' });
        assert.throws(() => createRootTestPhysicalAuthority({ env, read: () => Buffer.from(JSON.stringify(fresh)), ...options }), { code: 'TEST_PHYSICAL_AUTHORITY_UNKNOWN_RETAINED' });
        assert.throws(() => createRootTestPhysicalAuthority({ env, read: () => Buffer.from(JSON.stringify(fresh)), ownerEnrollment: true,
            captureSpawn: () => { captureSpawns++; throw Error('NO_CAPTURE_MAY_SPAWN'); }, ...options }), { code: 'TEST_PHYSICAL_AUTHORITY_UNKNOWN_RETAINED' });
        cases.push({ name, constructors: ['physical', 'root-runtime', 'root-owner-capture'],
            result: 'refused-before-channel', code: 'TEST_PHYSICAL_AUTHORITY_UNKNOWN_RETAINED' });
    }
    // Stop the native path here: no replacement/positive controller, owner row,
    // enrollment, binding, operation, Mongo or invented terminal proof.
    assert.equal(channels, 0); assert.equal(observations, 0); assert.equal(captureSpawns, 0);
    const files = ['src/modules/relay-l2tp/runtime/testPhysicalController.js', 'scripts/test-topology-owner.js',
        'src/modules/relay-l2tp/runtime/createTopologyOperationRuntime.js', 'src/modules/relay-l2tp/repositories/topologyExecutionBindingStore.js'];
    const result = { status: 'precise-blocker-proved', control: 'fixed-historical-config-construction-only-accepted-in-all-three-constructors', cases,
        constructorRefusals: cases.reduce((n, row) => n + row.constructors.length, 0),
        enrollment: 'not-invoked-controller-construction-refused', channels, observations, captureSpawns, persistence: 'not-invoked-no-store-created',
        source: Object.fromEntries(files.map(file => [file, createHash('sha256').update(fs.readFileSync(path.join(root, file))).digest('hex')])),
        missingCapability: 'Existing TEST physical/capture controller accepts only its fixed five historical IDs/endpoints; no public constructor accepting fresh approved rootless pins. A replacement controller or relaxed config would exceed scope.',
        nativeRuntimeJoin: 'not-run-blocked-before-enrollment', realMongo: false, syntheticPhysical: true };
    if (process.argv[2]) fs.writeFileSync(process.argv[2], JSON.stringify(result, null, 2) + '\n');
    console.log(JSON.stringify(result, null, 2));
}
main().catch(e => { console.error(e); process.exitCode = 1; });
