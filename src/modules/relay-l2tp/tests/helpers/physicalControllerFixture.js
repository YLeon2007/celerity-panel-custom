'use strict';
// Explicit simulated physical/kernel/systemd authority; real subprocess channels,
// actual installed file bytes and actual runner journal readbacks in a fake root.
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { spawn } = require('node:child_process');
const { createTestPhysicalController, AttestationChannel } = require('../../runtime/testPhysicalController');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../../domain/topologyExecutionContext');
const nodes = {
    '6ab18adc63913ebd4a917471': ['132.243.230.19', 'xray-main'],
    '6ab93ad2646b4b7d2f43c907': ['94.103.2.186', 'xray-main'],
    '6ab18d9c63913ebd4a917670': ['50.114.160.63', 'xray-bridge'],
    '6ab4b53bc4c0304573e06c72': ['104.143.201.72', 'xray-bridge'],
    '6ab189dc63913ebd4a917399': ['212.119.42.100', 'xray-main'],
};
function physicalControllerFixture(t, { nodeId, identity, bootId, maintenanceId, runnerRoot }) {
    const config = { version: 1, executionContext: TEST, nodes: Object.entries(nodes).map(([id, [ip, targetProfile]], i) => ({
        nodeId: id, targetProfile, endpoint: { ip, port: 2222, username: 'c3-test-runner' },
        physical: id === nodeId ? { ...identity, bootId } : { machineId: id === '6ab189dc63913ebd4a917399' ? '7fa266f995fe4aa69e96cf7d01359e34' : String(i + 1).repeat(32), sshHostKeySha256: String(i + 1).repeat(64), bootId: randomUUID() },
        maintenanceId: id === nodeId ? maintenanceId : randomUUID(), planHash: 'a'.repeat(64),
        guard: { pid: 100 + i, start: '123', socket: '/var/lib/c3-test-node-isolation/recovery.sock' }, operatorKeyPath: '/etc/celerity/test-operator.key',
    })), host: { owner: randomUUID(), guard: { pid: 200, start: '321', socket: '/var/lib/c3-test-node-isolation/host.sock',
        owner: '', planHash: 'a'.repeat(64), session: { pid: 201, start: '320' } }, backend: { instanceId: 'a'.repeat(64), pid: 333, processStartTime: '42' } } };
    config.host.guard.owner = config.host.owner;
    const installed = path.join(runnerRoot, 'usr/local/bin/celerity-topology-node-runner');
    fs.copyFileSync(path.join(__dirname, '../../node-artifacts/topology/runner.sh'), installed); fs.chmodSync(installed, 0o750);
    fs.chmodSync(path.join(runnerRoot, 'usr/local/etc/xray'), 0o755);
    const children = [];
    const controller = createTestPhysicalController({ config, openChannel: async pin => {
        const observation = { nodeId: pin.nodeId, physical: pin.physical, endpoint: pin.endpoint, targetProfile: pin.targetProfile,
            maintenanceId: pin.maintenanceId, planHash: pin.planHash, guard: pin.guard,
            host: pin.nodeId === '6ab189dc63913ebd4a917399' ? config.host : null,
            runnerState: { head: null, journal: 'absent', legacyState: 'absent', terminal: null } };
        const child = spawn(process.execPath, [path.join(__dirname, 'physicalObservationProcess.js'), JSON.stringify(observation),
            ...(pin.nodeId === nodeId ? [runnerRoot] : [])], { stdio: ['pipe', 'pipe', 'pipe'] });
        children.push(child);
        return new AttestationChannel(child.stdout, child.stdin, child, { timeoutMs: 2000 });
    } });
    t.after(async () => { controller.close(); for (const child of children) if (child.exitCode === null && child.signalCode === null) { const done = new Promise(r => child.once('exit', r)); child.kill(); await done; } });
    return controller;
}
module.exports = { physicalControllerFixture };
