'use strict';
// Shared installedFixture adapters. Service/attach gate/PPP gate are actual;
// MAIN, user-runner, persistence and service-active observations are MODELED.
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { L2tpSimpleService } = require('../../services/l2tpSimpleService');
const { TopologyAttachIngressGate } = require('../../services/topologyAttachIngressGate');
const { createTopologyPppReadinessGate } = require('../../services/topologyPppReadinessGate');
const { cascadePathIngressPort } = require('../../domain/cascadePathIngress');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../../domain/topologyExecutionContext');
function modeledInstalledMain(state) {
    const groupId = String(state.routeGroup), pathKey = state.activePathKey;
    return { inbounds: [{ tag: `relay-l2tp-${groupId}`, listen: '0.0.0.0', port: 12345, protocol: 'dokodemo-door',
        settings: { network: 'tcp,udp', followRedirect: true }, streamSettings: { sockopt: { tproxy: 'tproxy' } } }],
        outbounds: [{ tag: `cascade-${pathKey}`, protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port: cascadePathIngressPort(groupId, pathKey) }] } }],
        routing: { rules: [{ type: 'field', inboundTag: [`relay-l2tp-${groupId}`], outboundTag: `cascade-${pathKey}` }] } };
}
function installedIngressAdapters({ models, state, options = {}, readMain = () => modeledInstalledMain(state) }) {
    Object.assign(options, { readbackOk: true, prepares: [], plans: [], gateCalls: [] });
    const credentialRevision = state.secretRevision; // fixed modeled readback, never derive success from a later row
    const ingress = new TopologyAttachIngressGate({ nodeExecutionResolver: { async resolve() { return {
        async connect() {}, disconnect() {}, async exec(command, execOptions) {
            assert.equal(command, 'python3 -');
            options.gateCalls.push('ingress');
            const main = structuredClone(readMain());
            if (options.changeMain) options.changeMain(main);
            const setup = `import builtins,io,subprocess\nbuiltins.open=lambda *a,**k:io.StringIO(${JSON.stringify(JSON.stringify(main))})\nsubprocess.run=lambda *a,**k:type('Result',(),{'returncode':0,'stdout':'active\\n','stderr':''})()\n`;
            const result = spawnSync('python3', ['-'], { input: setup + execOptions.stdin, encoding: 'utf8', timeout: 10000 });
            return { code: result.status, stdout: result.stdout, stderr: result.stderr };
        } }; } } });
    const ppp = createTopologyPppReadinessGate({ ...models, executionContext: context, readOnly: true,
        NodeSSH: class { async exec() { options.gateCalls.push('users'); options.onUsers?.(); return { code: options.readbackOk ? 0 : 65, stderr: '', stdout: JSON.stringify({
            ok: options.readbackOk, code: 'USERS_VERIFIED', credentialRevision, enabledUserCount: 1, managedUserCount: 1 }) + '\n' }; } } });
    const forbidden = () => { throw new Error('No credential or provisioning writes permitted'); };
    const service = new L2tpSimpleService({ ...models, allowRemoteExecution: true, topologyIngressGate: ingress, topologyPppReadinessGate: ppp,
        l2tpService: { install: forbidden, getOperation: forbidden }, stateManagementService: { configureRelay: forbidden, revealPsk: forbidden },
        userManagementService: { createUser: forbidden, deleteUser: forbidden, importUser: forbidden }, stateRepository: { getTopologyRevision: forbidden }, nodeSSHFactory: forbidden });
    const prepare = async ({ operationPlan: plan }) => {
        assert.ok(Object.isFrozen(plan));
        assert.equal(models.NodeOperationLock.rows.filter(row => row.operationId === plan.operationId).length, plan.resourceNodeIds.length);
        const proofPlan = options.changePlan ? options.changePlan(plan) : plan;
        options.plans.push(proofPlan);
        const proof = await service.prepareConfiguredRelayIngress({ operationPlan: proofPlan });
        options.prepares.push(proof); return proof;
    };
    return { service, ingress, ppp, prepare, options };
}
module.exports = { installedIngressAdapters, modeledInstalledMain };
