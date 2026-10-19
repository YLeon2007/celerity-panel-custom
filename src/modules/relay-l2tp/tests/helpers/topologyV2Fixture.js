'use strict';

// Local protocol fixtures only: no production authority, database or SSH.
const { createHash } = require('node:crypto');
const GENERATION = '00000000-0000-4000-8000-000000000017';
const executionFence = Object.freeze({ owner: 'worker-17', attempt: 1, generation: GENERATION });
function freeze(value) {
    if (value && typeof value === 'object') {
        Object.values(value).forEach(freeze);
        Object.freeze(value);
    }
    return value;
}
function backupId(operationId, node) {
    return `topology-${createHash('sha256').update([
        operationId, node.node, `sha256:${node.candidateHash}`, node.targetProfile,
    ].join('\0')).digest('hex')}`;
}
function bindingRecord(context, hostIdentity = 'test.infograd.online') {
    const { node } = context;
    return freeze({
        operationId: context.operationId, nodeId: node.node,
        topologyRevision: context.topologyRevision,
        priorDeployedRevision: context.priorDeployedRevision,
        candidateHash: `sha256:${node.candidateHash}`,
        backupId: context.backupId ?? backupId(context.operationId, node),
        targetProfile: node.targetProfile,
        executionContext: hostIdentity,
        owner: context.executionFence.owner, attempt: context.executionFence.attempt,
        generation: context.executionFence.generation,
        attemptId: `attempt-${context.executionFence.attempt}`,
        bootId: 'boot-local-fixture', maintenanceId: 'maintenance-local-fixture',
        // Explicit simulated initial enrollment, never a dispatch-time default.
        predecessorGeneration: 'none',
        commandIds: Object.fromEntries(['prepare', 'commit', 'verify', 'rollback', 'close'].map(
            command => [command, `${command}-${node.node}`],
        )),
    });
}
function bindingReader(records) {
    const rows = new Map(records.map(row => [row.nodeId, row]));
    return { rows, async readVerified(expected) { return rows.get(expected.nodeId) ?? null; } };
}
function runnerRequest(command) {
    const request = Object.fromEntries([
        ['operationId', 'operation-id'], ['nodeId', 'node-id'],
        ['candidateHash', 'candidate-hash'], ['backupId', 'backup-id'],
        ['targetProfile', 'target-profile'], ['executionContext', 'execution-context'],
        ['attemptId', 'attempt-id'], ['generation', 'generation'],
        ['predecessorGeneration', 'predecessor-generation'], ['commandId', 'command-id'],
        ['command', 'command'],
    ].map(([key, flag]) => [key, command.match(new RegExp(`--${flag} ([A-Za-z0-9._:-]+)`))?.[1]]));
    const checks = command.match(/--checks ([A-Za-z0-9_-]+)/)?.[1];
    if (checks) request.checks = JSON.parse(Buffer.from(checks, 'base64url').toString());
    return request;
}
function v2Receipt(request, overrides = {}) {
    const { artifact: _artifact, checks: _checks, ...fields } = request;
    return { ok: true, ...fields, protocolVersion: 2, completion: 'completed',
        phase: { prepare: 'prepared', commit: 'committed', verify: 'verified', rollback: 'rolledback' }[request.command],
        terminal: false, terminalOutcome: 'not-terminal', ownershipRetained: true,
        bootId: 'boot-local-fixture', completedCommand: request.command,
        systemdJob: request.command === 'prepare' ? 'not-applicable' : 'completed',
        serviceState: request.command === 'prepare' ? 'not-applicable' : 'active:running',
        ...overrides };
}
module.exports = { executionFence, bindingRecord, bindingReader, runnerRequest, v2Receipt, freeze };
