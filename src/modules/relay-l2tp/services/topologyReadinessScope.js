'use strict';
// Private async capability; caller plans never supply a binding or connection.
const { AsyncLocalStorage } = require('node:async_hooks');
const { readinessCommandId } = require('./topologyReadinessProtocol');
const scopes = new AsyncLocalStorage();
const fields = ['executionContext', 'operationId', 'nodeId', 'candidateHash', 'backupId', 'targetProfile',
    'attemptId', 'generation', 'predecessorGeneration'];
function current(nodeId) {
    const scope = scopes.getStore();
    if (!scope?.active || scope.poisoned || !scope.entries.has(nodeId)) throw new Error('Readiness authority unavailable');
    return { scope, entry: scope.entries.get(nodeId) };
}
function topologyReadinessProfile(nodeId) { return current(nodeId).entry.binding.targetProfile; }
async function invokeTopologyReadiness(nodeId, command, payload) {
    const { scope, entry } = current(nodeId);
    if (scope.busy) throw new Error('Readiness dispatch already active');
    scope.busy = true;
    try {
        const binding = entry.binding;
        const request = { ...Object.fromEntries(fields.map(key => [key, binding[key]])),
            commandId: readinessCommandId(command, binding.commandIds.verify), bootId: binding.bootId };
        await scope.assertCurrent();
        current(nodeId);
        const body = command === 'restore-users' ? { users: payload.map(user => ({ ...user })) } : { expectation: { ...payload } };
        const result = await entry.invoke(command, { ...request, ...body });
        await scope.assertCurrent();
        current(nodeId);
        return result;
    } catch (error) {
        scope.poisoned = true;
        for (const entry of scope.entries.values()) entry.poison();
        throw error;
    } finally { scope.busy = false; }
}
async function withTopologyReadinessScope(entries, assertCurrent, work) {
    const scope = { active: true, poisoned: false, busy: false,
        entries: new Map(entries.map(entry => [entry.binding.nodeId, entry])), assertCurrent };
    if (scope.entries.size !== entries.length || typeof assertCurrent !== 'function') throw new Error('Invalid readiness scope');
    try {
        return await scopes.run(scope, async () => {
            const result = await work();
            await assertCurrent();
            if (scope.poisoned || scope.busy) throw new Error('Readiness outcome unconfirmed');
            return result;
        });
    } catch (error) {
        scope.poisoned = true;
        for (const entry of scope.entries.values()) entry.poison();
        throw error;
    } finally { scope.active = false; }
}
module.exports = { withTopologyReadinessScope, invokeTopologyReadiness, topologyReadinessProfile };
