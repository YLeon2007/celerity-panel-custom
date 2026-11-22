'use strict';

const { captureRelayBinding, sameRelayBinding } = require('./rebuildRelayAuthorization');

const IDENTITY_CHANGED = 'REBUILD_L2TP_IDENTITY_CHANGED';
const fail = code => Object.assign(new Error(code), { code });
const identityChanged = () => fail(IDENTITY_CHANGED);
const isIdentityChanged = error => error?.code === IDENTITY_CHANGED;
const grantErrors = new Set(['CONFLICT', 'INVALID', 'ENV_INVALID', 'REGISTRY_INVALID', 'PERSISTENCE_UNAVAILABLE']
    .map(suffix => `REBUILD_L2TP_GRANT_${suffix}`));
const isGrantAuthorityError = error => grantErrors.has(error?.code);

function readRelayAuthority(env, relayGrantStore) {
    if (relayGrantStore) return relayGrantStore.snapshot();
    // Standalone effect/test callers can still use the original ENV contract.
    return { env, grants: [], sourceFor: () => null };
}

function captureRelayEffect(env, relayGrantStore, snapshot, id, node, options) {
    let captured;
    try { captured = captureRelayBinding(snapshot.env, id, node, options); }
    catch (error) {
        if (relayGrantStore && error?.code === 'REBUILD_L2TP_BINDING_MISMATCH') throw identityChanged();
        throw error;
    }
    if (!captured || !relayGrantStore) return captured;
    const source = snapshot.sourceFor(id);
    const generation = generationFor(snapshot, id, source);
    return Object.freeze({ binding: captured.binding, listMode: captured.listMode, source, generation, merged: true,
        async check(currentNode = node, currentSnapshot) {
            const fresh = currentSnapshot ?? await readRelayAuthority(env, relayGrantStore);
            const currentSource = fresh.sourceFor(id);
            if (currentSource !== source || generationFor(fresh, id, currentSource) !== generation) throw identityChanged();
            let current;
            try {
                current = captureRelayBinding(fresh.env, id, captured.listMode || node !== undefined ? currentNode : undefined);
            } catch (error) {
                if (error?.code === 'REBUILD_L2TP_BINDING_MISMATCH') throw identityChanged();
                throw error;
            }
            if (current.listMode !== captured.listMode || !sameRelayBinding(current.binding, captured.binding)) throw identityChanged();
            return captured.binding;
        } });
}

function generationFor(snapshot, id, source) {
    if (source !== 'db') return undefined;
    const generation = snapshot.grants.find(row => String(row.nodeId) === id)?.generation;
    if (typeof generation !== 'string' || !generation) throw fail('REBUILD_L2TP_GRANT_INVALID');
    return generation;
}

module.exports = { readRelayAuthority, captureRelayEffect, IDENTITY_CHANGED, identityChanged, isIdentityChanged, isGrantAuthorityError };
