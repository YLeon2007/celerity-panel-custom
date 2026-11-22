'use strict';

const { isDeepStrictEqual: equal } = require('node:util');
const { createHash } = require('node:crypto');
const { isIP } = require('node:net');
const { performance } = require('node:perf_hooks');
const { mongo: { BSON }, Types: { ObjectId } } = require('mongoose');
const { createRetireStore } = require('./rebuildRelayRetireStore');
const { isPristine, createStore } = require('./rebuildRelayBackendStore');
const { inspectAccountSources } = require('./rebuildRelayAccountInventory');
const { collectionName: DIRECTORY, logicalAccount, readDirectory } = require('./rebuildRelayDirectory');
const { GRANTS, authorityKeys } = require('./rebuildRelayGrantStore');
const { readRelayAuthority, captureRelayEffect, identityChanged } = require('./rebuildRelayEffectAuthority');
const { CONNECT_TIMEOUT_MS } = require('./rebuildSshLimits');

const fail = code => Object.assign(new Error(code), { code });
const unavailable = () => fail('REBUILD_RETIRE_PREVIEW_UNAVAILABLE');
const changed = () => fail('PREVIEW_CHANGED');
const protectedChange = () => fail('REBUILD_RETIRE_PROTECTED_CHANGE');
const confirmationRequired = () => fail('REBUILD_RETIRE_CONFIRMATION_REQUIRED');
const validId = id => typeof id === 'string' && /^[a-f0-9]{24}(?![\s\S])/.test(id);
const count = value => Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);
const network = new Set(['ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN']);
const sshNetwork = error => error?.code === 'SSH_ADMISSION_TIMEOUT' || error?.level === 'client-timeout'
    || ((error?.level == null || ['client-dns', 'client-socket'].includes(error.level)) && network.has(error?.code));
const stale = new Set(['PREVIEW_CHANGED', 'REBUILD_LINK_CHANGED', 'REBUILD_PREVIEW_CHANGED', 'REBUILD_NODE_RETIRE_CHANGED',
    'REBUILD_L2TP_REMOVE_PREVIEW_CHANGED', 'REBUILD_L2TP_REMOVE_CHANGED',
    'REBUILD_L2TP_REMOVE_SESSIONS_BUSY', 'REBUILD_L2TP_REMOVE_IPSEC_BUSY']);
const read = { maxTimeMS: 5000, readPreference: 'primary', readConcern: { level: 'majority' }, raw: true };
const decode = (raw, options) => raw == null ? null : BSON.deserialize(raw, options);
const all = (collection, filter, cap) => collection.find(filter, { ...read, limit: cap + 1, sort: { _id: 1 } }).toArray();
const envKeys = [...authorityKeys, 'C3_REBUILD_ENABLED', 'C3_REBUILD_L2TP_INSTALL_ENABLED', 'ENCRYPTION_KEY'];
const sameFixedImage = (a, b) => ['node', 'grants', 'config'].every(key => equal(a[key], b[key]));

// Exact inverse of the DB publication in rebuildRelayRemove, not a generic
// exemption for a freshly observed absent state. Other fields (even hidden or
// unknown ones), the node card and grant must remain byte-for-byte unchanged.
const removedFields = ['clientCidr', 'tproxyPort', 'fwmark', 'routeTable', 'pskEncrypted', 'pskHint', 'secretRevision',
    'localAddress', 'poolStart', 'poolEnd', 'dnsServers', 'mtu', 'mru', 'backupId', 'routingMode', 'routingVersion',
    'rebuildInstallToken', 'rebuildMachineId', 'installedAt', 'lastVerifiedAt', 'lastSyncAt'];
function removedState(before, after) {
    if (!before || !after) return false;
    const options = { promoteValues: false, bsonRegExp: true };
    const expected = decode(before, options), current = decode(after, options);
    if (!(current.updatedAt instanceof Date) || !Number.isFinite(current.updatedAt.getTime())) return false;
    Object.assign(expected, { status: 'not_installed', desiredState: 'absent', updatedAt: current.updatedAt });
    for (const key of removedFields) delete expected[key];
    return BSON.serialize(expected).equals(after) && isPristine(decode(after));
}

// The API creates a service on each request. Only the exact frozen estimate
// can join the originating store and Remove helper; JSON, copies and replay
// cannot. Bound the retained graph/store data even for non-HTTP callers.
const proofs = new Map();
const ttl = 120_000, max = 32;
function remember(estimate, resume) {
    const now = performance.now();
    for (const [key, entry] of proofs) if (entry.until <= now) proofs.delete(key);
    while (proofs.size >= max) proofs.delete(proofs.keys().next().value);
    proofs.set(estimate, { until: now + ttl, resume });
}

// Evidence is process-local, survives request-local factories, and never comes
// from lastSync/health flags. Expiry and eviction are only loss of history.
const outagesByDb = new WeakMap();
const outageTtl = 300_000, maxOutages = 256;
function observeOutage(db, key, endpoint, reachable) {
    let outages = outagesByDb.get(db);
    if (!outages) outagesByDb.set(db, outages = new Map());
    if (reachable) { outages.delete(key); return null; }
    const now = performance.now();
    for (const [id, entry] of outages) if (entry.at + outageTtl <= now) outages.delete(id);
    const identity = createHash('sha256').update(JSON.stringify(endpoint)).digest('hex');
    const previous = outages.get(key);
    if (previous?.identity === identity) return previous;
    outages.delete(key);
    while (outages.size >= maxOutages) outages.delete(outages.keys().next().value);
    const entry = { identity, at: now, since: new Date(Date.now()).toISOString() };
    outages.set(key, entry);
    return entry;
}

async function observeSsh(node, binding) {
    const SSH = require('./nodeSSH');
    const { host: ip, port, username, sshHostKeySha256, machineId } = binding?.binding ?? {};
    const ssh = binding && new SSH({ ...node, ip, ssh: { ...node.ssh, port, username } },
        { expectedHostKeySha256: sshHostKeySha256, expectedEndpoint: { ip, port, username } });
    if (ssh) ssh.usePool = false;
    let signal, opening = false;
    try {
        // Classify only errors from admission, never from the remote command
        // or from a wrapper that also collapses auth and pin failures.
        try {
            if (binding) await ssh.connectDirectOnce(CONNECT_TIMEOUT_MS);
            else {
                const deadline = performance.now() + CONNECT_TIMEOUT_MS;
                signal = AbortSignal.timeout(CONNECT_TIMEOUT_MS);
                await SSH._acquireDirectSlot(signal);
                try {
                    signal.throwIfAborted();
                    if (performance.now() >= deadline) throw unavailable();
                    opening = true;
                    await SSH.probeDirectKex(node.ip, node.ssh?.port ?? 22, signal);
                    signal.throwIfAborted();
                    if (performance.now() >= deadline) throw fail('SSH_ADMISSION_TIMEOUT');
                }
                finally { SSH._releaseDirectSlot(); }
            }
        } catch (error) {
            if (error?.code === 'SSH_HOST_KEY_MISMATCH') throw identityChanged();
            if ((binding || opening) && (sshNetwork(error) || (signal?.aborted && error === signal.reason))) return false;
            throw unavailable();
        }
        if (binding) {
            const result = await ssh.exec('/usr/bin/head -c 34 /etc/machine-id', { timeout: 10000 });
            if (result?.code !== 0 || result.stderr !== '' || ![machineId, `${machineId}\n`].includes(result.stdout)) {
                throw identityChanged();
            }
        }
        return true;
    } finally {
        ssh?.disconnect();
    }
}

function validateEndpoint(node) {
    const { ip, xray, ssh } = node;
    const username = ssh?.username ?? 'root';
    const host = typeof ip === 'string' && (isIP(ip) || (ip.length <= 254 && /^[a-z0-9.-]+(?![\s\S])/i.test(ip)
        && ip.replace(/\.$/, '').split('.').every(part => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(part))
        && !/^(?:\d+|0x[\da-f]+)$/i.test(ip.replace(/\.$/, '').split('.').at(-1))));
    const port = value => Number.isInteger(value) && value >= 1 && value <= 65535;
    const text = value => typeof value === 'string' && value.length > 0;
    if (!host || !port(xray?.agentPort ?? 62080) || !text(xray?.agentToken) || /[^\x21-\x7e]/.test(xray.agentToken)
        || xray.agentTls !== undefined && typeof xray.agentTls !== 'boolean'
        || !port(ssh?.port ?? 22) || typeof username !== 'string' || !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}(?![\s\S])/.test(username)
        || [ssh?.privateKey, ssh?.password].some(value => value != null && typeof value !== 'string')
        || !(text(ssh?.privateKey) || text(ssh?.password))) throw unavailable();
}

async function observeAgent(sync, node) {
    let reply;
    try { reply = await sync.readRebuildReverseObservation(node, '/info', 5000); }
    catch (error) {
        if (!error?.response && !error?.request?.res && error?.httpStatus == null
            && (network.has(error?.code) || error?.code === 'AGENT_OBSERVATION_TIMEOUT'
                || (error?.isAxiosError === true && error.code === 'ECONNABORTED'))) return false;
        throw unavailable();
    }
    if (reply?.status !== 200 || typeof reply.data !== 'string') throw unavailable();
    let data;
    try { data = JSON.parse(reply.data); } catch { throw unavailable(); }
    if (typeof data?.agent_version !== 'string' || !data.agent_version) throw unavailable();
    return true;
}

function createRebuildRelayRetire({ Link, Node, State, L2tpUser, env, sync, relayGrantStore, locks,
    gate, retireGraph, verifyLinks, sameProtectedTarget, removal, guard }) {
    let store;
    const target = () => store ??= createRetireStore({ Link, Node, State, L2tpUser, env });

    async function fixedImage(id) {
        const config = Object.fromEntries(envKeys.filter(key => Object.hasOwn(env, key)).map(key => [key, env[key]]));
        const node = await Node.collection.findOne({ _id: new ObjectId(id) }, read);
        const grants = await all(Node.db.collection(GRANTS), { nodeId: id }, 1);
        if (!node || grants.length > 1) throw unavailable();
        return { node, grants, config };
    }
    async function image(id) {
        const ref = { $in: [new ObjectId(id), id] };
        const fixed = await fixedImage(id);
        const states = await all(State.collection, { node: ref }, 1);
        const accounts = await all(L2tpUser.collection, { relayNode: ref }, 2048);
        const directory = await Node.db.collection(DIRECTORY).findOne({ _id: 'directory' }, read);
        if (states.length > 1 || accounts.length > 2048) throw unavailable();
        return { ...fixed, state: states[0] ?? null, accounts, directory };
    }
    async function initial(id) {
        const snapshot = await target().capture(id), before = await image(id);
        const node = decode(before.node), state = decode(before.state);
        if (String(node._id) !== id || node.type !== 'xray' || node.cascadeRole !== 'relay'
            || (node.role ?? 'relay') !== 'relay' || node.useCustomConfig) throw unavailable();
        const installed = state?.status === 'installed' && state.desiredState === 'installed';
        if (!installed && (!isPristine(state) || before.accounts.length)) throw unavailable();
        return { snapshot, before, node, state, installed };
    }
    async function snapshotStill(id, snapshot) {
        if (!target().sameSnapshot(snapshot, await target().capture(id))) throw changed();
    }
    async function classify(id, data) {
        const { node } = data;
        validateEndpoint(node);
        const authority = await readRelayAuthority(env, relayGrantStore);
        const binding = captureRelayEffect(env, relayGrantStore, authority, id, node, { optional: !data.installed });
        if (data.state?.rebuildMachineId != null && data.state.rebuildMachineId !== binding?.binding.machineId) throw identityChanged();
        const agent = await observeAgent(sync, node);
        const agentOutage = observeOutage(Node.db, `${id}:agent`, [node.ip, node.xray.agentPort, node.xray.agentTls, node.xray.agentToken], agent);
        const ssh = await observeSsh(node, binding);
        const sshOutage = observeOutage(Node.db, `${id}:ssh`, [node.ip, node.ssh, binding?.binding, binding?.generation], ssh);
        if (binding) await binding.check();
        if (agent && ssh) return { mode: 'online', binding, unavailableSince: null };
        const earliest = agentOutage && (!sshOutage || agentOutage.at <= sshOutage.at) ? agentOutage : sshOutage;
        return { mode: 'abandon', unavailableSince: earliest.since };
    }
    async function preservedDirectory(data, binding) {
        if (data.before.directory !== null) return null;
        if (!binding.listMode) return data.before.accounts.map(raw => logicalAccount(decode(raw)));
        const rows = await createStore(State, L2tpUser, true).sourceRows(null);
        const { legacy } = inspectAccountSources({ rows, listMode: true });
        if (rows.directory !== null || !legacy) throw unavailable();
        return [...legacy].sort((a, b) => (a.login > b.login) - (a.login < b.login));
    }
    async function afterRemove(id, before, backfill) {
        const after = await image(id);
        if (!sameFixedImage(before, after) || after.accounts.length || !removedState(before.state, after.state)) throw changed();
        if (before.directory !== null) {
            if (!equal(before.directory, after.directory)) throw changed();
        } else {
            const directory = await readDirectory(Node.db);
            if (!directory || Object.keys(directory).length !== 4 || !equal(directory, decode(after.directory))
                || !equal(directory.accounts, backfill)) throw changed();
        }
        // Do not recapture authority until the Remove-only delta is proved.
        const snapshot = await target().capture(id);
        if (!equal(after, await image(id))) throw changed();
        return snapshot;
    }
    async function previewRetireRelay(nodeId) {
        gate();
        if (!validId(nodeId)) throw fail('REBUILD_INVALID_REQUEST');
        const { estimate, resume } = await locks.run(async (verify, retain) => {
            if (typeof retain !== 'function') throw fail('REBUILD_LOCK_LOST');
            const data = await initial(nodeId);
            const { mode, unavailableSince } = await classify(nodeId, data);
            const graph = await retireGraph({ nodeId, mode, preview: true }, verify);
            let l2tp = null;
            if (mode === 'online' && data.installed && graph.allowed) l2tp = await removal.previewRetireL2tp(nodeId, verify, retain);
            const accountCount = data.before.accounts.length;
            const activeClients = mode === 'abandon' ? null : data.installed ? l2tp?.activeClients ?? null : 0;
            const allowed = graph.allowed && (mode === 'abandon' || !data.installed ||
                (l2tp?.nodeId === nodeId && l2tp.confirmable === true && l2tp.accountCount === accountCount && count(activeClients)));
            await snapshotStill(nodeId, data.snapshot);
            if (!equal(await image(nodeId), data.before)) throw changed();
            await verifyLinks(nodeId, graph.previewId);
            await verify();
            const estimate = Object.freeze({ nodeId, mode, allowed, accountCount, activeClients, unavailableSince,
                ...(!graph.allowed && { code: 'REBUILD_RETIRE_PROTECTED_CHANGE' }) });
            return { estimate, resume: allowed && (until => apply(estimate, data, graph, l2tp, until)) };
        });
        if (resume) remember(estimate, resume);
        return estimate;
    }
    async function apply(estimate, data, original, l2tp, until) {
        gate();
        const { nodeId, mode } = estimate;
        let phase = 'preflight', l2tpRemoved = false;
        const fresh = () => { if (performance.now() >= until) throw confirmationRequired(); };
        try {
            return await locks.run(async (verify, retain) => {
                if (typeof retain !== 'function') throw fail('REBUILD_LOCK_LOST');
                try {
                    fresh();
                    await snapshotStill(nodeId, data.snapshot);
                    await verifyLinks(nodeId, original.previewId);
                    // Abandon is an explicit relinquishment, even if the
                    // target is back. Only local evidence and survivors apply.
                    let binding;
                    if (mode === 'online') {
                        const observed = await classify(nodeId, data);
                        if (observed.mode !== 'online') throw changed();
                        binding = observed.binding;
                    }
                    let graph = await retireGraph({ nodeId, mode, preview: true }, verify);
                    if (!graph.allowed) throw protectedChange();
                    if (graph.previewId !== original.previewId) throw changed();
                    let snapshot = data.snapshot;
                    const check = async () => {
                        await snapshotStill(nodeId, snapshot);
                        await verifyLinks(nodeId, graph.previewId);
                        await verify();
                    };
                    if (mode === 'online' && data.installed) {
                        if (l2tp?.confirmable !== true) throw confirmationRequired();
                        const backfill = await preservedDirectory(data, binding);
                        await check();
                        fresh();
                        let result;
                        try {
                            result = await guard(verify, retain, async () => {
                                // Remove fences its changing state, replicas and
                                // directory. Keep the rest of the original store
                                // image and the complete graph bound throughout it.
                                if (!sameFixedImage(data.before, await fixedImage(nodeId))) throw fail('REBUILD_NODE_RETIRE_CHANGED');
                                await verifyLinks(nodeId, original.previewId);
                            },
                                () => removal.confirmRetireL2tp(nodeId, l2tp, verify, retain));
                        } catch (error) {
                            if (error?.outcome === 'removed') { phase = 'removed'; l2tpRemoved = true; }
                            else if (error?.outcome === 'unknown' || error?.retryAllowed === false) phase = 'unknown';
                            throw error;
                        }
                        if (result?.nodeId !== nodeId || result.status !== 'not_installed') {
                            phase = 'unknown';
                            throw unavailable();
                        }
                        phase = 'removed';
                        l2tpRemoved = true;
                        await verifyLinks(nodeId, original.previewId);
                        snapshot = await afterRemove(nodeId, data.before, backfill);
                        graph = await retireGraph({ nodeId, mode, preview: true }, verify);
                        // The graph survivor fingerprint includes the protected
                        // target MAIN interfaces, not its legitimate PPP delta.
                        if (!graph.allowed || graph.survivorPreview !== original.survivorPreview
                            || !sameProtectedTarget(original, graph)) throw changed();
                    }
                    await check();
                    await retireGraph({ nodeId, mode, preview: false, expectedPreview: graph.previewId,
                        async beforeEffects() { await check(); if (phase === 'preflight') fresh(); },
                        onEffect() { phase = 'graph'; }, onCommit() { phase = 'committed'; },
                        finish: session => target().finish(snapshot, session, verify),
                    }, verify);
                    return { nodeId, status: 'deleted' };
                } catch (error) {
                    if (phase === 'preflight') throw error;
                    if (phase !== 'committed') retain();
                    throw Object.assign(fail(phase === 'removed' ? 'REBUILD_RETIRE_PARTIAL' :
                        phase === 'committed' ? 'REBUILD_GRAPH_COMMITTED_CLEANUP_FAILED' : 'REBUILD_RETIRE_OUTCOME_UNCONFIRMED'),
                    { outcome: phase === 'removed' ? 'partial' : phase === 'committed' ? 'deleted' : 'unknown',
                        retryAllowed: false, ...(l2tpRemoved && { l2tpRemoved }) });
                }
            });
        } catch (error) {
            if (error?.retryAllowed === false) throw error;
            if (phase === 'committed') throw Object.assign(fail('REBUILD_RETIRE_LOCK_RELEASE_UNCONFIRMED'),
                { outcome: 'deleted', retryAllowed: false, ...(l2tpRemoved && { l2tpRemoved }) });
            if (phase === 'preflight' && stale.has(error?.code)) throw changed();
            throw error;
        }
    }
    async function confirmRetireRelay(nodeId, estimate, decision) {
        gate();
        const entry = proofs.get(estimate);
        if (!entry || !validId(nodeId) || nodeId !== estimate.nodeId) throw confirmationRequired();
        proofs.delete(estimate);
        if (performance.now() >= entry.until) throw confirmationRequired();
        const expected = estimate.mode === 'abandon' ? 'abandon' : estimate.activeClients > 0 ? 'force' : 'delete';
        if (expected !== decision) throw fail('REBUILD_RETIRE_DECISION_REQUIRED');
        return entry.resume(entry.until);
    }
    return { previewRetireRelay, confirmRetireRelay };
}

module.exports = { createRebuildRelayRetire };
