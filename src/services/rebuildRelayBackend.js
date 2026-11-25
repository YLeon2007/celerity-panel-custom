'use strict';

const { isIP } = require('node:net');
const { isDeepStrictEqual: equal } = require('node:util');
const { appliedLink } = require('./rebuildAppliedLink');
const hex = (value, size) => typeof value === 'string' && value.length === size && /^[a-f0-9]+$/.test(value);
const { withNode, installOwner } = require('./rebuildLocks');
const { componentFor } = require('./rebuildCoordinator');
const { readRelayAuthority, captureRelayEffect, isIdentityChanged, isGrantAuthorityError } = require('./rebuildRelayEffectAuthority');
const { validateRebuildMode } = require('./rebuildMode');
const { runFreshRelayInstall } = require('./rebuildRelayInstall');
const { createStore, read } = require('./rebuildRelayBackendStore');
const { makeDesired } = require('./rebuildRelayBackendDesired');
const { resolveAccountSources } = require('./rebuildRelayAccountInventory');
const { compileRebuildGraph } = require('../modules/relay-l2tp/domain/rebuildTopologyCompiler');
const { storedExit, sameExit } = require('./rebuildExit');
const { grantIdentity, validActor } = require('./rebuildRelayInstallRecoveryStore');

const fail = code => Object.assign(new Error(code), { code });
const eligible = (node, id, listMode) => String(node?._id) === id && node.type === 'xray'
    && node.active === true && node.cascadeRole === 'relay' && !node.useCustomConfig && (listMode || !!isIP(node.ip));

async function readTopology(Node, Link, node, panelDomain) {
    const id = String(node._id);
    const links = await read(Link.find({ $or: [{ active: true }, { rebuildDelete: true }] })
        .select('portalNode bridgeNode active rebuildDelete lifecycle status geoRouting priority mode tunnelProtocol tunnelTransport tunnelPort tunnelUuid rebuildApplied rebuildApplyEpoch rebuildExit rebuildAppliedExit +rebuildAppliedMainSha256 +rebuildKcpApplied'));
    // Offline also describes an applied link whose tunnel is unconfirmed.
    const applied = link => link.active === true && !link.rebuildDelete && !link.lifecycle && ['deployed', 'online', 'offline'].includes(link.status);
    const notApplied = () => fail('REBUILD_L2TP_TOPOLOGY_NOT_APPLIED');

    const ids = new Set(componentFor(links, [id]));
    const scoped = links.filter(link => ids.has(String(link.portalNode)) && ids.has(String(link.bridgeNode)));
    // This is a graph inventory, not evidence that the data plane works.
    if (scoped.some(link => !applied(link))) {
        throw fail('REBUILD_L2TP_TOPOLOGY_NOT_APPLIED');
    }
    const peers = ids.size > 1 ? await read(Node.find({ _id: { $in: [...ids].filter(n => n !== id) } })
        .select('type active useCustomConfig cascadeRole ip domain')) : [];
    if (peers.length !== ids.size - 1 || peers.some(n => n.type !== 'xray' || !n.active || n.useCustomConfig)) {
        throw fail('REBUILD_L2TP_TOPOLOGY_NOT_APPLIED');
    }
    const nodes = [node, ...peers];
    // Status and the five-key tunnel receipt do not attest the portal policy.
    // Legacy shared rows may omit both selectors; an explicit pick must match
    // a separately published Apply selector before the existing MAIN proof.
    for (const row of scoped) {
        const desired = storedExit(row.rebuildExit), applied = storedExit(row.rebuildAppliedExit);
        if ((row.rebuildExit !== undefined && desired === undefined)
            || (row.rebuildAppliedExit !== undefined && (applied === undefined || row.rebuildApplied == null))
            || !sameExit(desired, applied)) throw notApplied();
    }
    let byNodeId;
    try { ({ byNodeId } = compileRebuildGraph({ nodes, links: scoped, affectedNodeIds: [...ids] })); }
    catch { throw notApplied(); }
    const relay = byNodeId.get(id);
    // Match the listener in MAIN, not every link incident to the relay. Use
    // the mKCP stamp only to refuse a still-applied listener, never as proof.
    if (scoped.some(link => (link.tunnelTransport === 'kcp' && String(appliedLink(link).listener) === id)
        || (link.rebuildKcpApplied != null && String(link.rebuildApplied?.listener) === id))) {
        throw fail('REBUILD_L2TP_KCP_LISTENER_UNSUPPORTED');
    }
    const ready = relay.outgoing.filter(edge => byNodeId.get(edge.target).role === 'bridge').map(({ id, link, target }) => {
        const expected = appliedLink(link), saved = link.rebuildApplied;
        if (!Number.isInteger(expected.port) || expected.port < 1 || expected.port > 65535
            || typeof expected.uuid !== 'string' || !/^\S{1,128}(?![\s\S])/.test(expected.uuid)
            || !saved || typeof saved !== 'object' || Object.keys(saved).length !== 5 || String(saved.listener) !== String(expected.listener)
            || !['mode', 'protocol', 'port', 'uuid'].every(key => saved[key] === expected[key])
            || !hex(link.rebuildApplyEpoch, 32) || !hex(link.rebuildAppliedMainSha256, 64)) {
            throw fail('REBUILD_L2TP_TOPOLOGY_NOT_APPLIED');
        }
        return { id, target, expected, epoch: link.rebuildApplyEpoch, sha: link.rebuildAppliedMainSha256 };
    });
    if (!ready.length || ready.some(edge => edge.sha !== ready[0].sha)) throw fail('REBUILD_L2TP_TOPOLOGY_NOT_APPLIED');
    const transit = [...relay.outgoing.filter(edge => edge.mode === 'reverse'),
        ...relay.incoming.filter(edge => edge.mode === 'forward' && edge.protocol === 'vless')]
        .map(({ id: linkId, mode, link }) => ({ linkId, mode, port: link.tunnelPort, uuid: link.tunnelUuid }));
    return {
        appliedMain: ready[0].sha,
        // Compare authoritative inputs, not the periodically updated health time.
        topologyWitness: { ready, peers: peers.map(({ _id, ip, domain, cascadeRole }) => [String(_id), ip, domain, cascadeRole])
            .sort((a, b) => a[0].localeCompare(b[0])), relay: [node.ip, node.domain],
            links: scoped.map(l => [String(l._id), String(l.portalNode), String(l.bridgeNode), l.mode, l.tunnelProtocol,
                l.tunnelPort, l.tunnelUuid, l.priority, l.geoRouting, l.rebuildApplied, l.rebuildApplyEpoch,
                l.rebuildExit, l.rebuildAppliedExit])
                .sort((a, b) => a[0].localeCompare(b[0])) },
        controlPlaneAddresses: [...new Set([panelDomain, ...nodes.flatMap(n => [n.ip, n.domain])].filter(Boolean))].sort(),
        carryDomain: relay.carryDomain,
        ...(transit.length && { transit }),
    };
}

// Load the production driver only after the locked inventory checks.
function defaultDriver(options) {
    return require('./rebuildRelayDirect').createRelayDirect(options);
}

async function precheckSource({ node, fence, installation, currentUsers }, createRelayDirect, env, checkAuthority) {
    await checkAuthority();
    const refused = () => fail('REBUILD_L2TP_ACCOUNT_SOURCE_PREFLIGHT_REFUSED');
    let remote, primary;
    try {
        remote = await createRelayDirect({ node, env, binding: fence.binding, fence });
        if (typeof remote?.checkChap !== 'function' || typeof remote?.close !== 'function') throw refused();
        // The persisted source projection is an expected preimage, not evidence
        // of host state. DIRECT authenticates the host, receipt and actual CHAP
        // rows. This is an inspection only, with no requested CHAP delta.
        if ((await remote.checkChap(installation, currentUsers, currentUsers, checkAuthority))?.changed !== false) throw refused();
    } catch (error) {
        primary = error?.code === 'REBUILD_LOCK_LOST' || isIdentityChanged(error) || isGrantAuthorityError(error) ? error : refused();
        throw primary;
    } finally {
        try { await remote?.close?.(); }
        catch { if (!primary) throw refused(); }
    }
    await checkAuthority();
}

function createRebuildRelayBackend({ Node, Link, State, L2tpUser, locks, env, relayGrantStore, actor: defaultActor,
    createRelayDirect = defaultDriver, getCleanupConsent }) {
    return async function installRelay(id, { actor = defaultActor, cleanupSessionId, foreignCleanup } = {}) {
        let enabled;
        try { enabled = validateRebuildMode(env); } catch { /* Conflicting mode. */ }
        if (enabled !== true || env.C3_REBUILD_L2TP_INSTALL_ENABLED !== 'true' || typeof id !== 'string'
            || id.length !== 24 || !/^[a-f0-9]{24}$/.test(id)) {
            throw fail('REBUILD_L2TP_INSTALL_DISABLED');
        }
        const snapshot = relayGrantStore ? await relayGrantStore.snapshot() : readRelayAuthority(env);
        const fence = captureRelayEffect(env, relayGrantStore, snapshot, id);
        const { machineId } = fence.binding;
        const getNode = (nodeId = id) => read(Node.findById(nodeId).select('ip domain active type cascadeRole useCustomConfig ssh'));
        let store, owner;
        const scope = fence.source === 'db' && fence.generation && validActor(actor) && cleanupSessionId
            ? { nodeId: id, generation: fence.generation, actor, sessionId: cleanupSessionId } : undefined;
        let cleanupStore;
        async function consentStore() {
            cleanupStore ??= getCleanupConsent();
            const store = await cleanupStore;
            return store;
        }
        function proofForStore(proof) {
            if (proof?.digest && proof.manual?.length === 0 && proof.cleanable?.length === proof.keys?.length) {
                return { check: proof.check, keys: proof.keys, digest: proof.digest, cleanable: true, manual: false };
            }
        }
        const cleanupConsent = scope && getCleanupConsent && {
            issue: async proof => (await consentStore()).issue(scope, proofForStore(proof)),
            consume: async (confirmation, proof) => (await consentStore()).consume(scope, confirmation, proofForStore(proof)),
            bind: async (confirmation, backupId) => (await consentStore()).bind(scope, confirmation, backupId),
            finish: async (confirmation, result) => (await consentStore()).finish(scope, confirmation, result),
        };
        return runFreshRelayInstall(id, {
            authorize: relayGrantStore ? async () => { await fence.check(); return true; }
                : () => { try { fence.check(); return true; } catch { return false; } },
            machineId, foreignCleanup, cleanupConsent,
            ...(relayGrantStore && { unifiedIdentity: true }),
            allowPackagePreparation: fence.listMode === true && fence.source === 'db',
            lock: fn => locks.run((verifyLock, retainLock) => withNode(id, async () => {
                if (await verifyLock() === false) throw fail('REBUILD_LOCK_LOST');
                if (fence.listMode && fence.source === 'db' && validActor(actor)) owner = installOwner(retainLock);
                return fn(verifyLock, retainLock);
            }), { allowStaleUnlock: false }),
            async inventory() {
                const node = await getNode();
                if (!eligible(node, id, fence.listMode)) return { eligible: false };
                const authority = await readRelayAuthority(env, relayGrantStore);
                await fence.check(node, authority);
                const bound = relayGrantStore && captureRelayEffect(env, relayGrantStore, authority, id, node);
                store = createStore(State, L2tpUser ?? require('../modules/relay-l2tp/models/l2tpUserModel'), fence.listMode);
                const snapshot = await store.snapshot(id);
                if (!snapshot.pristine) return snapshot;
                const topology = await readTopology(Node, Link, node, env.PANEL_DOMAIN);
                const sourceSnapshot = await store.sourceRows(id);
                const key = env.ENCRYPTION_KEY;
                const sourceInventory = await resolveAccountSources({ nodeId: id, rows: sourceSnapshot, env, relayGrantStore,
                    snapshot: authority, key, machineId,
                    readNode: getNode, listMode: fence.listMode });
                const payload = makeDesired(id, sourceInventory.occupied, topology.controlPlaneAddresses, key, sourceInventory);
                if (sourceInventory.inherited && payload.desired.users[0].ipAddress !== payload.desired.poolStart) {
                    throw fail('REBUILD_L2TP_ACCOUNT_INVENTORY_INVALID');
                }
                return { ...snapshot, ...topology, ...payload, sourceSnapshot, inherited: sourceInventory.inherited,
                    sources: sourceInventory.prechecks, key, node, bound, eligible: true, nodeId: id };
            },
            verifyBinding: fence.listMode || relayGrantStore ? async inventory => {
                const current = await getNode();
                if (!eligible(current, id, fence.listMode)) throw fail('REBUILD_L2TP_NOT_FRESH_RELAY');
                await (inventory?.bound ?? fence).check(current);
                if (inventory?.key !== undefined && env.ENCRYPTION_KEY !== inventory.key) throw fail('REBUILD_L2TP_CREDENTIAL_KEY_INVALID');
                for (const source of inventory?.sources ?? []) await source.verifyBinding();
            } : undefined,
            precheckSources: async ({ sources }, checkAuthority) => {
                for (const source of sources) await precheckSource(source, createRelayDirect, env, checkAuthority);
            },
            connect: inventory => createRelayDirect({ node: inventory.node, env,
                ...(inventory.bound && { fence: inventory.bound }) }),
            async verifyTopology(inventory) {
                const node = await getNode();
                if (!eligible(node, id, fence.listMode)) throw fail('REBUILD_L2TP_NOT_FRESH_RELAY');
                const current = await readTopology(Node, Link, node, env.PANEL_DOMAIN);
                if (!equal(current, Object.fromEntries(Object.keys(current).map(key => [key, inventory[key]])))) {
                    throw fail('REBUILD_L2TP_TOPOLOGY_NOT_APPLIED');
                }
            },
            async proveMain({ appliedMain }, remote, guard) {
                if (await remote.proveAppliedMain?.(appliedMain, guard) !== true) throw fail('REBUILD_L2TP_TOPOLOGY_NOT_APPLIED');
            },
            prepare: ({ nodeId, desired, controlPlaneAddresses, carryDomain, transit, appliedMain }, remote, cleanup) =>
                remote.prepare({ nodeId, desired, controlPlaneAddresses, carryDomain, appliedMain, ...(transit && { transit }),
                    ...(cleanup && { foreignCleanup: cleanup }) }),
            reserve: (inventory, backupId, verifyLock, packagePreparation) => store.reserve({ ...inventory, backupId, machineId, packagePreparation,
                ...(owner && { recovery: { owner, actor, authority: grantIdentity(inventory.bound), key: inventory.key } }),
            }, verifyLock),
            handBackRecovery: () => owner?.handBack(),
            verifyReservation: reservation => store.verifyReservation(reservation),
            progress: (reservation, stage, percent) => store.progress(reservation, stage, percent),
            finish: (reservation, verifyLock) => store.finish(reservation, verifyLock),
            restore: (reservation, verifyLock) => store.restore(reservation, verifyLock),
        });
    };
}

module.exports = { createRebuildRelayBackend };
