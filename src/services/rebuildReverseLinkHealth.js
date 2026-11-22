'use strict';

const { createHash, randomBytes } = require('node:crypto');
const { performance } = require('node:perf_hooks');

const appliedStatuses = ['deployed', 'online', 'offline'];
const isReverse = link => (link.mode ?? 'reverse') === 'reverse';
const noObservation = { lastHealthCheck: null, latencyMs: null };
const unverified = Object.freeze({ status: 'deployed', ...noObservation, lastError: '' });
const observationSelect = '+rebuildApplied +rebuildApplyEpoch +rebuildReverseObservation';
const maxAgeMs = 90_000;
const timeoutMs = 2_000; // Mongo reads/writes.
// Agent samples the native heartbeat for 11s, with a 13s handler deadline.
const observationTimeoutMs = 15_000;
const concurrency = 5;
const batchSize = 50;
const sha256 = input => createHash('sha256').update(input).digest('hex');
const id = value => String(value?._id ?? value);
const objectId = value => /^[a-f0-9]{24}$/.test(value);
const tupleFilter = {
    active: true, mode: 'reverse', lifecycle: null, rebuildDelete: { $ne: true },
    status: { $in: appliedStatuses }, tunnelProtocol: 'vless', tunnelTransport: 'tcp', tunnelSecurity: 'reality',
    'rebuildApplied.mode': 'reverse', 'rebuildApplied.protocol': 'vless',
};

function subject(link) {
    const { rebuildApplied: receipt, rebuildApplyEpoch: epoch, updatedAt, tunnelUuid, tunnelPort } = link;
    const linkId = id(link._id), listener = id(link.portalNode), dialer = id(link.bridgeNode);
    if (!receipt || Object.keys(receipt).length !== 5 || link.active !== true || link.rebuildDelete || link.lifecycle
        || !appliedStatuses.includes(link.status) || link.mode !== 'reverse'
        || link.tunnelSecurity !== 'reality' || link.tunnelProtocol !== 'vless' || link.tunnelTransport !== 'tcp'
        // The rebuild composer only enables VLESS decryption for security=none.
        || ![undefined, 'vless-enc', 'none'].includes(link.tunnelEncryption)
        || receipt.mode !== 'reverse' || receipt.protocol !== 'vless' || id(receipt.listener) !== listener
        || ![linkId, listener, dialer].every(objectId) || listener === dialer
        || !Number.isInteger(tunnelPort) || tunnelPort < 1 || tunnelPort > 65535 || receipt.port !== tunnelPort
        || typeof tunnelUuid !== 'string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(tunnelUuid)
        || receipt.uuid !== tunnelUuid || !(updatedAt instanceof Date) || !Number.isFinite(updatedAt.getTime())
        || (epoch !== undefined && (typeof epoch !== 'string' || !/^[a-f0-9]{32}$/.test(epoch)))) return null;
    // Older rebuild receipts are usable; legacy rows without a receipt are not.
    // New Apply always rotates the epoch, even if the desired tuple is identical.
    return { linkId, listener, port: tunnelPort, identity: sha256(tunnelUuid.toLowerCase()),
        generation: sha256(JSON.stringify([linkId, listener, dialer, tunnelPort, tunnelUuid, link.tunnelEncryption,
            updatedAt.getTime(), epoch])) };
}

// Read-time expiry also covers a stopped cron, and raw legacy status is never proof.
function projectReverseHealth(row, now = Date.now()) {
    const { rebuildApplied, rebuildReverseObservation: proof, rebuildApplyEpoch, observationExpiresAt, ...link } = row;
    if (!isReverse(link)) return link;
    if (!appliedStatuses.includes(link.status)) return { ...link, ...noObservation };
    const observedAt = proof?.observedAt instanceof Date ? proof.observedAt.getTime() : NaN;
    const expiresAt = observedAt + maxAgeMs;
    if (proof?.version === 1 && proof.established === true && typeof proof.generation === 'string'
        && observedAt <= now && now < expiresAt
        && proof.generation === subject(row)?.generation) {
        return { ...link, ...unverified, status: 'online', lastHealthCheck: proof.observedAt, observationExpiresAt: expiresAt };
    }
    // Explicit null (unlike a missing receipt on legacy rows) marks a draft
    // that has never been applied. A previous TCP check could overwrite it.
    return { ...link, ...unverified, status: rebuildApplied === null ? 'pending' : 'deployed' };
}

async function getObservation(request, node, { linkId, port, identity }) {
    const challenge = randomBytes(16).toString('hex');
    const query = new URLSearchParams({ port: String(port), challenge, identity });
    const startedAt = Date.now();
    const start = performance.now();
    try {
        const response = await request(node, `/rebuild/reverse-observation/${linkId}?${query}`, observationTimeoutMs);
        if (response.status !== 200 || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers?.['content-type'])
            || typeof response.data !== 'string' || Buffer.byteLength(response.data) > 1024) return false;
        const body = JSON.parse(response.data);
        // All valid string values are hex. Count JSON member names as well as
        // parsed keys so a duplicate key cannot disappear into JSON.parse.
        if (!body || Object.keys(body).length !== 5 || response.data.match(/"(?:[^"\\]|\\.)*"\s*:/g)?.length !== 5
            || body.version !== 1 || body.linkId !== linkId || body.port !== port || body.challenge !== challenge
            || typeof body.established !== 'boolean') return false;
        const now = Date.now();
        return body.established && performance.now() - start < observationTimeoutMs && now >= startedAt && now - startedAt < observationTimeoutMs;
    } catch {
        // Axios errors contain credential-bearing request config. Never export or log them.
        return false;
    }
}

function createReverseObserver({ Link, Node, request }) {
    const inFlight = new Map();
    let sweeping = false, manualBusy = false, cursor;
    const receiver = listener => Node.findOne({ _id: listener, active: true, type: 'xray', useCustomConfig: { $ne: true },
        cascadeRole: { $in: ['portal', 'relay'] } }).select('ip xray.agentToken xray.agentPort xray.agentTls').maxTimeMS(timeoutMs).lean();
    async function observe(row, target) {
        const observedAt = new Date(Date.now());
        const node = await receiver(target.listener);
        let established = !!node?.xray?.agentToken && await getObservation(request, node, target);
        if (established) {
            const current = await receiver(target.listener);
            established = !!current && current.ip === node.ip && current.xray?.agentToken === node.xray.agentToken
                && current.xray?.agentPort === node.xray.agentPort && current.xray?.agentTls === node.xray.agentTls;
        }
        const now = Date.now();
        established = established && now >= +observedAt && now < +observedAt + maxAgeMs;
        const exact = key => Object.hasOwn(row, key) ? row[key] : { $exists: false };
        const result = await Link.updateOne({ ...tupleFilter,
            _id: row._id, portalNode: row.portalNode, bridgeNode: row.bridgeNode,
            updatedAt: row.updatedAt, rebuildApplyEpoch: exact('rebuildApplyEpoch'),
            tunnelPort: row.tunnelPort, tunnelUuid: row.tunnelUuid, tunnelEncryption: exact('tunnelEncryption'),
            rebuildApplied: row.rebuildApplied, rebuildReverseObservation: exact('rebuildReverseObservation'),
        }, { $set: { rebuildReverseObservation: { version: 1, generation: target.generation, observedAt, established } } },
        { timestamps: false, runValidators: true, maxTimeMS: timeoutMs });
        return result.matchedCount === 1 && established;
    }

    function sample(row) {
        const target = subject(row);
        if (!target) return Promise.resolve(false);
        const existing = inFlight.get(target.linkId);
        if (existing) return existing;
        const work = observe(row, target).finally(() => inFlight.delete(target.linkId));
        inFlight.set(target.linkId, work);
        return work;
    }

    return {
        async manual(linkId) {
            if (inFlight.has(String(linkId))) return inFlight.get(String(linkId));
            // No operator queue. Reserve one slot separate from the periodic sweep.
            if (manualBusy) return false;
            manualBusy = true;
            try {
                const row = await Link.findOne({ _id: linkId, ...tupleFilter }).select(observationSelect).maxTimeMS(timeoutMs).lean();
                return row ? await sample(row) : false;
            } finally { manualBusy = false; }
        },
        async sweep() {
            if (sweeping) return;
            sweeping = true;
            const page = range => Link.find({ ...tupleFilter, ...range }).sort({ _id: 1 })
                .select(observationSelect).limit(batchSize).maxTimeMS(timeoutMs).lean();
            try {
                let rows = await page(cursor ? { _id: { $gt: cursor } } : {});
                if (!rows.length && cursor) rows = await page({});
                cursor = rows.at(-1)?._id;
                for (let i = 0; i < rows.length; i += concurrency) {
                    await Promise.allSettled(rows.slice(i, i + concurrency).map(sample));
                }
            } finally { sweeping = false; }
        },
    };
}

async function clearOldReverseHealth(Link, id) {
    // Check the CURRENT document atomically, not the snapshot used by the
    // explicit health route. Do not touch pending, retiring or error states.
    const filter = {
        ...(id === undefined ? {} : { _id: id }),
        mode: { $in: ['reverse', null] }, // includes old rows without a mode
        active: true,
        rebuildDelete: { $ne: true },
        lifecycle: null,
        status: { $in: appliedStatuses },
    };
    const options = { timestamps: false };
    const update = id === undefined ? Link.updateMany.bind(Link) : Link.updateOne.bind(Link);
    const oldDraft = await update({ ...filter, rebuildApplied: { $type: 'null' } },
        { $set: { ...unverified, status: 'pending' } }, options);
    const other = await update({ ...filter, rebuildApplied: { $not: { $type: 'null' } },
        $or: [{ status: { $ne: 'deployed' } }, { lastHealthCheck: { $ne: null } },
            { latencyMs: { $ne: null } }, { lastError: { $nin: ['', null] } }],
    }, { $set: unverified }, options);
    return oldDraft.modifiedCount + other.modifiedCount;
}

module.exports = { isReverse, projectReverseHealth, clearOldReverseHealth, unverified, observationSelect, createReverseObserver };
