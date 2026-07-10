/**
 * Hourly rollup writer.
 *
 * After a batch's events are persisted to Parquet, we also fold their aggregate
 * counts into MongoDB hourly rollups (one doc per node+hour). This is additive
 * ($inc), so re-processing the SAME batch would double-count — the caller only
 * invokes this on the first successful processing of a batch (processService
 * marks the batch processed right after, and dedup drops re-deliveries), so each
 * batch contributes exactly once.
 *
 * Top-K maps (destinations, users) are incremented per key and trimmed lazily on
 * read to stay bounded; here we only bump counts.
 */

const logger = require('../../utils/logger');

const TOPK_INC_LIMIT = 200; // cap distinct keys bumped per hour-bucket write

function hourBucket(date) {
    const d = new Date(date.getTime());
    d.setUTCMinutes(0, 0, 0);
    return d;
}

/**
 * Fold a set of canonical events (already partitioned to one date/node/hour) into
 * the matching hourly rollup document.
 */
async function foldPartition(dateStr, nodeId, hour, events) {
    if (!events || events.length === 0) return;
    const AccessLogRollup = require('../../models/accessLogRollupModel');

    // All events here share the same UTC hour; derive the bucket from the first.
    const bucket = new Date(`${dateStr}T${String(hour).padStart(2, '0')}:00:00.000Z`);

    let accepted = 0, rejected = 0, blocked = 0, tcp = 0, udp = 0;
    const destInc = {};
    const userInc = {};
    for (const ev of events) {
        if (ev.action === 'accepted') accepted++;
        else if (ev.action === 'rejected') rejected++;
        else if (ev.action === 'blocked') blocked++;
        if (ev.network === 'tcp') tcp++;
        else if (ev.network === 'udp') udp++;

        const dest = ev.destinationHost || ev.destinationIp;
        if (dest && Object.keys(destInc).length < TOPK_INC_LIMIT) {
            destInc[dest] = (destInc[dest] || 0) + 1;
        }
        if (ev.email && Object.keys(userInc).length < TOPK_INC_LIMIT) {
            userInc[ev.email] = (userInc[ev.email] || 0) + 1;
        }
    }

    const inc = {
        total: events.length,
        accepted, rejected, blocked, tcp, udp,
    };
    // Map fields are incremented with dotted paths.
    for (const [k, v] of Object.entries(destInc)) {
        inc[`topDestinations.${sanitizeKey(k)}`] = v;
    }
    for (const [k, v] of Object.entries(userInc)) {
        inc[`topUsers.${sanitizeKey(k)}`] = v;
    }

    try {
        await AccessLogRollup.updateOne(
            { hourBucket: bucket, nodeId: String(nodeId) },
            { $inc: inc, $set: { updatedAt: new Date() } },
            { upsert: true }
        );
    } catch (e) {
        // Rollups are a best-effort accelerator; never fail the pipeline over one.
        logger.warn(`[AccessLogs] rollup fold failed: ${e.message}`);
    }
}

// Mongo map keys cannot contain '.' or start with '$'. Escape both.
function sanitizeKey(k) {
    return String(k).replace(/\$/g, '\uFF04').replace(/\./g, '\uFF0E').slice(0, 253);
}

/**
 * Read rollups for a time range as a compact dashboard payload. Works without
 * DuckDB, so it is the degraded-mode data source.
 */
async function readSummary(from, to, nodeId) {
    const AccessLogRollup = require('../../models/accessLogRollupModel');
    const q = { hourBucket: { $gte: hourBucket(from), $lte: to } };
    if (nodeId) q.nodeId = String(nodeId);
    const docs = await AccessLogRollup.find(q).sort({ hourBucket: 1 }).lean();

    let total = 0, accepted = 0, rejected = 0, blocked = 0;
    const destAgg = {};
    const userAgg = {};
    const series = [];
    for (const d of docs) {
        total += d.total || 0;
        accepted += d.accepted || 0;
        rejected += d.rejected || 0;
        blocked += d.blocked || 0;
        series.push({ bucket: d.hourBucket, hits: d.total || 0 });
        mergeTopK(destAgg, d.topDestinations);
        mergeTopK(userAgg, d.topUsers);
    }

    return {
        totals: { total, accepted, rejected, blocked },
        topDestinations: topK(destAgg, 10),
        topUsers: topK(userAgg, 10),
        series,
    };
}

function mergeTopK(target, mapField) {
    if (!mapField) return;
    const entries = mapField instanceof Map ? mapField.entries() : Object.entries(mapField);
    for (const [k, v] of entries) {
        const key = unsanitizeKey(k);
        target[key] = (target[key] || 0) + (v || 0);
    }
}

function unsanitizeKey(k) {
    return String(k).replace(/\uFF04/g, '$').replace(/\uFF0E/g, '.');
}

function topK(agg, n) {
    return Object.entries(agg)
        .sort((a, b) => b[1] - a[1])
        .slice(0, n)
        .map(([key, hits]) => ({ key, hits }));
}

module.exports = {
    foldPartition,
    readSummary,
    hourBucket,
    sanitizeKey,
};
