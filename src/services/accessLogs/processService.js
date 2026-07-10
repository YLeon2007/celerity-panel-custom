/**
 * Spool processor: drains durably-spooled ingest batches into ClickHouse.
 *
 * For each sealed spool file it:
 *   1. gunzips + splits NDJSON into { node_id, raw } records,
 *   2. optionally masks client IPs in the raw line (privacy setting),
 *   3. inserts the raw rows into ClickHouse access_ingest (a materialized view
 *      parses them into access_events), using the batch id as a dedup token so
 *      a retried batch is dropped natively,
 *   4. marks the batch processed (idempotency) and removes the spool file.
 *
 * The panel does NO per-event parsing: ClickHouse does it. That keeps CPU on the
 * panel proportional to bytes moved, not events, which matters on weak hardware.
 *
 * Runs on a timer and can be nudged via kick() right after an ingest so latency
 * stays low without a tight busy loop. A single-flight guard prevents concurrent
 * drains from racing on the same files. When ClickHouse is unavailable the run
 * stops and everything stays spooled for a later retry (at-least-once).
 */

const zlib = require('zlib');
const { promisify } = require('util');
const fsp = require('fs/promises');
const path = require('path');

const logger = require('../../utils/logger');
const spoolService = require('./spoolService');
const clickhouse = require('./clickhouseService');

const gunzip = promisify(zlib.gunzip);

// Decompression bomb guard: a batch body is capped at 8 MB compressed on
// ingest; refuse to inflate past this many bytes so a crafted batch cannot
// exhaust panel memory. Legit batches (~500 log lines) are far smaller.
const MAX_INFLATED_BYTES = 64 * 1024 * 1024; // 64 MB

const PROCESS_INTERVAL_MS = 10 * 1000;
const MAX_FILES_PER_RUN = 50;

// Keep processed dedup markers for a week: long enough to cover any agent retry
// backoff, short enough to bound the marker directory.
const PROCESSED_MARKER_TTL_MS = 7 * 24 * 60 * 60 * 1000;

let running = false;
let timer = null;
let kickPending = false;
let lastMarkerPruneAt = 0;

// Cached maskClientIp flag (checked per drain run, cheap TTL cache).
let _maskCache = { value: false, at: 0 };
const MASK_TTL_MS = 30 * 1000;
async function shouldMaskClientIp() {
    const now = Date.now();
    if (now - _maskCache.at > MASK_TTL_MS) {
        try {
            const Settings = require('../../models/settingsModel');
            const s = await Settings.get();
            _maskCache = { value: !!s?.accessLogs?.maskClientIp, at: now };
        } catch (_) {
            // On DB error keep the previous value but do not cache the failure.
            _maskCache.at = now - MASK_TTL_MS + 5000;
        }
    }
    return _maskCache.value;
}

/**
 * Privacy mask for client IPs (settings.accessLogs.maskClientIp).
 * IPv4 keeps the /24 (last octet zeroed); IPv6 keeps the first three hextets.
 * Exact source-IP search becomes impossible by design.
 */
function maskIp(ip) {
    if (!ip) return '';
    const v4 = ip.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$/);
    if (v4) return `${v4[1]}.0`;
    if (ip.includes(':')) {
        const parts = ip.split(':');
        return parts.slice(0, 3).join(':') + '::';
    }
    return ip;
}

// The source IP is the first token after the timestamp on an Xray access line
// (optionally prefixed by "from "). Mask it in place so the exact address never
// reaches storage when masking is enabled. Best-effort: a line that does not
// match is passed through unchanged (it will land with parse_ok handling in CH).
const SRC_IP_RE = /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\s+(?:from\s+)?)([^\s:]+)/;
function maskRawLine(raw) {
    if (!raw) return raw;
    return raw.replace(SRC_IP_RE, (m, prefix, ip) => prefix + maskIp(ip));
}

// Parse a single spool file into ClickHouse raw rows tagged with the node id.
// Throws on corrupt gzip OR on decompression past MAX_INFLATED_BYTES (both are
// treated as an undecodable batch and dropped by the caller).
async function parseSpoolFile(filePath, mask) {
    const { nodeId } = spoolService.parseSpoolName(filePath);
    const gz = await fsp.readFile(filePath);
    const ndjson = (await gunzip(gz, { maxOutputLength: MAX_INFLATED_BYTES })).toString('utf8');

    const rows = [];
    for (const line of ndjson.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        let rec;
        try {
            rec = JSON.parse(trimmed);
        } catch (_) {
            continue; // skip malformed NDJSON record
        }
        let raw = String(rec.raw == null ? '' : rec.raw);
        if (mask) raw = maskRawLine(raw);
        // The agent also sends a file offset per record; it is only used for
        // agent-side resume and is deliberately not stored.
        rows.push({ node_id: nodeId, raw });
    }
    return { nodeId, rows };
}

// Process a single spool file end-to-end. Returns the number of rows inserted.
async function processFile(filePath, mask) {
    const { batchId, nodeId } = spoolService.parseSpoolName(filePath);

    // Crash-recovery fast path: a crash between markProcessed and spool-file
    // removal leaves an already-processed batch behind. The ClickHouse dedup
    // token would make re-insertion harmless, but skipping avoids wasted work.
    if (batchId && await spoolService.isAlreadyProcessed(nodeId, batchId)) {
        await spoolService.removeSpoolFile(filePath);
        return 0;
    }

    let parsed;
    try {
        parsed = await parseSpoolFile(filePath, mask);
    } catch (e) {
        // Undecodable batch (corrupt gzip, etc): drop it so it cannot block the
        // queue. There is no structured content to salvage.
        logger.warn(`[AccessLogs] undecodable batch ${path.basename(filePath)}: ${e.message}`);
        await spoolService.removeSpoolFile(filePath);
        return 0;
    }

    if (parsed.rows.length > 0) {
        // A failure here (incl. ClickHouse unavailable) throws: we deliberately
        // let it propagate so the batch stays in the spool and is retried later,
        // rather than acking data we never persisted.
        await clickhouse.insertRaw(parsed.rows, batchId);
    }

    await spoolService.markProcessed(parsed.nodeId || nodeId, batchId);
    await spoolService.removeSpoolFile(filePath);
    return parsed.rows.length;
}

// Track a "storage unavailable" state so the drain loop can back off instead of
// hammering ClickHouse when it is unreachable.
let storageUnavailable = false;

async function drainOnce() {
    if (running) { kickPending = true; return { processed: 0, skipped: true }; }
    running = true;
    let processedFiles = 0;
    let totalEvents = 0;
    try {
        // Skip entirely when ClickHouse is not configured: keep batches spooled
        // (backpressure guards the disk) until an admin sets up the connection.
        if (!(await clickhouse.isConfigured())) {
            return { processed: 0, unconfigured: true };
        }

        const mask = await shouldMaskClientIp();
        const files = await spoolService.listSpool();
        const slice = files.slice(0, MAX_FILES_PER_RUN);
        for (const f of slice) {
            try {
                totalEvents += await processFile(f, mask);
                processedFiles++;
                storageUnavailable = false;
            } catch (e) {
                // Any insert error (connection refused, timeout, auth): stop this
                // run, keep everything spooled, log once. The timer retries later.
                if (!storageUnavailable) {
                    logger.warn(`[AccessLogs] ClickHouse unavailable, batches remain spooled: ${e.message}`);
                    storageUnavailable = true;
                }
                break;
            }
        }
        // Occasionally prune old dedup markers (at most once a day).
        if (Date.now() - lastMarkerPruneAt > 24 * 60 * 60 * 1000) {
            lastMarkerPruneAt = Date.now();
            spoolService.pruneProcessedMarkers(PROCESSED_MARKER_TTL_MS).catch(() => {});
        }
    } catch (e) {
        logger.error(`[AccessLogs] drain failed: ${e.message}`);
    } finally {
        running = false;
    }
    if (processedFiles > 0) {
        logger.info(`[AccessLogs] drained ${processedFiles} batch(es), ${totalEvents} event(s)`);
    }
    // If a kick arrived mid-drain, or there are more files than one run handled,
    // schedule an immediate follow-up.
    if (kickPending) {
        kickPending = false;
        setImmediate(() => { drainOnce().catch(() => {}); });
    }
    return { processed: processedFiles, events: totalEvents };
}

// Nudge the processor to run soon (debounced by the single-flight guard).
function kick() {
    setImmediate(() => { drainOnce().catch(() => {}); });
}

function start() {
    if (timer) return;
    timer = setInterval(() => { drainOnce().catch(() => {}); }, PROCESS_INTERVAL_MS);
    if (timer.unref) timer.unref();
    logger.info('[AccessLogs] spool processor started');
    drainOnce().catch(() => {});
}

function stop() {
    if (timer) { clearInterval(timer); timer = null; }
}

module.exports = {
    start,
    stop,
    kick,
    drainOnce,
    // exported for tests
    maskIp,
    maskRawLine,
    parseSpoolFile,
    processFile,
};
