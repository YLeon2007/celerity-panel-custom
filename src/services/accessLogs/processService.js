/**
 * Spool processor: drains durably-spooled ingest batches into the analytical
 * store.
 *
 * For each sealed spool file it:
 *   1. gunzips + splits NDJSON into raw events,
 *   2. parses each line via the shared event contract,
 *   3. applies clock-skew quarantine (events too far from panel time are set
 *      aside instead of polluting partitions),
 *   4. hands parsed events to the Parquet writer, partitioned by (date, node, hour),
 *   5. marks the batch processed (idempotency) and removes the spool file.
 *
 * Runs on a timer and can be nudged via kick() right after an ingest so latency
 * stays low without a tight busy loop. A single-flight guard prevents concurrent
 * drains from racing on the same files.
 */

const zlib = require('zlib');
const { promisify } = require('util');
const fsp = require('fs/promises');
const path = require('path');

const logger = require('../../utils/logger');
const paths = require('./paths');
const spoolService = require('./spoolService');
const { parseAccessLine, maskEventSourceIp } = require('./eventContract');

const gunzip = promisify(zlib.gunzip);

// Decompression bomb guard: a batch body is capped at 8 MB compressed on
// ingest; refuse to inflate past this many bytes so a crafted batch cannot
// exhaust panel memory. Legit batches (~500 log lines) are far smaller.
const MAX_INFLATED_BYTES = 64 * 1024 * 1024; // 64 MB

// Events whose (node-local) timestamp differs from panel time by more than this
// are quarantined: likely severe clock skew or a bad parse. Keeps partitions
// bounded to a sane time window.
const MAX_CLOCK_SKEW_MS = 48 * 60 * 60 * 1000; // 48h

const PROCESS_INTERVAL_MS = 10 * 1000;
const MAX_FILES_PER_RUN = 50;

let running = false;
let timer = null;
let kickPending = false;

function utcDateStr(date) {
    return date.toISOString().slice(0, 10); // YYYY-MM-DD
}

// Split the canonical events of one batch into per-partition buckets keyed by
// "date|node|hour". Quarantined events are collected separately.
function bucketEvents(events, nodeId, now) {
    const buckets = new Map();
    const quarantined = [];
    for (const ev of events) {
        const ts = ev.timestamp instanceof Date ? ev.timestamp : null;
        if (!ts || Math.abs(now - ts.getTime()) > MAX_CLOCK_SKEW_MS) {
            quarantined.push(ev);
            continue;
        }
        const dateStr = utcDateStr(ts);
        const hour = ts.getUTCHours();
        const key = `${dateStr}|${nodeId}|${hour}`;
        if (!buckets.has(key)) {
            buckets.set(key, { dateStr, nodeId, hour, events: [] });
        }
        buckets.get(key).events.push(ev);
    }
    return { buckets, quarantined };
}

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

// Parse a single spool file into canonical events tagged with the node id.
// Throws on corrupt gzip OR on decompression past MAX_INFLATED_BYTES (both are
// treated as an undecodable batch and quarantined by the caller).
async function parseSpoolFile(filePath) {
    const { nodeId } = spoolService.parseSpoolName(filePath);
    const gz = await fsp.readFile(filePath);
    const ndjson = (await gunzip(gz, { maxOutputLength: MAX_INFLATED_BYTES })).toString('utf8');

    // Privacy: when enabled, client IPs are masked BEFORE anything is persisted
    // (Parquet, rollups, quarantine) so the exact address never hits disk.
    const mask = await shouldMaskClientIp();

    const events = [];
    for (const line of ndjson.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        let rec;
        try {
            rec = JSON.parse(trimmed);
        } catch (_) {
            continue; // skip malformed NDJSON record
        }
        let ev = parseAccessLine(rec.raw, { nodeId, offset: rec.offset });
        if (mask) ev = maskEventSourceIp(ev);
        events.push(ev);
    }
    return { nodeId, events };
}

async function quarantineEvents(nodeId, events) {
    if (!events.length) return;
    try {
        await fsp.mkdir(paths.QUARANTINE_DIR, { recursive: true });
        const name = `${Date.now()}-${nodeId}-${events.length}.jsonl`;
        const body = events.map(e => JSON.stringify(e)).join('\n') + '\n';
        await fsp.writeFile(path.join(paths.QUARANTINE_DIR, name), body);
    } catch (e) {
        logger.warn(`[AccessLogs] quarantine write failed: ${e.message}`);
    }
}

// Process a single spool file end-to-end. Returns the number of events written.
async function processFile(filePath) {
    const { batchId, nodeId } = spoolService.parseSpoolName(filePath);
    const now = Date.now();

    // Crash-recovery fast path: a crash between markProcessed and spool-file
    // removal leaves an already-processed batch behind. Parquet part-name dedup
    // would make re-processing harmless, but skipping it avoids the wasted
    // gunzip + parse work.
    if (batchId && await spoolService.isAlreadyProcessed(nodeId, batchId)) {
        await spoolService.removeSpoolFile(filePath);
        return 0;
    }

    let parsed;
    try {
        parsed = await parseSpoolFile(filePath);
    } catch (e) {
        // Undecodable batch (corrupt gzip, etc): quarantine the raw file so it
        // does not block the queue.
        logger.warn(`[AccessLogs] undecodable batch ${path.basename(filePath)}: ${e.message}`);
        try {
            await fsp.mkdir(paths.QUARANTINE_DIR, { recursive: true });
            await fsp.rename(filePath, path.join(paths.QUARANTINE_DIR, path.basename(filePath)));
        } catch (_) { await spoolService.removeSpoolFile(filePath); }
        return 0;
    }

    const { buckets, quarantined } = bucketEvents(parsed.events, parsed.nodeId || nodeId, now);

    let written = 0;
    const parquetWriter = require('./parquetWriter');
    const rollupService = require('./rollupService');
    for (const { dateStr, nodeId: nid, hour, events } of buckets.values()) {
        if (!events.length) continue;
        // A write failure (incl. duckdb_unavailable) throws: we deliberately let
        // it propagate so the batch stays in the spool and is retried later,
        // rather than acking data we never persisted.
        const wr = await parquetWriter.appendPartition(dateStr, nid, hour, events);
        // Fold into Mongo rollups only when this call actually wrote a new part
        // (not a dedup hit), so rollups are not double-counted on re-processing.
        if (!wr.dedup) {
            await rollupService.foldPartition(dateStr, nid, hour, events);
        }
        written += events.length;
    }

    // Only quarantine skewed events and mark processed AFTER a successful write,
    // so a retry re-runs the whole batch consistently.
    await quarantineEvents(parsed.nodeId || nodeId, quarantined);
    await spoolService.markProcessed(parsed.nodeId || nodeId, batchId);
    await spoolService.removeSpoolFile(filePath);
    return written;
}

// Track a "storage unavailable" state so the drain loop can back off instead of
// hammering DuckDB when the native binding is missing.
let storageUnavailable = false;

async function drainOnce() {
    if (running) { kickPending = true; return { processed: 0, skipped: true }; }
    running = true;
    let processedFiles = 0;
    let totalEvents = 0;
    try {
        const files = await spoolService.listSpool();
        const slice = files.slice(0, MAX_FILES_PER_RUN);
        for (const f of slice) {
            try {
                totalEvents += await processFile(f);
                processedFiles++;
                storageUnavailable = false;
            } catch (e) {
                if (String(e.message).includes('duckdb_unavailable')) {
                    // Persistent storage is down: stop this run, keep everything
                    // spooled, and log once. The interval timer will retry later.
                    if (!storageUnavailable) {
                        logger.warn('[AccessLogs] Parquet storage unavailable (DuckDB); batches remain spooled until it recovers');
                        storageUnavailable = true;
                    }
                    break;
                }
                logger.error(`[AccessLogs] processFile ${path.basename(f)} failed: ${e.message}`);
            }
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
    MAX_CLOCK_SKEW_MS,
    start,
    stop,
    kick,
    drainOnce,
    // exported for tests
    bucketEvents,
    parseSpoolFile,
    processFile,
};
