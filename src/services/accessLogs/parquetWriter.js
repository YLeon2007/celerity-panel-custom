/**
 * Parquet writer for the access-logs pipeline.
 *
 * Appends a set of canonical events to the Hive-partitioned Parquet store by
 * writing ONE immutable part file per call into
 *   parquet/date=YYYY-MM-DD/node_id=<id>/hour=HH/part-<hash>.parquet
 *
 * We never mutate existing part files (append-only, immutable). Many small part
 * files per partition are fine for DuckDB, which globs them at query time. The
 * part name is a content hash so re-processing the same batch is idempotent
 * (identical events -> identical file name -> overwrite, no duplication).
 *
 * Writing goes through a DuckDB child process (parquetWriteWorker) to isolate
 * the native binding and cap memory. If DuckDB is unavailable, appendPartition
 * throws so the caller (processService) leaves the batch in the spool for a
 * later retry rather than silently dropping data.
 */

const fs = require('fs');
const fsp = require('fs/promises');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { fork } = require('child_process');

const logger = require('../../utils/logger');
const paths = require('./paths');

const WRITE_WORKER_PATH = path.join(__dirname, 'parquetWriteWorker.js');
const WRITE_TIMEOUT_MS = 60 * 1000;

// Serialize an event for the worker's read_json: ISO-8601 UTC timestamp, nulls
// preserved. Keys match eventContract field names (the worker CASTs/renames).
function serializeEvent(ev) {
    return {
        eventId: ev.eventId || '',
        timestamp: ev.timestamp instanceof Date ? ev.timestamp.toISOString() : null,
        nodeId: ev.nodeId || '',
        email: ev.email || '',
        sourceIp: ev.sourceIp || '',
        sourcePort: ev.sourcePort == null ? null : ev.sourcePort,
        destinationHost: ev.destinationHost || '',
        destinationIp: ev.destinationIp || '',
        destinationPort: ev.destinationPort == null ? null : ev.destinationPort,
        network: ev.network || '',
        inboundTag: ev.inboundTag || '',
        outboundTag: ev.outboundTag || '',
        action: ev.action || '',
        raw: ev.raw || '',
        parseOk: !!ev.parseOk,
        parserVersion: ev.parserVersion || 0,
    };
}

// Deterministic part-file name from the event ids in this write, so identical
// re-processing produces the same file (idempotent) and distinct writes differ.
function partName(events) {
    const h = crypto.createHash('sha256');
    for (const e of events) h.update(e.eventId || '').update('\x00');
    return `part-${h.digest('hex').slice(0, 24)}.parquet`;
}

function runWriteWorker(job) {
    return new Promise((resolve) => {
        const payload = Buffer.from(JSON.stringify(job), 'utf8').toString('base64');
        const child = fork(WRITE_WORKER_PATH, [payload], {
            stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
        });
        let out = '';
        let err = '';
        let settled = false;
        const timer = setTimeout(() => {
            if (settled) return;
            settled = true;
            try { child.kill('SIGKILL'); } catch (_) {}
            resolve({ ok: false, error: 'timeout' });
        }, WRITE_TIMEOUT_MS);
        if (child.stdout) child.stdout.on('data', d => { out += d.toString(); });
        if (child.stderr) child.stderr.on('data', d => { err += d.toString(); });
        child.on('error', (e) => {
            if (settled) return;
            settled = true; clearTimeout(timer);
            resolve({ ok: false, error: String(e && e.message || e) });
        });
        child.on('exit', () => {
            if (settled) return;
            settled = true; clearTimeout(timer);
            try { resolve(JSON.parse(out)); }
            catch (_) { resolve({ ok: false, error: err ? err.slice(0, 500) : 'no output' }); }
        });
    });
}

/**
 * Append events to a single partition. Immutable: writes one new part file.
 *
 * @param {string} dateStr  YYYY-MM-DD (UTC)
 * @param {string} nodeId
 * @param {number} hour     0-23 (UTC)
 * @param {Array}  events   canonical events (all belonging to this partition)
 */
async function appendPartition(dateStr, nodeId, hour, events) {
    if (!events || events.length === 0) return { ok: true, rows: 0 };

    const partitionDir = paths.parquetPartitionDir(dateStr, nodeId, hour);
    await fsp.mkdir(partitionDir, { recursive: true });

    const name = partName(events);
    const finalPath = path.join(partitionDir, name);

    // Idempotency: if this exact part already exists, treat as done.
    try {
        await fsp.access(finalPath);
        return { ok: true, rows: events.length, dedup: true };
    } catch (_) { /* not present, proceed */ }

    // Serialize events to a temp JSON file for the worker.
    const tmpEvents = path.join(os.tmpdir(), `al-events-${crypto.randomBytes(8).toString('hex')}.json`);
    const tmpOut = finalPath + '.tmp';
    try {
        await fsp.writeFile(tmpEvents, JSON.stringify(events.map(serializeEvent)));

        const res = await runWriteWorker({
            eventsFile: tmpEvents,
            outFile: tmpOut,
            threads: 1,
            memoryLimitMb: 256,
        });

        if (!res.ok) {
            // Clean up any partial output and surface the error so the caller
            // keeps the batch in the spool for retry.
            try { if (fs.existsSync(tmpOut)) await fsp.unlink(tmpOut); } catch (_) {}
            const msg = res.error === 'duckdb_unavailable'
                ? 'duckdb_unavailable'
                : (res.error || 'parquet write failed');
            throw new Error(msg);
        }

        // Atomic publish into the partition.
        await fsp.rename(tmpOut, finalPath);
        return { ok: true, rows: res.rows || events.length, path: finalPath };
    } finally {
        try { await fsp.unlink(tmpEvents); } catch (_) {}
    }
}

module.exports = {
    appendPartition,
    serializeEvent,
    partName,
    WRITE_WORKER_PATH,
};
