/**
 * Retention & storage-cap enforcement for the Parquet store.
 *
 * Two independent limits, both configured in settings.accessLogs:
 *   - retentionDays:  drop whole date= partitions older than the cutoff.
 *   - maxStorageGb:   when the store exceeds the cap, drop oldest date=
 *                     partitions until under the cap.
 *
 * Also prunes the ingest "processed" dedup markers and old quarantine files so
 * those directories stay bounded. Runs on a daily cron; safe to run repeatedly.
 */

const fsp = require('fs/promises');
const path = require('path');
const paths = require('./paths');
const spoolService = require('./spoolService');
const logger = require('../../utils/logger');

// Parse "date=YYYY-MM-DD" -> Date (UTC midnight) or null.
function parseDatePartition(name) {
    const m = /^date=(\d{4})-(\d{2})-(\d{2})$/.exec(name);
    if (!m) return null;
    const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
    return isNaN(d.getTime()) ? null : d;
}

async function listDatePartitions() {
    let entries;
    try {
        entries = await fsp.readdir(paths.PARQUET_DIR, { withFileTypes: true });
    } catch (e) {
        if (e.code === 'ENOENT') return [];
        throw e;
    }
    const parts = [];
    for (const e of entries) {
        if (!e.isDirectory()) continue;
        const date = parseDatePartition(e.name);
        if (!date) continue;
        parts.push({ name: e.name, date, dir: path.join(paths.PARQUET_DIR, e.name) });
    }
    parts.sort((a, b) => a.date - b.date); // oldest first
    return parts;
}

// Recursively sum file sizes under a directory.
async function dirSize(dir) {
    let total = 0;
    let entries;
    try { entries = await fsp.readdir(dir, { withFileTypes: true }); }
    catch (_) { return 0; }
    for (const e of entries) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) total += await dirSize(p);
        else {
            try { total += (await fsp.stat(p)).size; } catch (_) { /* ignore */ }
        }
    }
    return total;
}

async function removeDir(dir) {
    try {
        await fsp.rm(dir, { recursive: true, force: true });
        return true;
    } catch (e) {
        logger.warn(`[AccessLogs] retention: failed to remove ${dir}: ${e.message}`);
        return false;
    }
}

/**
 * Enforce both limits. Returns a summary of what was removed.
 */
async function enforce() {
    const Settings = require('../../models/settingsModel');
    const settings = await Settings.get();
    const al = settings?.accessLogs || {};
    const retentionDays = Math.max(1, Number(al.retentionDays) || 14);
    const maxBytes = Math.max(1, Number(al.maxStorageGb) || 10) * 1024 * 1024 * 1024;

    const removed = [];
    let parts = await listDatePartitions();

    // 1) Age-based retention.
    const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
    cutoff.setUTCHours(0, 0, 0, 0);
    for (const p of parts) {
        if (p.date < cutoff) {
            if (await removeDir(p.dir)) removed.push({ partition: p.name, reason: 'age' });
        }
    }

    // 2) Size-cap retention: recompute remaining partitions and drop oldest
    // until under the cap.
    parts = await listDatePartitions();
    const sized = [];
    let total = 0;
    for (const p of parts) {
        const size = await dirSize(p.dir);
        sized.push({ ...p, size });
        total += size;
    }
    for (const p of sized) {
        if (total <= maxBytes) break;
        if (await removeDir(p.dir)) {
            total -= p.size;
            removed.push({ partition: p.name, reason: 'size' });
        }
    }

    // 3) Prune dedup markers + quarantine older than retention window.
    await pruneOlderThan(spoolService.PROCESSED_DIR, retentionDays);
    await pruneOlderThan(paths.QUARANTINE_DIR, retentionDays);

    // 4) Orphaned upload temp files: a crash between write and rename leaves
    // a .tmp behind forever (the processor only sees sealed *.ndjson.gz in the
    // spool root). Anything older than a day here is garbage by definition.
    await pruneOlderThan(paths.INCOMING_TMP_DIR, 1);

    if (removed.length) {
        logger.info(`[AccessLogs] retention removed ${removed.length} partition(s)`);
    }
    return { removed, totalBytes: total };
}

// Delete files in a directory whose mtime is older than `days`.
async function pruneOlderThan(dir, days) {
    const cutoffMs = Date.now() - days * 24 * 60 * 60 * 1000;
    let entries;
    try { entries = await fsp.readdir(dir, { withFileTypes: true }); }
    catch (_) { return; }
    for (const e of entries) {
        if (!e.isFile()) continue;
        const p = path.join(dir, e.name);
        try {
            const st = await fsp.stat(p);
            if (st.mtimeMs < cutoffMs) await fsp.unlink(p);
        } catch (_) { /* ignore */ }
    }
}

module.exports = {
    enforce,
    listDatePartitions,
    dirSize,
    parseDatePartition,
};
