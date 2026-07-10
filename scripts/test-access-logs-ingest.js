/**
 * End-to-end-ish test for the panel-side ingest spool + processor (no HTTP, no
 * DB, no Parquet binding). Verifies:
 *   - persistBatch writes an atomic sealed file and lists it,
 *   - the processor gunzips + parses NDJSON, buckets by date/node/hour,
 *   - quarantine of clock-skewed events,
 *   - processed marker + spool removal (idempotency).
 *
 * Uses a throwaway ACCESS_LOGS_DIR so it never touches real data.
 */

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');
const zlib = require('zlib');
const assert = require('assert');

// Point the pipeline at a temp dir BEFORE requiring modules that read it.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'al-ingest-'));
process.env.ACCESS_LOGS_DIR = TMP;

// No MongoDB in this test: disable mongoose op buffering so the best-effort
// rollup write fails fast instead of hanging for the default 10s timeout.
try { require('mongoose').set('bufferTimeoutMS', 1); } catch (_) { /* mongoose optional */ }

(async () => {
    const spoolService = require('../src/services/accessLogs/spoolService');
    const processService = require('../src/services/accessLogs/processService');
    const crypto = require('crypto');

    const nodeId = 'node123';

    // Build a gzipped NDJSON batch: one good recent line + one ancient (skew).
    const nowIso = new Date().toISOString();
    function xrayLine(d) {
        const y = d.getUTCFullYear();
        const mo = String(d.getUTCMonth() + 1).padStart(2, '0');
        const da = String(d.getUTCDate()).padStart(2, '0');
        const h = String(d.getUTCHours()).padStart(2, '0');
        const mi = String(d.getUTCMinutes()).padStart(2, '0');
        const s = String(d.getUTCSeconds()).padStart(2, '0');
        return `${y}/${mo}/${da} ${h}:${mi}:${s} 1.2.3.4:5555 accepted tcp:example.com:443 [vless-in -> direct] email: user@x`;
    }
    const recentLine = xrayLine(new Date());
    const ancientLine = xrayLine(new Date('2000-01-01T00:00:00Z'));

    const ndjson =
        JSON.stringify({ offset: 10, raw: recentLine, read_at: nowIso }) + '\n' +
        JSON.stringify({ offset: 20, raw: ancientLine, read_at: nowIso }) + '\n';
    const gz = zlib.gzipSync(Buffer.from(ndjson, 'utf8'));
    const batchId = crypto.createHash('sha256').update(gz).digest('hex');

    // Persist + verify it is listed.
    const { path: spoolPath } = await spoolService.persistBatch(nodeId, batchId, gz);
    assert.ok(fs.existsSync(spoolPath), 'spool file exists');
    let list = await spoolService.listSpool();
    assert.strictEqual(list.length, 1, 'one spooled batch');

    // Duplicate detection is false before processing.
    assert.strictEqual(await spoolService.isAlreadyProcessed(nodeId, batchId), false);

    // Drain. In this test env the DuckDB native binding is not exercised for
    // writing; if it is unavailable the batch must stay spooled (never acked
    // without a persisted write). If it IS available, the batch is fully
    // processed. Both outcomes are valid — assert the invariant accordingly.
    await processService.drainOnce();

    const duckAvailable = await require('../src/services/accessLogs/duckdbService').isAvailable();
    list = await spoolService.listSpool();
    if (duckAvailable) {
        assert.strictEqual(list.length, 0, 'spool drained when storage available');
        assert.strictEqual(await spoolService.isAlreadyProcessed(nodeId, batchId), true);
        // Parquet part file written for the recent event's partition.
        const parquetRoot = path.join(TMP, 'parquet');
        assert.ok(fs.existsSync(parquetRoot), 'parquet dir created');
    } else {
        assert.strictEqual(list.length, 1, 'batch stays spooled when storage unavailable');
        assert.strictEqual(await spoolService.isAlreadyProcessed(nodeId, batchId), false,
            'not marked processed without a persisted write');
    }

    // bucketEvents unit: recent -> 1 bucket, ancient -> quarantined.
    const { parseAccessLine } = require('../src/services/accessLogs/eventContract');
    const evGood = parseAccessLine(recentLine, { nodeId, offset: 1 });
    const evOld = parseAccessLine(ancientLine, { nodeId, offset: 2 });
    const { buckets, quarantined } = processService.bucketEvents([evGood, evOld], nodeId, Date.now());
    assert.strictEqual(buckets.size, 1, 'one partition bucket');
    assert.strictEqual(quarantined.length, 1, 'one quarantined');

    await fsp.rm(TMP, { recursive: true, force: true });
    console.log('test-access-logs-ingest: OK');
})().catch(async (e) => {
    console.error('test-access-logs-ingest FAILED:', e);
    try { await fsp.rm(TMP, { recursive: true, force: true }); } catch (_) {}
    process.exit(1);
});
