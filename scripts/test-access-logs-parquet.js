/**
 * Parquet write + DuckDB read round-trip test.
 *
 * Writes canonical events into the partitioned Parquet store via parquetWriter,
 * then reads them back through searchService (search + summary). Skips gracefully
 * if the DuckDB native binding is unavailable in this environment.
 *
 * Uses a throwaway ACCESS_LOGS_DIR.
 */

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');
const assert = require('assert');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'al-parquet-'));
process.env.ACCESS_LOGS_DIR = TMP;

(async () => {
    const duckdb = require('../src/services/accessLogs/duckdbService');
    if (!(await duckdb.isAvailable())) {
        console.log('test-access-logs-parquet: SKIPPED (duckdb unavailable)');
        await fsp.rm(TMP, { recursive: true, force: true });
        return;
    }

    const { parseAccessLine } = require('../src/services/accessLogs/eventContract');
    const parquetWriter = require('../src/services/accessLogs/parquetWriter');
    const searchService = require('../src/services/accessLogs/searchService');

    const nodeId = 'nodeABC';
    const base = new Date();
    base.setUTCMinutes(0, 0, 0);
    const dateStr = base.toISOString().slice(0, 10);
    const hour = base.getUTCHours();

    function line(ip, dest, email, action = 'accepted', net = 'tcp') {
        const y = base.getUTCFullYear();
        const mo = String(base.getUTCMonth() + 1).padStart(2, '0');
        const da = String(base.getUTCDate()).padStart(2, '0');
        const h = String(hour).padStart(2, '0');
        return `${y}/${mo}/${da} ${h}:05:00 ${ip}:1111 ${action} ${net}:${dest}:443 [vless-in -> direct] email: ${email}`;
    }

    const events = [
        parseAccessLine(line('1.1.1.1', 'a.example.com', 'alice@x'), { nodeId, offset: 1 }),
        parseAccessLine(line('1.1.1.1', 'a.example.com', 'alice@x'), { nodeId, offset: 2 }),
        parseAccessLine(line('2.2.2.2', 'b.example.com', 'bob@x', 'rejected'), { nodeId, offset: 3 }),
        parseAccessLine(line('3.3.3.3', 'a.example.com', 'alice@x', 'accepted', 'udp'), { nodeId, offset: 4 }),
    ];
    for (const e of events) assert.ok(e.parseOk, 'line parsed');

    const wr = await parquetWriter.appendPartition(dateStr, nodeId, hour, events);
    assert.ok(wr.ok, 'partition written');
    assert.ok(fs.existsSync(wr.path), 'part file exists');

    // Idempotency: same events -> dedup, no second file.
    const wr2 = await parquetWriter.appendPartition(dateStr, nodeId, hour, events);
    assert.ok(wr2.dedup, 'second identical write dedups');

    // Search: all events.
    const all = await searchService.search({}, { limit: 100 });
    assert.ok(!all.degraded, 'not degraded');
    assert.strictEqual(all.rows.length, 4, 'four events searchable');

    // Filter by email.
    const alice = await searchService.search({ email: 'alice@x' }, { limit: 100 });
    assert.strictEqual(alice.rows.length, 3, 'three alice events');

    // Filter by action.
    const rej = await searchService.search({ action: 'rejected' }, { limit: 100 });
    assert.strictEqual(rej.rows.length, 1, 'one rejected event');

    // Destination contains.
    const destA = await searchService.search({ destination: 'a.example' }, { limit: 100 });
    assert.strictEqual(destA.rows.length, 3, 'three events to a.example.com');

    // Summary aggregates.
    const sum = await searchService.summary({}, { topN: 5 });
    assert.strictEqual(Number(sum.totals.total), 4, 'summary total = 4');
    assert.ok(sum.topDestinations.length >= 1, 'has top destinations');
    const topDest = sum.topDestinations[0];
    assert.strictEqual(topDest.dest, 'a.example.com', 'top dest is a.example.com');
    assert.strictEqual(Number(topDest.hits), 3, 'a.example.com hit 3 times');

    await fsp.rm(TMP, { recursive: true, force: true });
    console.log('test-access-logs-parquet: OK');
})().catch(async (e) => {
    console.error('test-access-logs-parquet FAILED:', e);
    try { await fsp.rm(TMP, { recursive: true, force: true }); } catch (_) {}
    process.exit(1);
});
