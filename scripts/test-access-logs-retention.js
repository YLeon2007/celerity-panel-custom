/**
 * Retention service tests (no DB, no DuckDB).
 *
 * Verifies partition-name parsing and the two independent limits (age + size)
 * by seeding a temp Parquet tree with fake part files and stubbing Settings.get.
 */

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');
const assert = require('assert');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'al-retention-'));
process.env.ACCESS_LOGS_DIR = TMP;

// Stub the settings model BEFORE the retention service requires it.
const settingsStub = { accessLogs: { retentionDays: 7, maxStorageGb: 1 } };
const Module = require('module');
const origRequire = Module.prototype.require;
Module.prototype.require = function (id) {
    if (id.endsWith('settingsModel') || id.includes('models/settingsModel')) {
        return { get: async () => settingsStub };
    }
    return origRequire.apply(this, arguments);
};

(async () => {
    const retention = require('../src/services/accessLogs/retentionService');
    const paths = require('../src/services/accessLogs/paths');

    // parseDatePartition
    assert.deepStrictEqual(
        retention.parseDatePartition('date=2026-01-15').toISOString(),
        new Date(Date.UTC(2026, 0, 15)).toISOString()
    );
    assert.strictEqual(retention.parseDatePartition('node_id=x'), null);

    // Seed partitions: one old (should be dropped by age), two recent.
    function ymd(d) { return d.toISOString().slice(0, 10); }
    const now = new Date();
    const old = new Date(now.getTime() - 30 * 24 * 3600 * 1000);
    const recent1 = new Date(now.getTime() - 1 * 24 * 3600 * 1000);
    const recent2 = new Date(now.getTime() - 2 * 24 * 3600 * 1000);

    async function seed(d, bytes) {
        const dir = path.join(paths.PARQUET_DIR, `date=${ymd(d)}`, 'node_id=n', 'hour=00');
        await fsp.mkdir(dir, { recursive: true });
        await fsp.writeFile(path.join(dir, 'part-x.parquet'), Buffer.alloc(bytes, 1));
    }
    await seed(old, 1000);
    await seed(recent1, 700 * 1024 * 1024);   // 700 MB
    await seed(recent2, 700 * 1024 * 1024);   // 700 MB -> total 1.4GB > 1GB cap

    // Age retention drops `old`; size cap (1 GB) then drops the oldest remaining
    // (recent2) until under cap.
    const result = await retention.enforce();

    const remaining = await retention.listDatePartitions();
    const names = remaining.map(p => p.name);

    assert.ok(!names.includes(`date=${ymd(old)}`), 'old partition removed by age');
    assert.ok(names.includes(`date=${ymd(recent1)}`), 'newest partition kept');
    assert.ok(!names.includes(`date=${ymd(recent2)}`), 'oldest-of-recent removed by size cap');
    assert.ok(result.removed.some(r => r.reason === 'age'), 'age removal reported');
    assert.ok(result.removed.some(r => r.reason === 'size'), 'size removal reported');

    Module.prototype.require = origRequire;
    await fsp.rm(TMP, { recursive: true, force: true });
    console.log('test-access-logs-retention: OK');
})().catch(async (e) => {
    Module.prototype.require = origRequire;
    console.error('test-access-logs-retention FAILED:', e);
    try { await fsp.rm(TMP, { recursive: true, force: true }); } catch (_) {}
    process.exit(1);
});
