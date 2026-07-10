/**
 * Tests for the ClickHouse access-logs layer.
 *
 * Two parts:
 *   1. Offline (always runs): the schema DDL is well-formed and honors the
 *      retention value, and the CH_LINE_RE regex parses representative Xray
 *      access lines into the same fields the materialized view derives. The
 *      regex is RE2-flavored but also valid JS, so we exercise it directly.
 *   2. Online (only when CLICKHOUSE_TEST_URL is set): a real end-to-end check —
 *      ensure schema, insert raw rows, and read them back parsed. Skipped
 *      otherwise so CI without a ClickHouse stays green.
 */

const assert = require('assert');

// Point at a temp dir so requiring settings-backed modules is harmless.
const os = require('os');
const path = require('path');
const fs = require('fs');
process.env.ACCESS_LOGS_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'al-ch-'));

const clickhouse = require('../src/services/accessLogs/clickhouseService');

// Reproduce the materialized-view parse in JS from the shared regex, so we can
// assert the field extraction without a live server.
function parseLikeMv(raw) {
    const re = new RegExp(clickhouse.CH_LINE_RE);
    const m = re.exec(raw);
    if (!m) return { parse_ok: 0 };
    const src = (m[2] || '').replace(/^from /, '');
    const dst = m[5] || '';
    const route = m[6] || '';
    const splitRight = (s) => {
        const mm = /^(.*):(\d+)$/.exec(s);
        return mm ? { host: mm[1], port: Number(mm[2]) } : { host: s, port: 0 };
    };
    const sp = splitRight(src);
    const dp = splitRight(dst);
    const dstIsIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(dp.host) || dp.host.includes(':');
    const parts = route.split('->');
    return {
        parse_ok: 1,
        event_time: (m[1] || '').replace(/\//g, '-'),
        source_ip: sp.host,
        source_port: sp.port,
        dest_host: dstIsIp ? '' : dp.host,
        dest_ip: dstIsIp ? dp.host : '',
        dest_port: dp.port,
        network: m[4] || '',
        action: m[3] || '',
        inbound_tag: (parts[0] || '').trim(),
        outbound_tag: (parts[1] || '').trim(),
        email: m[7] || '',
    };
}

async function offlineTests() {
    // Schema DDL: three statements, retention inlined, tables named as expected.
    const ddl = clickhouse.schemaStatements(45);
    assert.strictEqual(ddl.length, 3, 'three schema statements');
    assert.ok(ddl[0].includes('access_ingest') && ddl[0].includes('ENGINE = Null'), 'ingest is Null engine');
    assert.ok(ddl[1].includes('access_events') && ddl[1].includes('MergeTree'), 'events is MergeTree');
    assert.ok(ddl[1].includes('INTERVAL 45 DAY'), 'retention honored');
    assert.ok(ddl[1].includes("DateTime('UTC')"), 'event_time pinned to UTC');
    assert.ok(ddl[2].includes('MATERIALIZED VIEW') && ddl[2].includes('access_events_mv'), 'mv defined');

    // The regex is inlined into a ClickHouse string literal, where a lone
    // backslash is an escape character: every backslash must arrive doubled or
    // the character classes ("\d", "\S") silently degrade to plain letters.
    const mvDdl = ddl[2];
    assert.ok(mvDdl.includes('\\\\d{4}/\\\\d{2}/\\\\d{2}'), 'regex backslashes doubled for SQL literal');
    assert.ok(!/[^\\]\\d\{4\}/.test(mvDdl), 'no single-backslash \\d leaked into the DDL');
    // Timestamp normalization must replace EVERY slash, not just the first.
    assert.ok(mvDdl.includes('replaceAll(ts_str'), 'date slashes replaced with replaceAll');
    // Unparsed lines must not land in 1970 (instantly TTL-dropped).
    assert.ok(mvDdl.includes("now('UTC')"), 'zero timestamps fall back to now()');

    // Retention clamps to sane bounds (0/NaN falls back to the 30-day default).
    assert.ok(clickhouse.schemaStatements(-5)[1].includes('INTERVAL 1 DAY'), 'retention floor');
    assert.ok(clickhouse.schemaStatements(99999)[1].includes('INTERVAL 3650 DAY'), 'retention ceiling');
    assert.ok(clickhouse.schemaStatements(0)[1].includes('INTERVAL 30 DAY'), 'retention default on 0');

    // Regex parse: a typical accepted TCP line with host destination + email.
    const a = parseLikeMv('2023/11/22 17:01:32 1.2.3.4:1122 accepted tcp:example.com:443 [vless-in -> direct] email: 42');
    assert.strictEqual(a.parse_ok, 1, 'line A parsed');
    assert.strictEqual(a.event_time, '2023-11-22 17:01:32', 'ts normalized');
    assert.strictEqual(a.source_ip, '1.2.3.4');
    assert.strictEqual(a.source_port, 1122);
    assert.strictEqual(a.dest_host, 'example.com');
    assert.strictEqual(a.dest_ip, '');
    assert.strictEqual(a.dest_port, 443);
    assert.strictEqual(a.network, 'tcp');
    assert.strictEqual(a.action, 'accepted');
    assert.strictEqual(a.inbound_tag, 'vless-in');
    assert.strictEqual(a.outbound_tag, 'direct');
    assert.strictEqual(a.email, '42');

    // UDP line to an IP destination, "from " prefix, fractional seconds.
    const b = parseLikeMv('2024/05/01 08:12:00.123456 from 9.9.9.9:5555 accepted udp:8.8.8.8:53 [in -> out] email: user@x');
    assert.strictEqual(b.parse_ok, 1, 'line B parsed');
    assert.strictEqual(b.source_ip, '9.9.9.9');
    assert.strictEqual(b.dest_ip, '8.8.8.8', 'ip destination goes to dest_ip');
    assert.strictEqual(b.dest_host, '', 'no host for ip destination');
    assert.strictEqual(b.dest_port, 53);
    assert.strictEqual(b.network, 'udp');
    assert.strictEqual(b.email, 'user@x');

    // Blocked line without email/route still parses.
    const c = parseLikeMv('2024/05/01 08:12:00 5.5.5.5:1000 blocked tcp:ads.example.net:80');
    assert.strictEqual(c.parse_ok, 1, 'line C parsed');
    assert.strictEqual(c.action, 'blocked');
    assert.strictEqual(c.email, '', 'no email');

    // Garbage line does not match.
    const d = parseLikeMv('this is not an xray line');
    assert.strictEqual(d.parse_ok, 0, 'garbage rejected');

    console.log('  offline: schema + regex OK');
}

async function onlineTests() {
    const url = process.env.CLICKHOUSE_TEST_URL;
    if (!url) {
        console.log('  online: skipped (set CLICKHOUSE_TEST_URL to run)');
        return;
    }
    // Configure the service via an in-memory settings stub.
    const u = new URL(url);
    const Settings = require('../src/models/settingsModel');
    Settings.get = async () => ({
        accessLogs: {
            retentionDays: 7,
            clickhouse: {
                host: u.hostname,
                port: Number(u.port) || 8123,
                database: u.pathname.replace(/^\//, '') || 'default',
                username: decodeURIComponent(u.username) || 'default',
                passwordEncrypted: '',
                secure: u.protocol === 'https:',
            },
        },
    });
    // Password comes plain from the URL for the test.
    const orig = clickhouse.readConfig;
    clickhouse.reset();

    const ping = await clickhouse.ping();
    assert.ok(ping.ok, `ping ok: ${ping.error || ''}`);

    await clickhouse.ensureSchema(7);

    const batchId = 'test-batch-' + Date.now();
    await clickhouse.insertRaw([
        { node_id: 'n1', raw: '2023/11/22 17:01:32 1.2.3.4:1122 accepted tcp:example.com:443 [vless-in -> direct] email: 42' },
    ], batchId);

    // Give the MV a moment (insert is synchronous, but read is eventually there).
    const res = await clickhouse.query("SELECT email, network, dest_host FROM access_events WHERE email = '42' LIMIT 1");
    assert.ok(res.ok, `read ok: ${res.error || ''}`);
    assert.ok(res.rows.length >= 1, 'row present after MV parse');
    assert.strictEqual(res.rows[0].network, 'tcp');
    assert.strictEqual(res.rows[0].dest_host, 'example.com');

    await clickhouse.truncate();
    void orig;
    console.log('  online: end-to-end OK');
}

(async () => {
    await offlineTests();
    await onlineTests();
    console.log('test-access-logs-clickhouse: OK');
    process.exit(0);
})().catch((e) => {
    console.error('test-access-logs-clickhouse FAILED:', e);
    process.exit(1);
});
