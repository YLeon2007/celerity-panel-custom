'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { test } = require('node:test');

const MARKER = Buffer.from('abcdef4d61784d696e642e636f6d', 'hex');
const NONE = { country: null, region: null, city: null, asn: null, isp: null };
const US = { country: { iso_code: 'US' }, subdivisions: [{ names: { en: 'California' } }],
    city: { names: { en: 'Fixture City', ru: 'Тестовый город', 'zh-CN': '测试市' } } };
const ASN = { autonomous_system_number: 64512, autonomous_system_organization: 'Fixture Network' };
const US_EN = { ...NONE, country: 'US', region: 'California', city: 'Fixture City' };
const ASN_OUT = { ...NONE, asn: 64512, isp: 'Fixture Network' };
const SERVICE = '../src/services/geoIpService';

function encode(value) {
    if (Buffer.isBuffer(value)) return value; // Already encoded test value.
    if (typeof value === 'string') {
        const bytes = Buffer.from(value);
        const n = bytes.length;
        const header = n < 29 ? [0x40 + n] : n < 285 ? [0x5d, n - 29] : [0x5e, (n - 285) >> 8, (n - 285) & 255];
        return Buffer.concat([Buffer.from(header), bytes]);
    }
    if (typeof value === 'number') {
        const bytes = Buffer.alloc(5);
        bytes[0] = 0xc4; // uint32
        bytes.writeUInt32BE(value, 1);
        return bytes;
    }
    if (Array.isArray(value)) return Buffer.concat([Buffer.from([value.length, 4]), ...value.map(encode)]);
    const entries = Object.entries(value);
    return Buffer.concat([Buffer.from([0xe0 + entries.length]), ...entries.flatMap(pair => pair.map(encode))]);
}

function mmdb(rows, { width = 24, ipVersion = 4, metadata = {}, dataPrefix = Buffer.alloc(0), separator = Buffer.alloc(16) } = {}) {
    // Fixture writer: rows are [prefix bits, record]. Allocate the internal nodes first.
    const nodes = [[null, null]];
    const data = [dataPrefix];
    let offset = dataPrefix.length;
    for (const [prefix, value] of rows) {
        let index = 0;
        for (const [i, bit] of [...prefix].entries()) {
            const branch = Number(bit);
            if (i === prefix.length - 1) {
                const record = encode(value);
                nodes[index][branch] = { offset };
                offset += record.length;
                data.push(record);
            } else {
                nodes[index][branch] ??= nodes.push([null, null]) - 1;
                index = nodes[index][branch];
            }
        }
    }
    const tree = nodes.map(node => {
        const records = node.map(v => v === null ? nodes.length : typeof v === 'number' ? v : nodes.length + 16 + v.offset);
        const bits = records.map(v => v.toString(2).padStart(width, '0'));
        const bytes = width === 28 ? bits[0].slice(4) + bits[0].slice(0, 4) + bits[1] : bits.join('');
        return Buffer.from(bytes.match(/.{8}/g).map(byte => parseInt(byte, 2)));
    });
    return Buffer.concat([...tree, separator, ...data, MARKER, encode({
        binary_format_major_version: 2, binary_format_minor_version: 0, ip_version: ipVersion,
        node_count: nodes.length, record_size: width, database_type: 'GeoIP-Fixture',
        build_epoch: 1, description: { en: 'test fixture' }, languages: ['en', 'ru'], ...metadata
    })]);
}

function useService(t, paths) {
    const id = require.resolve(SERVICE);
    for (const [name, value] of Object.entries({ GEOIP_CITY_DB: paths.city, GEOIP_ASN_DB: paths.asn })) {
        const previous = process.env[name];
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
        t.after(() => {
            if (previous === undefined) delete process.env[name];
            else process.env[name] = previous;
        });
    }
    delete require.cache[id];
    t.after(() => { delete require.cache[id]; });
    return require(SERVICE);
}

async function fixtures(t) {
    const dir = await fs.mkdtemp(path.join(__dirname, '.geoip-'));
    t.after(() => fs.rm(dir, { recursive: true, force: true }));
    let now = 0;
    t.mock.method(performance, 'now', () => now);
    return { city: path.join(dir, 'city.mmdb'), asn: path.join(dir, 'asn.mmdb'),
        advance() { now += 1001; } };
}

function ioCounts(t) {
    const stat = fs.stat;
    const open = fs.open;
    const counts = { stats: 0, opens: 0, reads: 0 };
    t.mock.method(fs, 'stat', (...args) => {
        counts.stats++;
        return stat(...args);
    });
    t.mock.method(fs, 'open', async (...args) => {
        counts.opens++;
        const file = await open(...args);
        const read = file.read.bind(file);
        file.read = (...readArgs) => {
            counts.reads++;
            return read(...readArgs);
        };
        return file;
    });
    return counts;
}

test('lazy defaults, invalid inputs and missing files return a silent all-null result', async t => {
    const paths = [];
    t.mock.method(fs, 'stat', async file => { paths.push(file); throw new Error('fixture path failure'); });
    const consoleCalls = ['log', 'info', 'debug', 'warn', 'error'].map(name => t.mock.method(console, name, () => {}));
    const { lookup } = useService(t, {});
    assert.deepEqual(paths, []);
    for (const ip of [null, {}, 'x'.repeat(10000), '01.2.3.4', '1.2.3.4:53', '1::2::3', '[::1]', 'fe80::1%eth0']) {
        assert.deepEqual(await lookup(ip, 'ru'), NONE);
    }
    assert.deepEqual(paths, []);
    const result = lookup('192.0.2.1', 'ru');
    assert.ok(result instanceof Promise);
    assert.deepEqual(await result, NONE);
    assert.deepEqual(paths.sort(), ['/app/data/geoip/asn.mmdb', '/app/data/geoip/city.mmdb']);
    for (const method of consoleCalls) assert.equal(method.mock.callCount(), 0);
});

test('IPv4, mapped IPv6 and native IPv6, including dotted tails, use the correct tree', async t => {
    const files = await fixtures(t);
    const nativeBits = [...Buffer.from('800000000000000000000000c0000201', 'hex')]
        .map(byte => byte.toString(2).padStart(8, '0')).join('');
    await fs.writeFile(files.city, mmdb([['0'.repeat(96) + '0', US], [nativeBits, { country: { iso_code: 'AU' } }]],
        { width: 28, ipVersion: 6 }));
    await fs.writeFile(files.asn, mmdb([['0', ASN]], { width: 32 }));
    const { lookup } = useService(t, files);
    const en = { ...US_EN, asn: 64512, isp: 'Fixture Network' };
    for (const ip of ['8.8.8.8', '::ffff:8.8.8.8', '0:0:0:0:0:FFFF:0808:0808']) {
        assert.deepEqual(await lookup(ip, 'en'), en);
    }
    assert.deepEqual(await lookup('::8.8.8.8'), US_EN); // ::/96 in an IPv6 MMDB, but not an IPv4-mapped address.
    assert.deepEqual(await lookup('8.8.8.8', 'RU_ru'), { ...en, city: 'Тестовый город' });
    assert.deepEqual(await lookup('8.8.8.8', 'zh-CN'), { ...en, city: '测试市' });
    assert.deepEqual(await lookup('8.8.8.8', 'ruin'), en);
    for (const ip of ['8000::192.0.2.1', '8000:0:0:0:0:0:C000:201']) {
        assert.deepEqual(await lookup(ip), { ...NONE, country: 'AU' });
    }
    assert.deepEqual(await lookup('8000::192.0.2.2'), NONE);
    assert.deepEqual(await lookup('2001:db8::1'), NONE);
});

test('decodes data pointers of all four widths relative to the data section', async t => {
    const files = await fixtures(t);
    const placements = [0, 2048, 526336, 600000];
    const pointers = [[0x20, 0], [0x28, 0, 0], [0x30, 0, 0, 0], [0x38, 0, 9, 39, 192]];
    const prefix = Buffer.alloc(600010);
    for (let i = 0; i < placements.length; i++) encode(`P${i}`).copy(prefix, placements[i]);
    const rows = ['00', '01', '10', '11'].map((bits, i) => [bits, { city: { names: { en: Buffer.from(pointers[i]) } } }]);
    await fs.writeFile(files.city, mmdb(rows, { dataPrefix: prefix }));
    const { lookup } = useService(t, files);
    for (const [i, octet] of [0, 64, 128, 192].entries()) {
        assert.deepEqual(await lookup(`${octet}.0.2.1`, 'ru'), { ...NONE, city: `P${i}` });
    }
});

test('corrupt headers, trees and records are contained without hiding the healthy database', async t => {
    const files = await fixtures(t);
    await fs.writeFile(files.asn, mmdb([['1', ASN]]));
    const { lookup } = useService(t, files);
    const hit = mmdb([['1', US]]);
    const withNode = node => { const b = Buffer.from(hit); b.writeUIntBE(node, 3, 3); return b; };
    const data = value => mmdb([['1', Buffer.from(value)]]);
    // Keep a valid country beside the broken field: ignoring corruption would leak a partial record.
    const extra = value => mmdb([['1', { ...US, extra: Buffer.from(value) }]]);
    const cycle = mmdb([['0', US]]);
    cycle.writeUIntBE(0, 3, 3); // A '10…' walk loops to root, then would take the valid left edge.
    const pad = Buffer.alloc(128 * 1024, 0x73);
    for (const [why, invalid] of [
        ['no marker', Buffer.from('not an MMDB')],
        ['marker too far from the end', Buffer.concat([hit, pad])],
        ['truncated metadata', hit.subarray(0, -1)],
        ['bad version', mmdb([['1', US]], { metadata: { binary_format_major_version: 3 } })],
        ['oversized node count', mmdb([['1', US]], { metadata: { node_count: 0xffffff } })],
        ['invalid separator', mmdb([['1', US]], { separator: Buffer.alloc(16, 1) })],
        ['empty tree edge', withNode(1)],
        ['reserved tree edge', withNode(16)],
        ['tree edge outside data', withNode(0xffffff)],
        ['tree cycle with a reachable exit', cycle],
        ['self-pointer', data([0x20, 0])],
        ['pointer back to ancestor map', data([0xe1, 0x41, 0x78, 0x20, 0])],
        ['pointer into metadata', data([0x20, 2])],
        ['truncated string', data([0xe1, 0x41, 0x78, 0x4f, 0x30])],
        ['invalid UTF-8', extra([0x41, 0xff])],
        ['overdeep array', extra([...Array.from({ length: 80 }, () => [1, 4]).flat(), 0x40])],
        ['overwide array', extra(Buffer.concat([Buffer.from([30, 4, 8, 167]), Buffer.alloc(2500, 0x40)]))],
        ['pointer to pointer', mmdb([['1', { ...US, extra: Buffer.from([0x20, 0]) }]],
            { dataPrefix: Buffer.from([0x20, 2, 0x40]) })],
        ['repeated pointer targets exhaust the payload budget', mmdb([['1', {
            ...US, extra: Array.from({ length: 3 }, () => Buffer.from([0x20, 0]))
        }]], { dataPrefix: encode('s'.repeat(45000)) })],
    ]) {
        await fs.writeFile(files.city, invalid);
        files.advance();
        assert.deepEqual(await lookup('128.0.2.1', 'ru'), ASN_OUT, why);
    }
    // An erroneous branch must not invalidate a valid sibling branch in the same file.
    const mixed = mmdb([['0', US], ['1', Buffer.from([0x20, 0xff])]]);
    await fs.writeFile(files.city, mixed);
    files.advance();
    assert.deepEqual(await lookup('8.8.8.8'), US_EN);
    assert.deepEqual(await lookup('192.0.2.1'), ASN_OUT);
});

test('refreshes on mtime, handles replacement/deletion and retries a missing peer', async t => {
    const files = await fixtures(t);
    const first = mmdb([['0', { country: { iso_code: 'US' } }]]);
    const second = mmdb([['0', { country: { iso_code: 'AU' } }]]);
    const counts = ioCounts(t);
    const { lookup } = useService(t, files);
    const ip = '8.8.8.8';
    assert.deepEqual(await lookup(ip), NONE);
    await fs.writeFile(files.city, first);
    files.advance();
    assert.deepEqual(await lookup(ip), { ...NONE, country: 'US' });
    await fs.writeFile(files.city, second);
    await fs.utimes(files.city, 1700000000, 1700000000);
    assert.deepEqual(await lookup(ip), { ...NONE, country: 'US' });
    files.advance();
    assert.deepEqual(await lookup(ip), { ...NONE, country: 'AU' });
    const replacement = `${files.city}.new`;
    await fs.writeFile(replacement, first);
    await fs.utimes(replacement, 1700000000, 1700000000);
    await fs.rename(replacement, files.city);
    await fs.writeFile(files.asn, mmdb([['0', ASN]]));
    files.advance();
    assert.deepEqual(await lookup(ip), { ...ASN_OUT, country: 'US' });
    files.advance();
    assert.deepEqual(await lookup(ip), { ...ASN_OUT, country: 'US' });
    assert.equal(counts.reads, 4, 'do not read unchanged files');
    await fs.unlink(files.city);
    files.advance();
    assert.deepEqual(await lookup(ip), ASN_OUT);
    await fs.writeFile(files.city, first);
    await fs.writeFile(files.asn, Buffer.from('bad ASN DB'));
    files.advance();
    assert.deepEqual(await lookup(ip), { ...NONE, country: 'US' });
});

test('bounds file size and remembers an unchanged corrupt metadata snapshot', async t => {
    const files = await fixtures(t);
    await fs.writeFile(files.city, Buffer.alloc(100));
    await fs.writeFile(files.asn, Buffer.alloc(0));
    await fs.truncate(files.asn, 260 * 1024 * 1024); // Sparse oversized fixture, not read.
    const counts = ioCounts(t);
    const { lookup } = useService(t, files);
    assert.deepEqual(await lookup('8.8.8.8'), NONE);
    files.advance();
    assert.deepEqual(await lookup('8.8.4.4'), NONE);
    assert.deepEqual(counts, { stats: 4, opens: 1, reads: 1 });
});

test('does not publish a file edited while it was being read', async t => {
    const files = await fixtures(t);
    await fs.writeFile(files.city, mmdb([['0', US]]));
    await fs.writeFile(files.asn, mmdb([['0', ASN]]));
    const newer = mmdb([['0', { ...US, country: { iso_code: 'AU' } }]]);
    const open = fs.open;
    let changed = false;
    t.mock.method(fs, 'open', async (file, ...args) => {
        const handle = await open(file, ...args);
        if (file === files.city && !changed) {
            const read = handle.read.bind(handle);
            handle.read = async (...readArgs) => {
                const result = await read(...readArgs);
                await fs.writeFile(file, newer);
                await fs.utimes(file, 1700000000, 1700000000);
                changed = true;
                return result;
            };
        }
        return handle;
    });
    const { lookup } = useService(t, files);
    assert.deepEqual(await lookup('8.8.8.8'), ASN_OUT);
    assert.ok(changed);
    files.advance();
    assert.deepEqual(await lookup('8.8.8.8'), { ...ASN_OUT, country: 'AU', region: US_EN.region, city: US_EN.city });
});

test('coalesces file I/O for 5000 distinct IPs and retains exactly 5000 IPs in LRU order', async t => {
    const files = await fixtures(t);
    await fs.writeFile(files.city, mmdb([['0', US]]));
    await fs.writeFile(files.asn, mmdb([['0', ASN]]));
    const counts = ioCounts(t);
    const { lookup } = useService(t, files);
    const ips = Array.from({ length: 5000 }, (_, i) => `10.${i >> 8}.${i & 255}.1`);
    const results = await Promise.all(ips.map(ip => lookup(ip, 'ru')));
    assert.equal(results.filter(r => r.asn === 64512 && r.city === 'Тестовый город').length, ips.length);
    assert.deepEqual(counts, { stats: 2, opens: 2, reads: 2 });

    const readUIntBE = Buffer.prototype.readUIntBE;
    const reads = t.mock.method(Buffer.prototype, 'readUIntBE', function (...args) {
        return readUIntBE.apply(this, args);
    });
    const first = await lookup('::ffff:10.0.0.1', 'en');
    assert.equal(first.city, 'Fixture City');
    assert.equal(reads.mock.callCount(), 0, 'mapped alias and new locale reuse the first cached IP');
    first.city = 'modified by caller';
    await lookup('10.20.0.1'); // Entry 5001, evicts the second entry, not the first.
    const afterInsert = reads.mock.callCount();
    assert.ok(afterInsert > 0);
    assert.equal((await lookup(ips[0])).city, 'Fixture City');
    assert.equal(reads.mock.callCount(), afterInsert, 'most recently touched entry survives');
    await lookup(ips[1]);
    assert.ok(reads.mock.callCount() > afterInsert, 'least recently used entry was evicted');
    files.advance();
    for (const ip of ips.slice(0, 20)) await lookup(ip);
    assert.deepEqual(counts, { stats: 4, opens: 2, reads: 2 }, 'sequential warm lookups also share a poll');
});

// Opt in with the two DB-IP 2026-11 files; no downloads or private files needed by default.
const realFiles = { city: process.env.GEOIP_TEST_CITY_DB, asn: process.env.GEOIP_TEST_ASN_DB };
test('provided DB-IP snapshot: public IPv4 and IPv6, ASN organization and RU fallback',
    { skip: !realFiles.city && !realFiles.asn }, async t => {
        assert.ok(realFiles.city && realFiles.asn, 'set both GEOIP_TEST_CITY_DB and GEOIP_TEST_ASN_DB');
        const { lookup } = useService(t, realFiles);
        const cases = [
            ['8.8.8.8', { country: 'US', region: 'California', city: 'Mountain View', asn: 15169, isp: 'Google LLC' }],
            ['77.88.8.8', { country: 'RU', region: 'Moscow', city: 'Moscow (Tsentralnyy administrativnyy okrug)', asn: 13238, isp: 'YANDEX LLC' }],
            ['1.1.1.1', { country: 'AU', region: 'New South Wales', city: 'Sydney', asn: 13335, isp: 'Cloudflare, Inc.' }]
        ];
        for (const [ip, expected] of cases) {
            assert.deepEqual(await lookup(ip, 'en'), expected);
            assert.deepEqual(await lookup(ip, 'ru'), expected);
            assert.deepEqual(await lookup(`::ffff:${ip}`, 'ru'), expected);
        }
        const ipv6 = await lookup('2001:4860:4860::8888', 'ru');
        assert.deepEqual(ipv6, { country: 'CA', region: 'Quebec', city: 'Montreal', asn: 15169, isp: 'Google LLC' });
        assert.deepEqual(await lookup('2001:4860:4860::0.0.136.136', 'ru'), ipv6);
    });
