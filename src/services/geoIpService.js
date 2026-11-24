'use strict';

const fs = require('node:fs/promises');
const { O_RDONLY, O_NONBLOCK } = require('node:fs').constants;
const { createHmac, randomBytes } = require('node:crypto');
const { isIP } = require('node:net');
const { performance } = require('node:perf_hooks');
const { TextDecoder } = require('node:util');

// Format: https://maxmind.github.io/MaxMind-DB/ (MMDB v2).
const MARKER = Buffer.from('\xab\xcd\xefMaxMind.com', 'latin1');
const SEPARATOR_SIZE = 16;
const MAX_METADATA = 128 * 1024;
const POINTER_BIAS = [0, 0, 2048, 526336]; // Indexed by pointer byte width.
const SIZE_BIAS = [0, 29, 285, 65821];
const MAX_DEPTH = 32;
const MAX_VALUES = 2048;
const MAX_PAYLOAD = 128 * 1024; // Per decode, including repeated pointer targets.
const MAX_LABEL_LENGTH = 512;
const POLL_MS = 1000;
const CACHE_SIZE = 5000;
const MIB = 1024 * 1024;
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const cache = new Map();
const cacheKey = randomBytes(32);
const EMPTY = Object.freeze({ country: null, region: null, city: null, asn: null, isp: null });

function invalid() {
    throw new Error('Invalid MMDB');
}

function isMap(value) {
    return value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === null;
}

function decode(buffer, offset, start, end) {
    const active = new Set();
    let values = MAX_VALUES;
    let payload = MAX_PAYLOAD;

    function check(off, size) {
        if (off < start || off + size > end) invalid();
    }

    function read(off, depth, indirect = false) {
        if (--values < 0 || depth > MAX_DEPTH || active.has(off)) invalid();
        check(off, 1);
        active.add(off);
        try {
            return readValue(off, depth, indirect);
        } finally {
            active.delete(off);
        }
    }

    function readValue(off, depth, indirect) {
        const control = buffer[off++];
        let type = control >> 5;
        if (type === 1) {
            if (indirect) invalid(); // The format disallows pointers to pointers.
            const width = ((control >> 3) & 3) + 1;
            check(off, width);
            const low = buffer.readUIntBE(off, width);
            const pointer = width === 4 ? low : (control & 7) * 2 ** (8 * width) + low + POINTER_BIAS[width];
            return [read(start + pointer, depth + 1, true)[0], off + width];
        }
        if (type === 0) {
            check(off, 1);
            type = 7 + buffer[off++];
            if (type < 8) invalid();
        }
        let size = control & 31;
        if (size >= 29) {
            const width = size - 28;
            check(off, width);
            size = SIZE_BIAS[width] + buffer.readUIntBE(off, width);
            off += width;
        }
        if (type === 7 || type === 11) {
            const stride = type === 7 ? 2 : 1;
            // Each key/value needs at least one byte, even if it is a pointer.
            if (size * stride > values || size * stride > end - off) invalid();
            if (type === 7) {
                const map = Object.create(null);
                for (let i = 0; i < size; i++) {
                    let key;
                    [key, off] = read(off, depth + 1);
                    if (typeof key !== 'string' || Object.hasOwn(map, key)) invalid();
                    [map[key], off] = read(off, depth + 1);
                }
                return [map, off];
            }
            const array = [];
            for (let i = 0; i < size; i++) [array[i], off] = read(off, depth + 1);
            return [array, off];
        }
        if (type === 14) {
            if (size > 1) invalid();
            return [size === 1, off]; // Boolean value is in the size field, not the payload.
        }

        check(off, size);
        payload -= size;
        if (payload < 0) invalid();
        let value;
        switch (type) {
            case 2: value = utf8.decode(buffer.subarray(off, off + size)); break;
            case 3:
                if (size !== 8) invalid();
                value = buffer.readDoubleBE(off);
                break;
            case 4: value = buffer.subarray(off, off + size); break;
            case 5: // uint16
            case 6: // uint32
            case 8: // int32 (negative values use all four bytes)
            case 9: // uint64
            case 10: { // uint128
                if (size > (type === 5 ? 2 : type === 9 ? 8 : type === 10 ? 16 : 4)) invalid();
                if (type === 8 && size === 4) value = buffer.readInt32BE(off);
                else if (size <= 6) value = size === 0 ? 0 : buffer.readUIntBE(off, size);
                else {
                    const wide = BigInt(`0x${buffer.toString('hex', off, off + size)}`);
                    value = wide <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(wide) : wide;
                }
                break;
            }
            case 15:
                if (size !== 4) invalid();
                value = buffer.readFloatBE(off);
                break;
            default: invalid(); // Invalid/reserved types, including the unused container/end marker.
        }
        return [value, off + size];
    }

    return read(offset, 0);
}

function openDatabase(buffer) {
    // Restrict the backwards search; don't scan a corrupt file's entire data section.
    const tail = Math.max(0, buffer.length - MAX_METADATA - MARKER.length);
    const marker = buffer.subarray(tail).lastIndexOf(MARKER);
    if (marker < 0) invalid();
    const dataEnd = tail + marker;
    const metaStart = dataEnd + MARKER.length;
    const [meta, metaEnd] = decode(buffer, metaStart, metaStart, buffer.length);
    if (!isMap(meta) || metaEnd !== buffer.length) invalid();
    const { node_count: count, record_size: width, ip_version: version } = meta;
    if (meta.binary_format_major_version !== 2 || !Number.isInteger(meta.binary_format_minor_version) ||
        meta.binary_format_minor_version < 0 || ![4, 6].includes(version) || ![24, 28, 32].includes(width) ||
        !Number.isInteger(count) || count < 0 || count >= 2 ** width ||
        typeof meta.database_type !== 'string' || !meta.database_type ||
        (typeof meta.build_epoch !== 'bigint' && !Number.isSafeInteger(meta.build_epoch)) || meta.build_epoch < 0 ||
        (meta.languages !== undefined && (!Array.isArray(meta.languages) || meta.languages.some(s => typeof s !== 'string'))) ||
        (meta.description !== undefined && (!isMap(meta.description) || Object.values(meta.description).some(s => typeof s !== 'string')))) invalid();

    const nodeSize = width / 4;
    const treeEnd = count * nodeSize;
    const dataStart = treeEnd + SEPARATOR_SIZE;
    if (dataStart > dataEnd) invalid();
    for (let i = treeEnd; i < dataStart; i++) if (buffer[i] !== 0) invalid();

    function edge(node, bit) {
        const off = node * nodeSize;
        if (width === 24) return buffer.readUIntBE(off + bit * 3, 3);
        if (width === 32) return buffer.readUInt32BE(off + bit * 4);
        const middle = buffer[off + 3];
        const high = bit ? middle & 15 : middle >> 4;
        return high * 0x1000000 + buffer.readUIntBE(off + bit * 4, 3);
    }

    // IPv4 addresses in an IPv6 MMDB occupy ::/96. Keep ancestors so a loop
    // from below this prefix back into it is detected during IPv4 lookups.
    let v4Root = 0;
    const v4Ancestors = new Set();
    if (version === 6) {
        for (let i = 0; i < 96 && v4Root < count; i++) {
            if (v4Ancestors.has(v4Root)) {
                v4Root = count;
                break;
            }
            v4Ancestors.add(v4Root);
            v4Root = edge(v4Root, 0);
        }
    }

    return function find(bytes) {
        const v4 = bytes.length === 4;
        if (!v4 && version === 4) return null;
        let node = v4 ? v4Root : 0;
        const seen = new Set();
        for (let i = 0; i < bytes.length * 8 && node < count; i++) {
            if (seen.has(node) || (v4 && v4Ancestors.has(node))) invalid();
            seen.add(node);
            node = edge(node, (bytes[i >> 3] >> (7 - (i & 7))) & 1);
        }
        if (node === count) return null;
        const offset = treeEnd + node - count;
        if (offset < dataStart || offset >= dataEnd) invalid(); // Also rejects an unfinished tree walk.
        const [record] = decode(buffer, offset, dataStart, dataEnd);
        if (!isMap(record)) invalid();
        return record;
    };
}

function parseIP(ip) {
    if (typeof ip !== 'string' || ip.length > 45 || ip.includes('%')) return null;
    const version = isIP(ip);
    if (version === 0) return null;
    if (version === 4) return Buffer.from(ip.split('.').map(Number));
    const lastColon = ip.lastIndexOf(':');
    const tail = ip.slice(lastColon + 1);
    if (tail.includes('.')) {
        const [a, b, c, d] = tail.split('.').map(Number);
        ip = `${ip.slice(0, lastColon + 1)}${(a * 256 + b).toString(16)}:${(c * 256 + d).toString(16)}`;
    }
    const [left, right] = ip.split('::');
    const head = left ? left.split(':') : [];
    const end = right ? right.split(':') : [];
    const bytes = Buffer.alloc(16);
    head.forEach((part, i) => bytes.writeUInt16BE(parseInt(part, 16), i * 2));
    end.forEach((part, i) => bytes.writeUInt16BE(parseInt(part, 16), (8 - end.length + i) * 2));
    // Only ::ffff:0:0/96 is IPv4-mapped. Other dotted-tail forms remain IPv6.
    if (bytes.readUInt32BE(0) === 0 && bytes.readUInt32BE(4) === 0 && bytes.readUInt32BE(8) === 0xffff) {
        return bytes.subarray(12);
    }
    return bytes;
}

function sameFile(a, b) {
    return b !== null && a.dev === b.dev && a.ino === b.ino && a.size === b.size &&
        a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
}

function database(file, limit) {
    let find = null;
    let checked = null;
    let nextCheck = 0;
    let inflight = null;

    async function refresh() {
        const stat = await fs.stat(file, { bigint: true }).catch(() => null);
        if (stat && sameFile(stat, checked)) return;
        checked = null;
        if (find) {
            find = null; // Release the old buffer reference before reading a replacement.
            cache.clear();
        }
        if (!stat) return;
        if (!stat.isFile() || stat.size > BigInt(limit) || stat.size < BigInt(SEPARATOR_SIZE + MARKER.length + 1)) {
            checked = stat;
            return;
        }
        const handle = await fs.open(file, O_RDONLY | O_NONBLOCK);
        let buffer;
        try {
            // Read only this open inode, with a fixed byte cap even if the path
            // was replaced or the file grew between stat and open/read.
            if (!sameFile(stat, await handle.stat({ bigint: true }))) return;
            buffer = Buffer.allocUnsafe(Number(stat.size));
            let offset = 0;
            for (let i = 0; offset < buffer.length && i < 16; i++) {
                const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
                if (bytesRead === 0) return;
                offset += bytesRead;
            }
            if (offset !== buffer.length || !sameFile(stat, await handle.stat({ bigint: true }))) return;
        } finally {
            await handle.close();
        }
        checked = stat; // Don't reread an unchanged corrupt snapshot at every poll.
        find = openDatabase(buffer);
        cache.clear(); // Invalidate also when a previously missing/bad file comes online.
    }

    return {
        poll() {
            if (inflight) return inflight;
            if (performance.now() < nextCheck) return null;
            inflight = refresh().catch(() => { /* Optional local database; never log errors. */ }).finally(() => {
                nextCheck = performance.now() + POLL_MS;
                inflight = null;
            });
            return inflight;
        },
        lookup(bytes) {
            try {
                return find ? find(bytes) : null;
            } catch {
                return null; // A bad record/branch does not disable the other addresses/file.
            }
        }
    };
}

const cityDb = database(process.env.GEOIP_CITY_DB || '/app/data/geoip/city.mmdb', 256 * MIB);
const asnDb = database(process.env.GEOIP_ASN_DB || '/app/data/geoip/asn.mmdb', 64 * MIB);

function label(value) {
    return typeof value === 'string' && value.length <= MAX_LABEL_LENGTH ? value.trim() || null : null;
}

function cityNames(names) {
    // Retain only bounded strings used by the panel, never decoded records or buffer views.
    return { en: label(names?.en), ru: label(names?.ru), 'zh-CN': label(names?.['zh-CN']) };
}

function panelLocale(locale) {
    if (typeof locale !== 'string' || locale.length > 32) return 'en';
    const lang = locale.trim().toLowerCase().split(/[-_]/, 1)[0];
    return lang === 'ru' ? 'ru' : lang === 'zh' ? 'zh-CN' : 'en';
}

/** Local GeoIP lookup. Country is ISO alpha-2; ISP is the ASN organization in DB-IP Lite. */
async function lookup(ip, locale) {
    const bytes = parseIP(ip);
    if (!bytes) return { ...EMPTY };
    const cityPoll = cityDb.poll();
    const asnPoll = asnDb.poll();
    if (cityPoll || asnPoll) await Promise.all([cityPoll, asnPoll]);

    // The geolocation LRU outlives the connection snapshot. Don't keep a
    // reversible IP key, or any user/node association, in that cache.
    const key = createHmac('sha256', cacheKey).update(bytes).digest('base64url');
    let entry = cache.get(key);
    if (entry) {
        cache.delete(key); // Move the hit to the most-recent end.
    } else {
        const location = cityDb.lookup(bytes);
        const network = asnDb.lookup(bytes);
        const iso = location?.country?.iso_code;
        const asn = network?.autonomous_system_number;
        entry = {
            country: typeof iso === 'string' && /^[A-Z]{2}$/.test(iso) ? iso : null,
            region: cityNames(location?.subdivisions?.[0]?.names),
            city: cityNames(location?.city?.names),
            asn: Number.isInteger(asn) && asn > 0 && asn <= 0xffffffff ? asn : null,
            isp: label(network?.isp) ?? label(network?.autonomous_system_organization)
        };
    }
    cache.set(key, entry);
    if (cache.size > CACHE_SIZE) cache.delete(cache.keys().next().value);
    const lang = panelLocale(locale);
    return {
        country: entry.country,
        region: entry.region[lang] ?? entry.region.en,
        city: entry.city[lang] ?? entry.city.en,
        asn: entry.asn,
        isp: entry.isp
    };
}

module.exports = { lookup };
