/**
 * Access-logs event contract tests.
 *
 * Validates the Xray access-line parser against fixtures covering the common
 * formats, malformed lines, IPv6 destinations and idempotent event ids.
 */

const assert = require('assert');
const {
    PARSER_VERSION,
    EVENT_COLUMNS,
    parseAccessLine,
    computeEventId,
    splitHostPort,
    maskIp,
    maskEventSourceIp,
} = require('../src/services/accessLogs/eventContract');

// --- splitHostPort ---------------------------------------------------------
assert.deepStrictEqual(splitHostPort('1.2.3.4:443'), { host: '1.2.3.4', port: 443 });
assert.deepStrictEqual(splitHostPort('example.com:80'), { host: 'example.com', port: 80 });
assert.deepStrictEqual(splitHostPort('[::1]:443'), { host: '::1', port: 443 });
assert.deepStrictEqual(splitHostPort('nohost'), { host: 'nohost', port: null });

// --- standard accepted TCP line -------------------------------------------
{
    const raw = '2023/11/22 17:01:32 192.168.1.33:11421 accepted tcp:example.com:443 [vless-in -> direct] email: 42';
    const ev = parseAccessLine(raw, { nodeId: 'n1', offset: 100 });
    assert.strictEqual(ev.parseOk, true, 'standard line should parse');
    assert.strictEqual(ev.action, 'accepted');
    assert.strictEqual(ev.network, 'tcp');
    assert.strictEqual(ev.sourceIp, '192.168.1.33');
    assert.strictEqual(ev.sourcePort, 11421);
    assert.strictEqual(ev.destinationHost, 'example.com');
    assert.strictEqual(ev.destinationIp, '');
    assert.strictEqual(ev.destinationPort, 443);
    assert.strictEqual(ev.inboundTag, 'vless-in');
    assert.strictEqual(ev.outboundTag, 'direct');
    assert.strictEqual(ev.email, '42');
    assert.strictEqual(ev.parserVersion, PARSER_VERSION);
    assert.ok(ev.timestamp instanceof Date && !isNaN(ev.timestamp.getTime()));
}

// --- "from" prefix + UDP + IP destination ---------------------------------
{
    const raw = '2024/05/01 08:12:00 from 1.2.3.4:5555 accepted udp:8.8.8.8:53 [in -> out] email: user@x';
    const ev = parseAccessLine(raw, { nodeId: 'n1', offset: 0 });
    assert.strictEqual(ev.parseOk, true);
    assert.strictEqual(ev.network, 'udp');
    assert.strictEqual(ev.sourceIp, '1.2.3.4');
    assert.strictEqual(ev.destinationIp, '8.8.8.8');
    assert.strictEqual(ev.destinationHost, '');
    assert.strictEqual(ev.email, 'user@x');
}

// --- fractional seconds + no email ----------------------------------------
{
    const raw = '2024/05/01 08:12:00.123456 5.5.5.5:1000 rejected tcp:blocked.com:443 [in -> block]';
    const ev = parseAccessLine(raw, { nodeId: 'n1', offset: 5 });
    assert.strictEqual(ev.parseOk, true);
    assert.strictEqual(ev.action, 'rejected');
    assert.strictEqual(ev.outboundTag, 'block');
    assert.strictEqual(ev.email, '');
}

// --- malformed line: preserved raw, parseOk=false -------------------------
{
    const raw = 'this is not an xray access line';
    const ev = parseAccessLine(raw, { nodeId: 'n1', offset: 9 });
    assert.strictEqual(ev.parseOk, false, 'garbage should not parse');
    assert.strictEqual(ev.raw, raw, 'raw preserved');
    assert.ok(ev.eventId, 'event id present even when parse fails');
}

// --- event id determinism + offset sensitivity ----------------------------
{
    const raw = '2023/11/22 17:01:32 1.1.1.1:2 accepted tcp:a.com:443 [in -> out] email: 1';
    const a = computeEventId('n1', raw, 100);
    const b = computeEventId('n1', raw, 100);
    const c = computeEventId('n1', raw, 200);
    assert.strictEqual(a, b, 'same inputs -> same id (idempotent)');
    assert.notStrictEqual(a, c, 'different offset -> different id (distinct repeats)');
}

// --- client-IP masking ------------------------------------------------------
{
    assert.strictEqual(maskIp('192.168.1.33'), '192.168.1.0', 'IPv4 keeps /24');
    assert.strictEqual(maskIp('2001:db8:abcd:12:34::1'), '2001:db8:abcd::', 'IPv6 keeps 3 hextets');
    assert.strictEqual(maskIp(''), '', 'empty stays empty');

    const raw = '2023/11/22 17:01:32 192.168.1.33:11421 accepted tcp:example.com:443 [vless-in -> direct] email: 42';
    const ev = parseAccessLine(raw, { nodeId: 'n1', offset: 100 });
    const masked = maskEventSourceIp(ev);
    assert.strictEqual(masked.sourceIp, '192.168.1.0', 'sourceIp masked');
    assert.ok(!masked.raw.includes('192.168.1.33'), 'raw line scrubbed');
    assert.ok(masked.raw.includes('192.168.1.0'), 'raw carries masked ip');
    assert.strictEqual(masked.eventId, ev.eventId, 'event id unchanged (dedup stays deterministic)');
    // Untouched fields survive.
    assert.strictEqual(masked.destinationHost, 'example.com');
    assert.strictEqual(masked.email, '42');
}

// --- contract columns present in a parsed event ---------------------------
{
    const ev = parseAccessLine('2023/11/22 17:01:32 1.1.1.1:2 accepted tcp:a.com:443 [in -> out] email: 1', { nodeId: 'n', offset: 1 });
    for (const col of EVENT_COLUMNS) {
        assert.ok(Object.prototype.hasOwnProperty.call(ev, col), `event missing column ${col}`);
    }
}

console.log('test-access-logs-contract: OK');
