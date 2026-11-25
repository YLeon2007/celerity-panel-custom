'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createHash } = require('node:crypto');
const { BSON, MongoClient, MongoServerError } = require('mongodb');
const { createRelayCleanupConsentStore } = require('../rebuildRelayCleanupConsentMongo');

const collectionName = 'rebuild_l2tp_cleanup_consents_v1';
const scope = Object.freeze({ nodeId: 'a'.repeat(24), actor: '$fixture-admin', sessionId: 'fixture-session-id',
    generation: '12345678-1234-4234-8234-123456789abc' });
const keys = Object.freeze(['CHAP_NOT_EMPTY', 'MODULES_LOAD_FOREIGN']);
const proof = Object.freeze({ check: 'L2TP_FOREIGN_CONFIG', keys, cleanable: true, manual: false, digest: 'b'.repeat(64) });
const confirm = (token, fixXrayUnitMode = false) => ({ token, fixXrayUnitMode });
const err = suffix => ({ code: `REBUILD_L2TP_CLEANUP_CONSENT_${suffix}` });
const sha = s => createHash('sha256').update(s).digest('hex');
const start = Date.UTC(2026, 10, 25);
const ttl = 600_000;
const clone = value => BSON.deserialize(BSON.serialize(value));

// Socket-free fixture at the native collection boundary. The BSON round trip
// and emitted selectors/pipelines are real; Mongo storage/clock/ACK are modeled.
function fixture() {
    const rows = new Map();
    const writes = [];
    const indexes = [];
    const reads = [];
    const f = { rows, writes, indexes, reads, now: start };
    const noAck = () => new Error('private fixture failure: ' + proof.digest + scope.sessionId);
    function evalExpr(expression, row) {
        if (expression === '$$NOW') return new Date(f.now);
        if (typeof expression === 'string' && expression.startsWith('$')) {
            return expression.slice(1).split('.').reduce((value, key) => value?.[key], row);
        }
        if (!expression || typeof expression !== 'object' || expression instanceof Date) return expression;
        const next = expr => evalExpr(expr, row);
        if ('$literal' in expression) return expression.$literal;
        if ('$and' in expression) return expression.$and.every(next);
        if ('$cond' in expression) return next(expression.$cond[next(expression.$cond[0]) ? 1 : 2]);
        if ('$eq' in expression) return same(...expression.$eq.map(next));
        if ('$lt' in expression) return next(expression.$lt[0]) < next(expression.$lt[1]);
        if ('$lte' in expression) return next(expression.$lte[0]) <= next(expression.$lte[1]);
        if ('$type' in expression) return next(expression.$type) instanceof Date ? 'date' : 'other';
        if ('$add' in expression) return new Date(Number(next(expression.$add[0])) + next(expression.$add[1]));
        return Object.fromEntries(Object.entries(expression).map(([k, v]) => [k, next(v)]));
    }
    const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
    const matches = (row, filter) => row && Object.entries(filter).every(([key, value]) => {
        if (key === '$expr') return evalExpr(value, row);
        if (value?.$exists !== undefined) return Object.hasOwn(row, key) === value.$exists;
        return same(row[key], value);
    });
    const collection = {
        async createIndex(spec, opts) {
            indexes.push(clone({ spec, opts }));
            if (f.indexError) throw noAck();
            return opts.name;
        },
        async updateMany(filter, pipeline, opts) {
            ({ filter, pipeline, opts } = clone({ filter, pipeline, opts }));
            writes.push({ filter, pipeline, opts });
            const kind = opts.upsert ? 'issue' : 'consume';
            if (f.before === kind) throw noAck();
            let row = rows.get(filter._id);
            const matched = matches(row, filter);
            const upsert = opts.upsert && !matched;
            if (upsert && row) throw noAck();
            if (upsert) row = { _id: filter._id };
            if (matched || upsert) {
                for (const stage of pipeline) {
                    if (stage.$set) row = { ...row, ...evalExpr(stage.$set, row) };
                    else if (stage.$unset) for (const key of stage.$unset) delete row[key];
                    else assert.fail('unexpected update stage');
                }
                rows.set(row._id, row);
            }
            if (f.after === kind) throw noAck();
            return { acknowledged: f.unacknowledged !== kind, upsertedId: upsert ? row._id : null,
                upsertedCount: upsert ? 1 : 0, matchedCount: matched ? 1 : 0, modifiedCount: matched ? 1 : 0 };
        },
        async findOne(filter, opts) {
            reads.push(clone({ filter, opts }));
            if (f.readError) throw noAck();
            const row = rows.get(filter._id);
            return matches(row, filter) ? clone({ audit: row.audit }) : null;
        },
    };
    f.store = () => createRelayCleanupConsentStore({ db: { collection(name) {
        assert.equal(name, collectionName);
        return collection;
    } } });
    return f;
}

function noPrivate(record, token) {
    const text = JSON.stringify(record);
    for (const value of [token, sha(token), scope.sessionId, sha(scope.sessionId), scope.generation, proof.digest]) {
        assert.equal(text.includes(value), false, 'private data leaked');
    }
}

test('database expiry index; token, session and private digest are never sent raw; atomically persisted safe audit', async () => {
    const f = fixture(), issuer = f.store();
    await issuer.ensureIndexes();
    assert.deepEqual(f.indexes, [{ spec: { expiresAt: 1 }, opts: { name: 'cleanup_consent_expiry', expireAfterSeconds: 0,
        writeConcern: { w: 'majority' } } }, { spec: { 'audit.backupId': 1 }, opts: {
        name: 'cleanup_consent_install', unique: true, partialFilterExpression: { 'audit.backupId': { $exists: true } },
        writeConcern: { w: 'majority' } } }]);
    const issued = await issuer.issue(scope, proof);
    assert.deepEqual(Object.keys(issued), ['token']);
    const { token } = issued;
    assert.match(token, /^[a-f0-9]{64}$/);
    const id = sha(token), pending = f.rows.get(id);
    assert.equal(pending.issuedAt.valueOf(), start);
    assert.equal(pending.expiresAt.valueOf(), start + ttl);
    assert.equal(pending.owner.sessionSha256, sha(scope.sessionId));
    assert.match(pending.proof.digestSha256, /^[a-f0-9]{64}$/);
    f.now += 17;
    const result = await f.store().consume(scope, confirm(token), proof);
    assert.deepEqual(result, { keys, fixXrayUnitMode: false, audit: { action: 'l2tp-cleanup-consent',
        issuedAt: new Date(start).toISOString(), consumedAt: new Date(f.now).toISOString(), actor: scope.actor,
        nodeId: scope.nodeId, keys, paths: ['/etc/ppp/chap-secrets', '/etc/modules-load.d/c3-l2tp.conf'], result: 'consumed' } });
    const spent = f.rows.get(id);
    assert.deepEqual(Object.keys(spent).sort(), ['_id', 'audit', 'state', 'version']);
    assert.deepEqual({ ...spent.audit, issuedAt: spent.audit.issuedAt.toISOString(), consumedAt: spent.audit.consumedAt.toISOString() }, result.audit);
    noPrivate(result, token);
    assert.equal(JSON.stringify(f.writes).includes(token), false);
    assert.equal(JSON.stringify(f.writes).includes(scope.sessionId), false);
    assert.equal(JSON.stringify(f.writes).includes(proof.digest), false);
    assert.deepEqual(f.reads[0].opts.projection, { _id: 0, audit: 1 });
    assert.equal(f.reads[0].opts.readConcern.level, 'majority');
    assert.equal(f.reads[0].opts.readPreference, 'primary');
    for (const write of f.writes) assert.deepEqual(write.opts.writeConcern, { w: 'majority' });
});

test('two independent stores race the same token; exactly one succeeds and restarts cannot replay', async () => {
    const f = fixture(), token = (await f.store().issue(scope, proof)).token;
    const results = await Promise.allSettled(Array.from({ length: 12 }, () => f.store().consume(scope, confirm(token), proof)));
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    for (const r of results.filter(r => r.status === 'rejected')) assert.equal(r.reason.code, err('REQUIRED').code);
    assert.equal(f.rows.size, 1);
    assert.equal(f.reads.length, 1);
    await assert.rejects(f.store().consume(scope, confirm(token), proof), err('REQUIRED'));
});

test('wrong actor, node, session, generation and token never burn or delete the owner’s consent', async () => {
    const f = fixture(), store = f.store(), token = (await store.issue(scope, proof)).token;
    const pending = clone(f.rows.get(sha(token)));
    for (const change of [{ actor: '$FIXTURE-ADMIN' }, { nodeId: 'f'.repeat(24) }, { sessionId: 'other-session' },
        { generation: '12345678-1234-4234-a234-123456789abc' }]) {
        await assert.rejects(store.consume({ ...scope, ...change }, confirm(token), proof), err('REQUIRED'));
    }
    const wrongToken = (token[0] === '1' ? '0' : '1') + token.slice(1);
    await assert.rejects(store.consume(scope, confirm(wrongToken), proof), err('REQUIRED'));
    assert.deepEqual(f.rows.get(sha(token)), pending);
    assert.equal(f.reads.length, 0);
    assert.equal((await store.consume(scope, confirm(token), proof)).audit.result, 'consumed');
});

test('10-minute absolute TTL uses database time, not TTL sweep, restart, diagnostics or last access', async () => {
    const f = fixture(), store = f.store();
    const one = (await store.issue(scope, proof)).token;
    const two = (await store.issue(scope, proof)).token;
    const three = (await store.issue(scope, proof)).token;
    f.now = start - 1;
    await assert.rejects(store.consume(scope, confirm(one), proof), err('REQUIRED'));
    f.now = start + ttl - 1;
    assert.equal((await f.store().consume(scope, confirm(one), proof)).audit.result, 'consumed');
    f.now++;
    await assert.rejects(f.store().consume(scope, confirm(two), proof), err('REQUIRED'));
    f.now++;
    await assert.rejects(f.store().consume(scope, confirm(three), proof), err('REQUIRED'));
    assert.equal(f.rows.get(sha(two)).expiresAt.valueOf(), start + ttl);
    assert.equal(f.rows.get(sha(three)).state, 'issued');
});

test('fresh read is required; digest, key, check or manual drift burns the exact scoped token without consent', async () => {
    const f = fixture(), store = f.store();
    for (const current of [undefined, { ...proof, manual: true }, { ...proof, cleanable: false },
        { ...proof, digest: 'c'.repeat(64) }, { ...proof, keys: ['MODULES_LOAD_FOREIGN'] },
        { ...proof, check: 'L2TP_PPP_ACTIVE' }, { ...proof, keys: ['CHAP_NOT_EMPTY', 'UNIT_WRITABLE'] }]) {
        const { token } = await store.issue(scope, proof);
        await assert.rejects(store.consume(scope, confirm(token), current), err('CHANGED'));
        const row = f.rows.get(sha(token));
        assert.equal(row.audit.result, 'changed');
        noPrivate(row.audit, token);
        assert.deepEqual(row.audit.keys, keys);
        await assert.rejects(f.store().consume(scope, confirm(token), proof), err('REQUIRED'));
    }
});

test('only exact canonical cleanable leaves; no client path, manual classification or diagnostic keys', async () => {
    const f = fixture(), store = f.store();
    const getter = { ...proof, get digest() { assert.fail('do not run getters'); } };
    for (const p of [getter, { ...proof, manual: true }, { ...proof, cleanable: 1 }, { ...proof, manual: [] },
        { ...proof, paths: ['/tmp/foreign'] }, { ...proof, digest: `${proof.digest}\n` },
        ...[[], Array(1), [...keys].reverse(), [keys[0], keys[0]], ['/etc/ppp/chap-secrets'], ['__proto__'],
            ...['UNIT_WRITABLE', 'IPSEC_D_FOREIGN_CONF', 'SWAN_TREE_NOT_STOCK',
                'CONFFILE_UNKNOWN', 'INCLUDE_FOREIGN', 'L2TP_UDP_BOUND'].map(key => [key])].map(keys => ({ ...proof, keys }))]) {
        await assert.rejects(store.issue(scope, p), err('INVALID'));
    }
    for (const s of [{ ...scope, generation: 'env' }, { ...scope, nodeId: { $ne: '' } },
        { ...scope, actor: 'fixture\nadmin' }, { ...scope, sessionId: '' }, { ...scope, token: 'extra' }]) {
        await assert.rejects(store.issue(s, proof), err('INVALID'));
    }
    assert.equal(f.writes.length, 0);
    const token = (await store.issue(scope, proof)).token;
    for (const c of [{ token }, { token, fixXrayUnitMode: 'false' }, { ...confirm(token), paths: [] },
        confirm({ $ne: '' }), confirm(`${token}\n`), new Proxy(confirm(token), { get() { assert.fail('do not run proxies'); } })]) {
        await assert.rejects(store.consume(scope, c, proof), err('INVALID'));
    }
    assert.equal(f.writes.length, 1);
});

test('Xray 0666 report may be issued without opt-in; false cannot authorize stock-blocking modes', async () => {
    const f = fixture(), store = f.store();
    const observed = { ...proof, keys: ['CHAP_NOT_EMPTY', 'XRAY_UNIT_0666', 'XRAY_BRIDGE_UNIT_0666'] };
    const { token } = await store.issue(scope, observed);
    await assert.rejects(store.consume(scope, confirm(token), observed), err('XRAY_OPT_IN_REQUIRED'));
    assert.equal(f.rows.get(sha(token)).audit.result, 'xray-opt-in-required');
    await assert.rejects(store.consume(scope, confirm(token, true), observed), err('REQUIRED'));
    const other = (await store.issue(scope, observed)).token;
    const result = await store.consume(scope, confirm(other, true), observed);
    assert.equal(result.fixXrayUnitMode, true);
    assert.deepEqual(result.audit.paths, ['/etc/ppp/chap-secrets', '/etc/systemd/system/xray.service',
        '/etc/systemd/system/xray-bridge.service']);
    const unrelated = (await store.issue(scope, proof)).token;
    await assert.rejects(store.consume(scope, confirm(unrelated, true), proof), err('CHANGED'));
});

test('audit static paths cover all digest-bearing leaves in pinned DIRECT order', async () => {
    const f = fixture(), store = f.store();
    const all = { ...proof, keys: ['SWAN_PROFILE_PRESENT', 'IKE_PROFILE_PRESENT', 'OPTIONS_PRESENT', 'STARTER_NOT_STOCK',
        'SECRETS_NOT_EMPTY', 'CHAP_NOT_EMPTY', 'LNS_NOT_STOCK', 'XRAY_UNIT_0666', 'XRAY_BRIDGE_UNIT_0666',
        'MODULES_LOAD_FOREIGN', 'NETWORK_UNIT_ORPHANED', 'LEGACY_NFT_PRESENT'] };
    const { token } = await store.issue(scope, all);
    const { audit } = await store.consume(scope, confirm(token, true), all);
    assert.deepEqual(audit.paths, ['/etc/strongswan.d/celerity-rebuild-l2tp.conf', '/etc/ipsec.d/celerity-rebuild-l2tp.conf',
        '/etc/ppp/options.xl2tpd', '/etc/ipsec.conf', '/etc/ipsec.secrets', '/etc/ppp/chap-secrets', '/etc/xl2tpd/xl2tpd.conf',
        '/etc/systemd/system/xray.service', '/etc/systemd/system/xray-bridge.service', '/etc/modules-load.d/c3-l2tp.conf',
        '/etc/systemd/system/celerity-rebuild-l2tp-network.service', '/etc/nftables.d/celerity-l2tp.nft']);
});

test('lost or missing write ACK never grants, retries, leaks originals or restores a spent token', async () => {
    for (const cut of ['before', 'after', 'unacknowledged']) {
        const f = fixture(), store = f.store();
        const { token } = await store.issue(scope, proof);
        f[cut] = 'consume';
        await assert.rejects(store.consume(scope, confirm(token), proof), error => {
            assert.equal(error.code, err('UNAVAILABLE').code);
            noPrivate({ ...error, message: error.message, stack: error.stack }, token);
            assert.equal(Object.hasOwn(error, 'cause'), false);
            return true;
        });
        assert.equal(f.writes.length, 2);
        assert.equal(f.reads.length, 0);
        assert.equal(f.rows.get(sha(token)).state, cut === 'before' ? 'issued' : 'spent');
        if (cut !== 'before') {
            delete f[cut];
            await assert.rejects(f.store().consume(scope, confirm(token), proof), err('REQUIRED'));
        }
    }
});

test('index, issue and audit readback failures fail closed', async () => {
    const f = fixture(), store = f.store();
    f.indexError = true;
    await assert.rejects(store.ensureIndexes(), err('UNAVAILABLE'));
    f.after = 'issue';
    await assert.rejects(store.issue(scope, proof), err('UNAVAILABLE'));
    assert.equal(f.writes.length, 1);
    delete f.after;
    const { token } = await store.issue(scope, proof);
    f.readError = true;
    await assert.rejects(store.consume(scope, confirm(token), proof), err('UNAVAILABLE'));
    assert.equal(f.rows.get(sha(token)).audit.result, 'consumed');
    await assert.rejects(f.store().consume(scope, confirm(token), proof), err('REQUIRED'));
});

test('native driver does not retry the scoped write even with retryWrites enabled', async () => {
    // Real driver operation/retry logic and BSON, simulated server selection
    // and reply. No Mongo server, socket or actual DB is used by this test.
    const client = new MongoClient('mongodb://127.0.0.1:1/fixture', { retryWrites: true });
    const seen = [];
    const server = {
        description: { type: 'RSPrimary', logicalSessionTimeoutMinutes: 30, maxWireVersion: 21 },
        async command(operation, command, options) {
            const modern = typeof operation.buildCommandDocument === 'function';
            seen.push({ cmd: clone(modern ? operation.buildCommandDocument() : command),
                wc: modern ? operation.writeConcern?.w : command.writeConcern?.w,
                retry: modern ? operation.options.willRetryWrite : options.willRetryWrite });
            const unavailable = new MongoServerError({ code: 91, errmsg: 'fixture ACK loss' });
            unavailable.addErrorLabel('RetryableWriteError');
            throw unavailable;
        },
    };
    client.topology = { s: { options: client.options }, description: { logicalSessionTimeoutMinutes: 30 },
        selectServer: async () => server };
    const db = client.db();
    const store = createRelayCleanupConsentStore({ db });
    try {
        // Positive control: the same driver and fault actually retry updateOne.
        await assert.rejects(db.collection(collectionName).updateOne({ _id: 'fixture' }, { $set: { fixture: true } }),
            { code: 91 });
        assert.equal(seen.length, 2);
        assert.ok(seen.every(call => call.retry === true));
        seen.length = 0;
        const token = '0123456789abcdef'.repeat(4);
        await assert.rejects(store.consume(scope, confirm(token), proof), err('UNAVAILABLE'));
        assert.equal(seen.length, 1);
        const [{ cmd, wc, retry }] = seen;
        assert.equal(cmd.update, collectionName);
        assert.equal(cmd.updates.length, 1);
        assert.equal(cmd.updates[0].multi, true);
        assert.equal(cmd.updates[0].upsert, false);
        assert.equal(cmd.updates[0].q._id, sha(token));
        assert.deepEqual(cmd.updates[0].collation, { locale: 'simple' });
        assert.equal(retry, undefined);
        assert.equal(wc, 'majority');
    } finally {
        client.topology = undefined;
        await client.close();
    }
});
