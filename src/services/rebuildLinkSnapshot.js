'use strict';

const { BSON } = require('mongoose').mongo;
const keyEnvelopeField = 'rebuildVlessKeyEnvelope';
const fullLinkRead = Object.freeze({ schemaLevelProjections: false });

// Only top-level fields written by health checks (including Mongoose's timestamp).
// Keep every other field, including unknown fields and nested objects, in the guard.
function linkSnapshot({ status, lastHealthCheck, latencyMs, lastError, updatedAt, ...working }) {
    return working;
}

function canonical(value) {
    // Encode values, not object identity or V8's array layout. Explicit tags
    // distinguish null, undefined, absence, and embedded BSON types.
    if (value === null) return ['null'];
    if (value === undefined) return ['undefined'];
    if (typeof value === 'number') return ['number', Object.is(value, -0) ? '-0' : String(value)];
    if (typeof value === 'bigint') return ['bigint', String(value)];
    if (typeof value === 'string' || typeof value === 'boolean') return [typeof value, value];
    if (Array.isArray(value)) return ['array', value.map(canonical)];
    const proto = Object.getPrototypeOf(value);
    if (proto === Object.prototype || proto === null) {
        return [proto === null ? 'dictionary' : 'object',
            Object.keys(value).sort().map(key => [key, canonical(value[key])])];
    }
    if (value instanceof Date) return ['date', String(value.getTime())];
    if (value instanceof RegExp) return ['regexp', value.source, value.flags];
    if (Buffer.isBuffer(value)) return ['buffer', value.toString('base64')];
    if (value instanceof BSON.Code) return ['code', value.code, canonical(value.scope)];
    if (typeof value._bsontype === 'string') return ['bson', value._bsontype, BSON.serialize({ value }).toString('base64')];
    throw Object.assign(new Error('REBUILD_LINK_CHANGED'), { code: 'REBUILD_LINK_CHANGED' });
}

function linkSnapshotBytes(link) {
    return Buffer.from(JSON.stringify(canonical(linkSnapshot(link))));
}

module.exports = { linkSnapshot, linkSnapshotBytes, keyEnvelopeField, fullLinkRead };