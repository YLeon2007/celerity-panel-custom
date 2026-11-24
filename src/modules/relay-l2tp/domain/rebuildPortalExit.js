'use strict';

const { Types: { ObjectId } } = require('mongoose');

const PORTAL_EXIT_INVALID = 'REBUILD_PORTAL_EXIT_INVALID';
const invalid = () => Object.assign(new Error(PORTAL_EXIT_INVALID), { code: PORTAL_EXIT_INVALID });

function normalizeRebuildExitNodeId(value) {
    if (value === null) return null;
    let id = value;
    if (value instanceof ObjectId) {
        try { id = ObjectId.prototype.toHexString.call(value); }
        catch { throw invalid(); }
    }
    if (typeof id !== 'string' || id.length !== 24 || !/^[a-f0-9]+$/.test(id)) {
        throw invalid();
    }
    return id;
}

// Accept lean BSON records or wire objects, not coerced booleans, populated
// references, or ObjectId-like objects with a caller-supplied method.
function normalizeRebuildExit(value) {
    if (value == null) return value;
    const proto = Object.getPrototypeOf(value);
    if ((proto !== Object.prototype && proto !== null) || !Object.hasOwn(value, 'nodeId')
        || Reflect.ownKeys(value).some(key => key !== 'nodeId' && key !== 'relayGeo')
        || (Object.hasOwn(value, 'relayGeo') && typeof value.relayGeo !== 'boolean')) {
        throw invalid();
    }
    return { nodeId: normalizeRebuildExitNodeId(value.nodeId), relayGeo: value.relayGeo ?? true };
}

module.exports = { normalizeRebuildExit, normalizeRebuildExitNodeId, PORTAL_EXIT_INVALID };
