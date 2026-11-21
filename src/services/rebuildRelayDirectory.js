'use strict';

const { randomUUID } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { validLogin } = require('./rebuildRelayBackendDesired');

const collectionName = 'c3_rebuild_relay_accounts';
const selector = { _id: 'directory' };
const bootstrap = 'relay-bootstrap';
const conflict = () => Object.assign(new Error('REBUILD_L2TP_ACCOUNT_SOURCE_CONFLICT'), { code: 'REBUILD_L2TP_ACCOUNT_SOURCE_CONFLICT' });

// The _id namespace is disjoint from the existing pending-operation singleton.
// A directory identity is not a relay or replica reference, even when it was
// initially copied from a legacy account id. Projection IPs/revisions stay local.
async function readDirectory(db, session, publicOnly = false) {
    const directory = await db.collection(collectionName).findOne(selector, {
        maxTimeMS: 5000,
        ...(session ? { session } : { readPreference: 'primary', readConcern: { level: 'majority' } }),
        ...(publicOnly && { projection: { _id: 1, version: 1, generation: 1, 'accounts.id': 1, 'accounts.login': 1, 'accounts.enabled': 1 } }),
    });
    if (directory === null) return null;
    if (directory?._id !== selector._id || directory.version !== 1 || typeof directory.generation !== 'string'
        || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}(?![\s\S])/.test(directory.generation)
        || !Array.isArray(directory.accounts) || directory.accounts.length > 2048) throw conflict();
    const ids = new Set(), logins = new Set();
    for (const row of directory.accounts) {
        const { id, login, enabled, passwordEncrypted } = row ?? {};
        if (typeof id !== 'string' || !/^[a-f0-9]{24}(?![\s\S])/.test(id) || ids.has(id)
            || !validLogin(login) || logins.has(login) || typeof enabled !== 'boolean'
            || (!publicOnly && (typeof passwordEncrypted !== 'string' || !passwordEncrypted))) throw conflict();
        ids.add(id); logins.add(login);
    }
    if (!directory.accounts.some(row => row.login === bootstrap && row.enabled)) throw conflict();
    return directory;
}

const logicalAccount = row => ({ id: String(row._id), login: row.login, enabled: row.enabled, passwordEncrypted: row.passwordEncrypted });
function sameAccounts(catalog, rows, ciphertext = true) {
    const byLogin = new Map(rows.map(row => [row.login, row]));
    return catalog.length === rows.length && byLogin.size === rows.length && catalog.every(row => {
        const candidate = byLogin.get(row.login);
        return candidate && row.enabled === candidate.enabled && (!ciphertext || row.passwordEncrypted === candidate.passwordEncrypted);
    });
}

async function checkDirectory(db, expected, session) {
    if (!equal(await readDirectory(db, session), expected)) throw conflict();
}

async function writeDirectory(db, before, rows, session) {
    const accounts = [...rows].sort((a, b) => (a.login > b.login) - (a.login < b.login));
    const fields = { version: 1, generation: randomUUID(), accounts };
    const document = { ...selector, ...fields };
    const options = session ? { session } : { writeConcern: { w: 'majority' } };
    // Absence is not an upsert match: a concurrent initializer must hit _id's
    // unique index, never match/adopt it. Multi forms do not retry writes.
    const filter = before
        ? { ...selector, $expr: { $eq: ['$$ROOT', { $literal: before }] } }
        : { ...selector, generation: fields.generation };
    const result = await db.collection(collectionName).updateMany(filter, before ? { $set: fields } : { $setOnInsert: document },
        { ...options, ...(!before && { upsert: true }) });
    if (result?.acknowledged !== true || result[before ? 'matchedCount' : 'upsertedCount'] !== 1) throw conflict();
    return document;
}

module.exports = { collectionName, readDirectory, checkDirectory, writeDirectory, logicalAccount, sameAccounts, conflict };
