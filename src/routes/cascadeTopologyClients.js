'use strict';

const Admin = require('../models/adminModel');
const syncService = require('../services/syncService');
const { checkIpWhitelist } = require('./panel/helpers');
const { detectLanguage } = require('../middleware/i18n');

const path = '/api/cascade/topology/clients';

function noStore(_req, res, next) {
    res.set('Cache-Control', 'no-store');
    next();
}

function requireAdminSession(req, res, next) {
    // Reject credential-bearing requests even if they also carry a valid cookie.
    // Do not run the generic API-key middleware (usage writes, key scopes, logs).
    if (req.apiKey || req.headers['x-api-key'] !== undefined || req.headers.authorization !== undefined) {
        return res.status(403).json({ error: 'Admin session required' });
    }
    const username = req.session?.adminUsername;
    if (req.session?.authenticated !== true || !req.sessionID || typeof username !== 'string' || !username.trim()) {
        return res.status(401).json({ error: 'Admin session required' });
    }
    return next();
}

function queryNodeId(url) {
    const start = url.indexOf('?');
    if (start < 0) return null;
    const query = [...new URLSearchParams(url.slice(start + 1))];
    if (query.length !== 1 || query[0][0] !== 'nodeId' || !/^[0-9a-f]{24}$/i.test(query[0][1])
        || query[0][1].length !== 24) return null;
    return query[0][1].toLowerCase();
}

async function listClients(req, res) {
    const nodeId = queryNodeId(req.originalUrl);
    if (!nodeId) return res.status(400).json({ error: 'Expected a single nodeId (24 hex characters)' });
    try {
        if (!await Admin.exists({ username: req.session.adminUsername })) {
            return res.status(403).json({ error: 'Admin session required' });
        }
        const locale = detectLanguage(req);
        const { state, rows } = await syncService.readXrayClientConnections(nodeId,
            ip => require('../services/geoIpService').lookup(ip, locale));
        res.set('X-Client-Connections-State', state);
        // Do not generate an ETag/fingerprint for the private response or
        // let conditional requests turn distinct [] states into a 304.
        return res.type('application/json').end(JSON.stringify(rows));
    } catch {
        // Do not pass an exception/partially enriched row to Express's logger.
        res.set('X-Client-Connections-State', 'unavailable');
        return res.status(503).json([]);
    }
}

function mountClientsRoute(app) {
    app.get(path, noStore, requireAdminSession, checkIpWhitelist, listClients);
}

module.exports = { path, noStore, mountClientsRoute };
