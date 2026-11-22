/**
 * Hysteria + Xray nodes sync service
 *
 * Hysteria: HTTP auth callback — no user sync needed, auth happens in realtime.
 * Xray: managed via CC Agent HTTP API (add/remove users, traffic stats, health).
 *       SSH is only used for full config uploads (rare: node setup / config changes).
 *
 * This service handles:
 * - Node config updates (Hysteria YAML / Xray JSON)
 * - Traffic stats collection
 * - Node health checks
 * - Xray user add/remove via Agent HTTP API (no SSH per-operation)
 */

const HyUser = require('../models/hyUserModel');
const HyNode = require('../models/hyNodeModel');
const Settings = require('../models/settingsModel');
const RelayL2tpState = require('../modules/relay-l2tp/models/relayL2tpStateModel');
const { mergePreservedL2tpConfig } = require('../modules/relay-l2tp/domain/l2tpXrayConfigMerge');
const { APPLIED_LINK_STATUSES, usesTestTopologyConfig, topologyManagesNodeConfig } = require('./topologyConfigOwnership');
const { withClassicNodeConfigWrite } = require('./classicNodeConfigWrite');
const { finishClassicConfigRouting } = require('./classicL2tpConfigComposition');
const { resolveL2tpExecutionAuthorization } = require('../modules/relay-l2tp/domain/l2tpExecutionAuthorization');
const NodeSSH = require('./nodeSSH');
const configGenerator = require('./configGenerator');
const cache = require('./cacheService');
const { invalidateNodesCache, invalidateUserCache } = require('../utils/helpers');
const logger = require('../utils/logger');
const axios = require('axios');
const https = require('https');
const { performance } = require('node:perf_hooks');
const config = require('../../config');
const webhook = require('./webhookService');
const { extractXrayOnlineUserIds } = require('../utils/userClientStats');
const nodeSetup = require('./nodeSetup');
const { getPanelCertificates, isSameVpsAsPanel } = nodeSetup;
const {
    extractAgentOnlineUserIds,
    mergeNodeOnlineContributions,
} = require('../utils/agentOnlineState');

// HTTPS agent that ignores self-signed certs (agent uses self-signed cert by default)
const selfSignedAgent = new https.Agent({ rejectUnauthorized: false });

// Mark node offline after this many consecutive health check failures (1 check/min)
const HEALTH_FAILURE_THRESHOLD = 3;

// Fields whose change requires regenerating the runtime config on the node.
// Anything not listed here (name, groups, flag, rankingCoefficient, ssh.*, ...)
// is treated as cosmetic and does not trigger an auto-push.
// Dotted keys (e.g. "xray.realityPrivateKey") are matched via their root.
const CONFIG_AFFECTING_FIELDS = new Set([
    // Shared
    'domain', 'sni', 'port', 'portRange', 'statsPort', 'statsSecret',
    'useCustomConfig', 'customConfig',
    // Hysteria
    'obfs', 'hopInterval', 'acme', 'masquerade', 'bandwidth',
    'ignoreClientBandwidth', 'speedTest', 'disableUDP', 'udpIdleTimeout',
    'sniff', 'quic', 'resolver', 'acl', 'aclRules', 'outbounds', 'useTlsFiles',
    // Xray (any xray.* sub-path triggers regeneration)
    'xray',
]);

function hasConfigRelevantUpdates(updates) {
    // null/undefined means "unknown" — err on the side of pushing.
    if (!updates) return true;
    const keys = Object.keys(updates);
    if (keys.length === 0) return false;
    return keys.some(k => {
        const root = k.split('.')[0];
        return CONFIG_AFFECTING_FIELDS.has(k) || CONFIG_AFFECTING_FIELDS.has(root);
    });
}

/**
 * The manualKey field is select:false at the schema level. When sync code
 * receives a node loaded by another caller (panel route, scheduled job),
 * the private key is therefore absent. For nodes using tlsSource==='manual'
 * we must lazy-load it before generating config — without it the inlined
 * tlsSettings.certificates[0].key would be empty and Xray would refuse to
 * start with a TLS handshake error.
 *
 * Mutates `node.xray.manualKey` in place when needed; otherwise no-op.
 *
 * @param {Object} node - HyNode document or plain object
 */
async function ensureManualKeyLoaded(node) {
    const xray = node?.xray;
    if (!xray) return;
    if (xray.tlsSource !== 'manual') return;
    if (xray.manualKey && String(xray.manualKey).trim().length > 0) return;
    try {
        const fresh = await HyNode.findById(node._id).select('+xray.manualKey').lean();
        const key = fresh?.xray?.manualKey || '';
        if (key) {
            // node.xray may be a Mongoose subdoc — assign directly.
            xray.manualKey = key;
        }
    } catch (err) {
        logger.warn(`[Sync] Failed to lazy-load manualKey for node ${node.name || node._id}: ${err.message}`);
    }
}

// ─── Panel certificate rotation watcher ──────────────────────────────────────
//
// When Caddy/Greenlock renews the panel's LE certificate the on-disk file
// changes. Xray nodes that masquerade under the panel domain
// (xray.tlsSource === 'panel') need to receive an updated config.json with the
// new inline PEM, otherwise their TLS cert grows stale within ~24h of expiry.
//
// Poll cert mtime on cron; on change, invalidate cache and re-push to all
// panel-source nodes. mtime advances only when every push succeeds; failed
// nodes are retried with exponential backoff (capped) on subsequent ticks.
let _lastPanelCertMtime = null;
const _failedNodeBackoff = new Map(); // nodeId -> { attempts, nextAttemptAt }
const _MAX_RETRY_ATTEMPTS = 6;
const _BACKOFF_BASE_MS = 5 * 60 * 1000;

async function checkPanelCertRotation(syncInstance) {
    const fs = require('fs');
    const path = require('path');
    const domain = (config?.PANEL_DOMAIN || '').trim();
    if (!domain) return;
    const candidates = [
        path.join('/caddy_data/caddy/certificates/acme-v02.api.letsencrypt.org-directory', domain, `${domain}.crt`),
        path.join(__dirname, '../../greenlock.d/live', domain, 'fullchain.pem'),
    ];
    let currentMtime = 0;
    let foundPath = '';
    for (const candidate of candidates) {
        try {
            const stat = fs.statSync(candidate);
            currentMtime = stat.mtimeMs;
            foundPath = candidate;
            break;
        } catch (_) { /* try next */ }
    }
    if (!foundPath) return;

    if (_lastPanelCertMtime === null) {
        _lastPanelCertMtime = currentMtime;
        return;
    }

    // Fresh cert → full sweep; same mtime + pending retries → retry-only sweep.
    const certIsFresh = currentMtime > _lastPanelCertMtime;
    const hasPendingRetries = _failedNodeBackoff.size > 0;
    if (!certIsFresh && !hasPendingRetries) return;

    if (certIsFresh) {
        logger.info(`[CertWatch] Panel certificate mtime changed (${foundPath}), pushing config to panel-source Xray nodes`);
        try {
            const configGen = require('./configGenerator');
            if (typeof configGen.invalidatePanelCertCache === 'function') {
                configGen.invalidatePanelCertCache();
            }
        } catch (_) { /* configGen may not be loaded yet at first invocation */ }
    } else {
        logger.info(`[CertWatch] Retrying ${_failedNodeBackoff.size} previously-failed cert push(es)`);
    }

    let nodes;
    try {
        nodes = await HyNode.find({
            type: 'xray',
            active: true,
            'xray.security': 'tls',
            'xray.tlsSource': 'panel',
        });
    } catch (err) {
        logger.error(`[CertWatch] Failed to list panel-source nodes: ${err.message}`);
        return;
    }
    if (!nodes || nodes.length === 0) {
        logger.info('[CertWatch] No panel-source Xray nodes to update');
        if (certIsFresh) _lastPanelCertMtime = currentMtime;
        _failedNodeBackoff.clear();
        return;
    }

    const now = Date.now();
    let targets;
    if (certIsFresh) {
        _failedNodeBackoff.clear();
        targets = nodes;
    } else {
        targets = nodes.filter(n => {
            const entry = _failedNodeBackoff.get(String(n._id));
            return entry && entry.nextAttemptAt <= now;
        });
        if (targets.length === 0) return;
    }

    const CONCURRENCY = 4;
    let cursor = 0;
    const total = targets.length;
    let failures = 0;
    const stillPending = new Set();
    const worker = async () => {
        while (cursor < total) {
            const idx = cursor++;
            const node = targets[idx];
            const id = String(node._id);
            try {
                await syncInstance.updateXrayNodeConfig(node);
                _failedNodeBackoff.delete(id);
                logger.info(`[CertWatch] Pushed renewed cert to ${node.name} (${node.ip})`);
            } catch (err) {
                failures++;
                const prev = _failedNodeBackoff.get(id) || { attempts: 0, nextAttemptAt: 0 };
                const attempts = prev.attempts + 1;
                const delay = _BACKOFF_BASE_MS * Math.min(16, Math.pow(2, Math.max(0, attempts - 1)));
                _failedNodeBackoff.set(id, { attempts, nextAttemptAt: now + delay });
                stillPending.add(id);
                if (attempts >= _MAX_RETRY_ATTEMPTS) {
                    logger.error(`[CertWatch] Push failed for ${node.name} (${node.ip}) [attempt ${attempts}, giving up until next rotation]: ${err.message}`);
                } else {
                    logger.warn(`[CertWatch] Push failed for ${node.name} (${node.ip}) [attempt ${attempts}, retry in ${Math.round(delay / 1000)}s]: ${err.message}`);
                }
            }
        }
    };
    const workers = Array.from({ length: Math.min(CONCURRENCY, total) }, () => worker());
    await Promise.all(workers);

    // Advance mtime only on a fully clean sweep so the next tick re-enters
    // when any node still has pending failures.
    if (failures === 0) {
        _lastPanelCertMtime = currentMtime;
        logger.info(`[CertWatch] Panel cert rotation push completed for ${total} node(s)`);
    } else {
        logger.warn(`[CertWatch] ${failures}/${total} cert push(es) failed; will retry on next tick (mtime kept at ${_lastPanelCertMtime})`);
    }
}

class SyncService {
    constructor() {
        this.isSyncing = false;
        this.lastSyncTime = null;
        this.xrayUserStatsSnapshots = new Map();
        this.xrayNodeOnlineUsers = new Map();
        this.xrayNodeUserLastActive = new Map();
    }

    /**
     * Get HTTP auth URL
     */
    getAuthUrl() {
        return `${config.BASE_URL}/api/auth`;
    }

    // ==================== XRAY AGENT METHODS ====================

    /**
     * Make an authenticated HTTP request to the CC Agent on a node.
     * Uses HTTPS if agentTls !== false, HTTP otherwise.
     * Self-signed certificates are accepted.
     */
    async _agentRequest(node, method, path, body = null) {
        if (require('./rebuildMode').isRebuildEnabled() && method !== 'GET') {
            return require('./rebuildLocks').withNode(node._id, () => this._sendAgentRequest(node, method, path, body));
        }
        return this._sendAgentRequest(node, method, path, body);
    }

    async _sendAgentRequest(node, method, path, body, directRead) {
        const xray = node.xray || {};
        const useTls = xray.agentTls !== false;
        const port = xray.agentPort || 62080;
        const token = xray.agentToken;

        if (!token) {
            throw new Error(`[Agent] Node ${node.name} has no agentToken — install agent first`);
        }

        const protocol = useTls ? 'https' : 'http';
        let host = node.ip;
        if (directRead) {
            const ipVersion = require('node:net').isIP(host);
            if (ipVersion === 6) host = `[${host}]`;
            else if (typeof host !== 'string' || !/^[a-z0-9.-]+$/i.test(host)) throw new Error('Invalid agent host');
            if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid agent port');
        }
        const url = `${protocol}://${host}:${port}${path}`;

        const options = {
            method,
            url,
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
            },
            timeout: 15000,
            maxRedirects: 0,
            validateStatus: null, // handle errors manually
        };

        if (body !== null) {
            options.data = body;
        }

        if (useTls) {
            options.httpsAgent = selfSignedAgent;
        }

        const signal = directRead && AbortSignal.timeout(directRead.timeout);
        if (directRead) {
            // The observation challenge and bearer must stay at the configured
            // receiving agent. This GET has a total deadline and never retries.
            Object.assign(options, {
                proxy: false, maxRedirects: 0, timeout: directRead.timeout,
                signal, maxContentLength: 1024,
                responseType: 'text', transformResponse: [bytes => bytes],
            });
            options.headers.Accept = 'application/json';
            options.headers['Cache-Control'] = 'no-store';
        }

        let response;
        try { response = await axios(options); }
        catch (error) {
            // Axios reports our absolute deadline as cancellation, not as its
            // socket timeout. Require an attempted request and no HTTP reply.
            if (signal?.aborted && error?.code === 'ERR_CANCELED' && axios.isCancel(error)
                && error.request && !error.request.res && !error.response) {
                throw Object.assign(new Error('Agent observation timed out'), { code: 'AGENT_OBSERVATION_TIMEOUT' });
            }
            throw error;
        }

        if (response.status === 401) {
            const error = new Error(`[Agent] Unauthorized — check agentToken for node ${node.name}`);
            error.code = 'AGENT_HTTP_ERROR';
            error.httpStatus = 401;
            throw error;
        }
        if (!Number.isInteger(response.status) || response.status < 200 || response.status >= 300) {
            // Never include the agent's response body: it may contain secrets.
            const error = new Error(`[Agent] HTTP ${Number.isInteger(response.status) ? response.status : 'unknown'} for node ${node.name}`);
            error.code = 'AGENT_HTTP_ERROR';
            error.httpStatus = response.status;
            throw error;
        }

        return response;
    }

    readRebuildReverseObservation(node, path, timeout) {
        return this._sendAgentRequest(node, 'GET', path, null, { timeout });
    }

    // Read-only, safe to use from GET routes. Neither liveness nor legacy
    // /stats (identical zero counters on success and failure) proves Xray.
    async probeXrayHealth(node) {
        const unknown = { online: false, xrayStatus: 'unknown', agentStatus: 'unknown', info: {} };
        if (!node.xray?.agentToken) {
            return { ...unknown, lastError: 'Xray health unknown: no agent token configured' };
        }
        const [probe, metadata] = await Promise.allSettled([
            this._agentRequest(node, 'GET', '/xray-health'),
            this._agentRequest(node, 'GET', '/info'),
        ]);
        const info = {};
        const data = metadata.value?.data;
        if (metadata.value?.status === 200 && typeof data?.agent_version === 'string' && data.agent_version) {
            for (const key of ['agent_version', 'xray_version', 'last_sync']) {
                if (typeof data[key] === 'string' && data[key].length <= 256) info[key] = data[key];
            }
            for (const key of ['users_count', 'uptime_seconds']) {
                if (Number.isSafeInteger(data[key]) && data[key] >= 0) info[key] = data[key];
            }
            if (typeof data.access_logs?.enabled === 'boolean') {
                info.access_logs = { enabled: data.access_logs.enabled };
                for (const key of ['spool_bytes', 'spool_batches', 'lag_bytes', 'dropped_events']) {
                    if (Number.isSafeInteger(data.access_logs[key])) info.access_logs[key] = data.access_logs[key];
                }
            }
        }

        const xrayStatus = probe.value?.data?.xray_status;
        if (probe.value?.status === 200 && (xrayStatus === 'online' || xrayStatus === 'offline')) {
            return { online: xrayStatus === 'online', xrayStatus, agentStatus: 'online', info,
                lastError: xrayStatus === 'online' ? '' : 'Xray runtime API unavailable' };
        }

        const agentStatus = (info.agent_version || probe.value?.status === 200) ? 'online' : 'offline';
        const httpStatus = probe.reason?.httpStatus;
        const transient = probe.status === 'rejected' && probe.reason?.code !== 'AGENT_HTTP_ERROR';
        const transientCode = ['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ECONNABORTED'].includes(probe.reason?.code)
            ? ` (${probe.reason.code})` : '';
        let detail = 'agent returned no Xray health proof';
        if (transient) detail = `agent health request failed${transientCode}`;
        else if (httpStatus === 404 || httpStatus === 405) detail = 'agent does not support Xray health checks';
        else if (Number.isInteger(httpStatus)) detail = `agent health request returned HTTP ${httpStatus}`;
        return { ...unknown, agentStatus, info, transient, lastError: `Xray health unknown: ${detail}` };
    }

    // Durable status writer shared by periodic refresh and explicit operations.
    // Debounce panel-to-agent transport failures, not a local Xray failure or
    // a legacy response that cannot establish health. Explicit checks require
    // a fresh proof, so a transport failure there saves unknown, not offline.
    async checkXrayAgentHealth(node, { requireProof = false, lastSync, writeOptions = {}, verify } = {}) {
        const startedAt = new Date();
        const health = await this.probeXrayHealth(node);
        const filter = { _id: node._id, type: 'xray', ip: node.ip,
            // An older in-flight response must not heal a node after a newer
            // authenticated observation (or undo that observation's recovery).
            $or: [{ agentLastSeen: null }, { agentLastSeen: { $lte: startedAt } }],
        };
        if (typeof node.active === 'boolean') filter.active = node.active;
        filter['xray.agentToken'] = node.xray?.agentToken || { $in: [null, ''] };
        const fields = { agentStatus: health.agentStatus, lastError: health.lastError };
        if (lastSync) fields.lastSync = lastSync;
        if (health.agentStatus === 'online') fields.agentLastSeen = startedAt;
        if (health.info.xray_version) fields.xrayVersion = health.info.xray_version;
        if (health.info.agent_version) fields.agentVersion = health.info.agent_version;
        if (!health.transient || requireProof) {
            fields.status = health.xrayStatus;
            fields.healthFailures = 0;
            if (!health.online) fields.onlineUsers = 0;
        }

        await verify?.();
        let previous = await HyNode.findOneAndUpdate(filter,
            health.transient && !requireProof ? { $set: fields, $inc: { healthFailures: 1 } } : { $set: fields },
            { ...writeOptions, projection: { status: 1, healthFailures: 1, lastError: 1, onlineUsers: 1 } });
        if (!previous) return { ...health, online: false, xrayStatus: 'unknown',
            lastError: 'Xray health unknown: node changed during check' };
        let status = fields.status;
        if (health.transient && !requireProof && (previous.healthFailures || 0) + 1 >= HEALTH_FAILURE_THRESHOLD) {
            // Don't overwrite a newer successful sample that reset the counter.
            previous = await HyNode.findOneAndUpdate(
                { ...filter, status: 'online', healthFailures: { $gte: HEALTH_FAILURE_THRESHOLD } },
                { $set: { status: 'offline', onlineUsers: 0 } },
                { ...writeOptions, projection: { status: 1, lastError: 1 } });
            status = 'offline';
        }
        if (previous && (status === 'offline' || status === 'unknown')) {
            const key = String(node._id);
            this.xrayUserStatsSnapshots.delete(key);
            this.xrayNodeUserLastActive.delete(key);
            // Reject in-flight online samples taken before confirmed demotion.
            this.xrayNodeOnlineUsers.set(key, { ids: [], observedAt: performance.now() });
        }
        if (previous && ((status && previous.status !== status) || previous.lastError !== fields.lastError ||
            (fields.onlineUsers === 0 && previous.onlineUsers > 0))) {
            await invalidateNodesCache();
            if (status === 'online' && previous.status !== 'online') {
                webhook.emit(webhook.EVENTS.NODE_ONLINE, { nodeId: node._id, name: node.name });
            } else if (status === 'offline' && previous.status === 'online') {
                webhook.emit(webhook.EVENTS.NODE_OFFLINE, { nodeId: node._id, name: node.name, lastError: health.lastError });
            }
        }
        return health;
    }

    async refreshXraySetupHealth(node, { agentToken, writeOptions, verify } = {}) {
        // setupXrayNodeWithAgent may have saved the token on another document.
        const target = agentToken ? {
            _id: node._id, active: node.active, ip: node.ip, name: node.name,
            xray: { agentToken, agentTls: node.xray?.agentTls, agentPort: node.xray?.agentPort },
        } : node;
        return this.checkXrayAgentHealth(target, { requireProof: true, lastSync: new Date(), writeOptions, verify });
    }

    async finishXraySetup(node, logs = [], { restartService = true, ...options } = {}) {
        const health = await this.refreshXraySetupHealth(node, options);
        const result = { success: true, logs: [...logs], xray_status: health.xrayStatus,
            xray_verification: health.xrayStatus === 'unknown' ? 'unavailable' : 'available' };

        if (health.xrayStatus === 'offline' && restartService !== false) {
            result.success = false;
            result.error = health.lastError;
            result.logs.push(`[FAIL] ${result.error}`);
            logger.warn(`[Xray Setup] ${node.name}: ${result.error}`);
        } else if (health.xrayStatus === 'unknown' || health.xrayStatus === 'offline') {
            result.warning = health.xrayStatus === 'unknown' ? health.lastError
                : `${health.lastError} (service restart was not requested)`;
            result.logs.push(`[Warning] ${result.warning}`);
            logger.warn(`[Xray Setup] ${node.name}: ${result.warning}`);
        } else {
            result.logs.push('[OK] Xray runtime API verified');
        }
        return result;
    }

    /**
     * Add a single user to a running Xray node via Agent HTTP API.
     * No SSH, no restart needed.
     */
    async addXrayUser(node, user) {
        if (!user.xrayUuid) {
            logger.warn(`[Agent] User ${user.userId} has no xrayUuid, skipping`);
            return false;
        }

        const xray = node.xray || {};
        const flow = ((xray.security === 'reality' || xray.security === 'tls') && xray.transport === 'tcp')
            ? (xray.flow || 'xtls-rprx-vision')
            : '';

        try {
            await this._agentRequest(node, 'POST', '/users', {
                id: user.xrayUuid,
                email: user.userId,
                flow,
            });
            logger.info(`[Agent] Added user ${user.userId} to ${node.name}`);
            return true;
        } catch (error) {
            logger.error(`[Agent] addXrayUser ${node.name}/${user.userId}: ${error.message}`);
            return false;
        }
    }

    /**
     * Remove a single user from a running Xray node via Agent HTTP API.
     * No SSH, no restart needed.
     */
    async removeXrayUser(node, user) {
        try {
            await this._agentRequest(node, 'DELETE', `/users/${encodeURIComponent(user.userId)}`);
            logger.info(`[Agent] Removed user ${user.userId} from ${node.name}`);
            return true;
        } catch (error) {
            logger.error(`[Agent] removeXrayUser ${node.name}/${user.userId}: ${error.message}`);
            return false;
        }
    }

    /**
     * Get all enabled users for a given node (by groups or explicit node list)
     */
    async _getUsersForNode(node) {
        const nodeId = node._id.toString();
        // Users with explicit node assignment
        const byNodes = await HyUser.find({ nodes: node._id, enabled: true }).lean();
        // Users linked via groups
        const nodeGroupIds = (node.groups || []).map(g => g._id?.toString() || g.toString());
        const noExplicitNodes = {
            $or: [
                { nodes: { $size: 0 } },
                { nodes: { $exists: false } },
            ],
        };
        let byGroups = [];
        if (nodeGroupIds.length > 0) {
            byGroups = await HyUser.find({ groups: { $in: node.groups }, enabled: true, ...noExplicitNodes }).lean();
        } else {
            // Node has no groups — all users without group assignment
            byGroups = await HyUser.find({ enabled: true, groups: { $size: 0 }, ...noExplicitNodes }).lean();
        }
        // Merge and deduplicate by userId
        const seen = new Set();
        return [...byNodes, ...byGroups].filter(u => {
            if (seen.has(u.userId)) return false;
            seen.add(u.userId);
            return true;
        });
    }

    /**
     * Resolve the full downstream forward-chain path for an Xray node.
     * Delegates to cascadeService to avoid duplication.
     *
     * @param {string|ObjectId} startNodeId
     * @returns {Promise<Array>}
     */
    async _getForwardChainLinks(startNodeId, allowedStatuses) {
        const cascadeService = require('./cascadeService');
        return cascadeService._getForwardChainLinks(startNodeId, new Set(), allowedStatuses);
    }

    /**
     * Share config ownership with the cascade writer. Durable server operation
     * evidence vetoes classic rewrites independently of execution flags; only
     * the paired TEST installation retains applied-link compatibility.
     */
    async _topologyManagesNode(node) {
        return topologyManagesNodeConfig(node);
    }

    /**
     * Add user to all active Xray nodes they belong to (fire-and-forget safe)
     */
    async addUserToAllXrayNodes(user) {
        const xrayNodes = await HyNode.find({ type: 'xray', active: true });
        for (const node of xrayNodes) {
            const nodeUsers = await this._getUsersForNode(node);
            const belongs = nodeUsers.some(u => u.userId === user.userId);
            if (belongs) {
                this.addXrayUser(node, user).catch(() => {});
            }
        }
    }

    /**
     * Remove user from all active Xray nodes (fire-and-forget safe)
     */
    async removeUserFromAllXrayNodes(user) {
        const xrayNodes = await HyNode.find({ type: 'xray', active: true });
        for (const node of xrayNodes) {
            this.removeXrayUser(node, user).catch(() => {});
        }
    }

    /**
     * Full config update for an Xray node.
     *
     * Step 1: Upload xray config.json via SSH (inbound/outbound settings, no user list).
     * Step 2: Restart Xray via Agent API (no SSH restart needed).
     * Step 3: Sync all users to Xray runtime via Agent /sync endpoint.
     *
     * SSH is only used for the config upload. If agent is not yet installed,
     * falls back to SSH restart.
     */
    async updateXrayNodeConfig(node) {
        if (require('./rebuildMode').isRebuildEnabled()) {
            const { withNode } = require('./rebuildLocks');
            const { withNodeWrite, nodeWriteVerifier, assertRelaySetupAllowed } = require('./rebuildRelayRoleGuard');
            const manages = async current => !!(current.cascadeRole && current.cascadeRole !== 'standalone'
                || await require('../models/cascadeLinkModel').exists({
                    $or: [{ portalNode: current._id }, { bridgeNode: current._id }], active: true,
                }));
            const sync = (current, topologyManaged) => this.#updateXrayNodeConfig(current, {
                topologyManaged, allowedStatuses: undefined, fenced: true,
            });
            const syncUnderApply = async (current, verify) => {
                if (!current || current.type !== 'xray') return false;
                const managed = await manages(current);
                if (!managed) await assertRelaySetupAllowed(current);
                await verify();
                return sync(current, managed);
            };
            // Enable/Restart already own Apply and the node lock and supplied
            // the fresh, fenced card. Do not try to acquire Apply underneath it.
            const verifyRebuildWrite = nodeWriteVerifier(node);
            if (verifyRebuildWrite) return syncUnderApply(node, verifyRebuildWrite);

            // The user-only path keeps the per-node lock. Re-read here so a
            // queued standalone snapshot cannot overwrite a newly owned relay.
            const managed = await withNode(node._id, async () => {
                const current = await HyNode.findById(node._id).read('primary').readConcern('majority').maxTimeMS(5000);
                if (!current || current.type !== 'xray') return { result: false };
                return await manages(current) ? { result: await sync(current, true) } : null;
            });
            if (managed) return managed.result;
            // Standalone Sync can upload a complete profile. Release the local
            // lock before entering the normal Apply -> node acquisition order.
            return await withNodeWrite(node._id, (_, current, verify) => syncUnderApply(current, verify)) ?? false;
        }
        logger.info(`[Xray Sync] Updating config for node ${node.name} (${node.ip})`);
        const writerEnv = Object.freeze({ ...process.env });
        const allowedStatuses = usesTestTopologyConfig(node) ? APPLIED_LINK_STATUSES : undefined;
        // Select the server policy before the first async boundary. A failed
        // ownership read must not authorize a classic rewrite.
        const topologyManaged = await this._topologyManagesNode(node);
        const fenced = !topologyManaged && resolveL2tpExecutionAuthorization(writerEnv).enableInstallAdmission;
        const update = () => this.#updateXrayNodeConfig(node, { topologyManaged, allowedStatuses, fenced });
        // Managed nodes keep their existing user-only path. Classic writers
        // recheck the durable veto inside the acquired generation before work.
        return topologyManaged ? update() : withClassicNodeConfigWrite({
            nodeId: node._id, kind: 'sync-xray', env: writerEnv,
        }, update);
    }

    async #updateXrayNodeConfig(node, { topologyManaged, allowedStatuses, fenced }) {
        // Keep the old best-effort behavior dormant, but never turn a swallowed
        // error/nonzero/unknown remote completion into verified fence release.
        let completionFailed = false;
        const createSSH = () => {
            const ssh = new NodeSSH(node);
            if (fenced) {
                const exec = ssh.exec.bind(ssh);
                ssh.exec = async (...args) => {
                    try {
                        const result = await exec(...args);
                        if (result?.code !== 0) throw new Error('CLASSIC_CONFIG_COMMAND_UNCERTAIN');
                        return result;
                    } catch (error) { completionFailed = true; throw error; }
                };
                const upload = ssh.uploadContent.bind(ssh);
                ssh.uploadContent = async (...args) => {
                    try {
                        const result = await upload(...args);
                        // NodeSSH's checked WRITE+CLOSE upload resolves void.
                        if (result !== undefined) throw new Error('CLASSIC_CONFIG_UPLOAD_UNCERTAIN');
                    } catch (error) { completionFailed = true; throw error; }
                };
            }
            return ssh;
        };
        await HyNode.updateOne({ _id: node._id }, { $set: { status: 'syncing' } });

        // Resolve ownership before generation: topology config may use a
        // different certificate and must never be rebuilt by classic Sync.
        if (!topologyManaged) await ensureManualKeyLoaded(node);

        const users = await this._getUsersForNode(node);

        // Bail out early on cert-availability errors only when classic Sync
        // owns the config; topology-managed nodes still sync users via agent.
        let configContent;
        if (!topologyManaged) {
            try {
                configContent = configGenerator.generateXrayConfigWithApi(node, users);
            } catch (genErr) {
                if (genErr.code === 'PANEL_CERT_UNAVAILABLE' || genErr.code === 'MANUAL_CERT_UNAVAILABLE') {
                    logger.error(`[Xray Sync] Node ${node.name}: skipping push — ${genErr.message}`);
                    await HyNode.updateOne({ _id: node._id }, {
                        $set: {
                            status: 'error',
                            lastSync: new Date(),
                            lastError: genErr.message,
                        },
                    });
                    await invalidateNodesCache();
                    return false;
                }
                throw genErr;
            }
        }

        // Step 1: Upload config.json via SSH (only if SSH is configured).
        // Skipped for topology-managed nodes: the topology deployment owns
        // the full Xray config there, and a classic rewrite would clobber
        // its cascade structure (and used the persisted link.tunnelUuid,
        // which mismatches the deterministic tunnel credentials the
        // topology composer puts on the other end of the link).
        if (topologyManaged) {
            logger.info(`[Xray Sync] Node ${node.name}: config upload and restart skipped (topology-managed node)`);
        }
        if (!topologyManaged && (node.ssh?.password || node.ssh?.privateKey)) {
            const ssh = createSSH();
            try {
                await ssh.connect();

                // Apply cascade settings (reverse-portal + forward-chain + forward-hop inbounds)
                try {
                    const CascadeLink = require('../models/cascadeLinkModel');
                    if (!allowedStatuses) {
                        const { MAIN, BRIDGE, readClassicProfile, selectClassicMain } = require('./classicAppliedConfig');
                        const current = await readClassicProfile(ssh, MAIN);
                        const portalLinks = await CascadeLink.find({ portalNode: node._id, active: true }).populate('bridgeNode');
                        const hopLinks = await CascadeLink.find({ bridgeNode: node._id, active: true }).populate('portalNode');
                        const forwardLinks = await CascadeLink.find({ mode: 'forward', active: true }).populate('bridgeNode');
                        const bridgeCurrent = portalLinks.some(link => link.mode !== 'forward') && hopLinks.some(link => link.mode !== 'forward')
                            ? await readClassicProfile(ssh, BRIDGE, { allowAbsent: true }) : null;
                        const selection = selectClassicMain({ node, current, bridgeCurrent, portalLinks, hopLinks, forwardLinks });
                        const composed = selection.compose(JSON.parse(configContent));
                        await require('./cascadeService')._applyClassicL2tpPathIngress(composed, node, { mode: 'forward',
                            appliedLinkIds: selection.forward.map(link => String(link._id)) });
                        configContent = JSON.stringify(composed, null, 2);
                    } else {
                    // Preserve the existing exact paired-TEST compatibility
                    // policy; ordinary classic writers use installed bytes above.
                    const statusFilter = allowedStatuses ? { status: { $in: allowedStatuses } } : {};
                    const allPortalLinks = await CascadeLink.find({ portalNode: node._id, active: true, ...statusFilter }).populate('bridgeNode');
                    const allBridgeLinks = await CascadeLink.find({ bridgeNode: node._id, active: true, ...statusFilter });
                    const forwardHopLinks = allBridgeLinks.filter(link => link.mode === 'forward');
                    // An actual reverse upstream makes this a transit relay:
                    // xray-bridge owns its downstream portals/listeners. Main
                    // must not bind them again (Xray enables SO_REUSEPORT).
                    const hasReverseUpstream = allBridgeLinks.some(link => link.mode !== 'forward');

                    if (allPortalLinks.length > 0 || forwardHopLinks.length > 0) {
                        const configObj = JSON.parse(configContent);
                        // Cascade routing applies to ALL client-facing inbounds
                        // (main + extras), so traffic from any inbound goes
                        // into the cascade.
                        const inboundTags = [
                            node.xray?.inboundTag || 'vless-in',
                            ...(node.xray?.extraInbounds || [])
                                .map(i => i.inboundTag)
                                .filter(Boolean),
                        ];

                        const reverseLinks = hasReverseUpstream ? [] : allPortalLinks.filter(l => l.mode !== 'forward');
                        const forwardLinks = await this._getForwardChainLinks(node._id, allowedStatuses);

                        if (reverseLinks.length > 0) {
                            configGenerator.applyReversePortal(configObj, reverseLinks, inboundTags);
                        }
                        if (forwardLinks.length > 0) {
                            configGenerator.applyForwardChain(configObj, forwardLinks, inboundTags);
                        }
                        // This branch only runs for classic-owned nodes; keep
                        // the normal hop listener in their main config.
                        if (forwardHopLinks.length > 0) {
                            configGenerator.applyForwardHopInbound(configObj, forwardHopLinks);
                        }

                        await require('./cascadeService')._applyClassicL2tpPathIngress(configObj, node, { mode: 'forward' });
                        finishClassicConfigRouting(configObj);

                        configContent = JSON.stringify(configObj, null, 2);
                        const total = reverseLinks.length + forwardLinks.length + forwardHopLinks.length;
                        logger.info(`[Xray Sync] Node ${node.name}: applied ${total} cascade link(s) (${reverseLinks.length}R/${forwardLinks.length}F/${forwardHopLinks.length}H)`);
                    } else {
                        // No cascade links, still ensure geoip:private is present
                        const configObj = JSON.parse(configContent);
                        await require('./cascadeService')._applyClassicL2tpPathIngress(configObj, node, { mode: 'forward' });
                        finishClassicConfigRouting(configObj);
                        configContent = JSON.stringify(configObj, null, 2);
                    }
                    }
                } catch (cascadeErr) {
                    // Never degrade an unknown baseline into a base-only push.
                    if (!allowedStatuses || fenced) throw cascadeErr;
                    logger.warn(`[Xray Sync] Node ${node.name}: cascade apply skipped: ${cascadeErr.message}`);
                }

                // L2TP relays: the regenerated base config has no L2TP-managed
                // sections (tproxy inbound, path socks outbound, their rules).
                // Re-attach them from the live config so a plain node sync does
                // not strand L2TP clients until a reinstall.
                try {
                    const hasInstalledL2tp = await RelayL2tpState.exists({
                        node: node._id,
                        desiredState: 'installed',
                    });
                    // The checked classic baseline already retains all L2TP
                    // sections. Re-merging them would duplicate routing rules.
                    if (hasInstalledL2tp && allowedStatuses) {
                        const current = await ssh.exec('cat /usr/local/etc/xray/config.json 2>/dev/null || true');
                        if (fenced && !current?.stdout) throw new Error('CLASSIC_CONFIG_L2TP_READ_UNCERTAIN');
                        if (current?.stdout) {
                            if (fenced) {
                                // The compatibility merger deliberately returns
                                // the base on malformed JSON. That is unsafe
                                // evidence for a fenced preservation write.
                                const live = JSON.parse(current.stdout);
                                if (!live || typeof live !== 'object' || Array.isArray(live)) {
                                    throw new Error('CLASSIC_CONFIG_L2TP_READ_UNCERTAIN');
                                }
                            }
                            const merged = mergePreservedL2tpConfig(configContent, current.stdout);
                            if (merged !== configContent) {
                                logger.info(`[Xray Sync] Node ${node.name}: preserved L2TP-managed Xray sections`);
                            }
                            const composed = JSON.parse(merged);
                            finishClassicConfigRouting(composed);
                            configContent = JSON.stringify(composed, null, 2);
                        }
                    }
                } catch (l2tpErr) {
                    if (fenced) throw l2tpErr;
                    logger.warn(`[Xray Sync] Node ${node.name}: L2TP section preservation skipped: ${l2tpErr.message}`);
                }

                // When access logging is enabled, the log directory must exist
                // and be writable by the Xray service user (User=nobody in the
                // systemd unit) BEFORE Xray restarts with the new config —
                // otherwise Xray fails to start and the node goes down.
                if (node.xray?.accessLogs?.enabled) {
                    try {
                        await ssh.exec(
                            'mkdir -p /var/log/xray && '
                            + 'chown nobody /var/log/xray 2>/dev/null || chown nobody:nogroup /var/log/xray 2>/dev/null || true; '
                            + 'chmod 755 /var/log/xray; '
                            + 'touch /var/log/xray/access.log && chown nobody /var/log/xray/access.log 2>/dev/null || true'
                        );
                    } catch (dirErr) {
                        if (fenced) throw dirErr;
                        logger.warn(`[Xray Sync] Node ${node.name}: access-log dir prep failed: ${dirErr.message}`);
                    }
                }

                // Xray config always goes to /usr/local/etc/xray/config.json
                const xrayConfigPath = '/usr/local/etc/xray/config.json';
                await ssh.uploadContent(configContent, xrayConfigPath);
                logger.info(`[Xray Sync] Node ${node.name}: config uploaded to ${xrayConfigPath}`);

                // Also refresh cc-agent config when extra inbounds may have
                // changed, so the agent picks up new tag→flow mapping. The
                // helper restarts cc-agent via systemctl; safe to call always.
                if (node.xray?.agentToken) {
                    try {
                        await nodeSetup.reloadCcAgent(node, ssh);
                    } catch (reloadErr) {
                        if (fenced) throw reloadErr;
                        logger.warn(`[Xray Sync] Node ${node.name}: cc-agent reload failed: ${reloadErr.message}`);
                    }
                }
            } catch (error) {
                if (error?.code?.startsWith('CLASSIC_APPLIED_')) throw error;
                if (!allowedStatuses || fenced) return false;
                logger.warn(`[Xray Sync] Node ${node.name}: config upload failed (SSH): ${error.message}`);
            } finally {
                ssh.disconnect();
            }
        }

        if (fenced && !topologyManaged && !node.ssh?.password && !node.ssh?.privateKey) return false;

        // Step 2: Restart Xray via Agent (preferred) or SSH fallback
        const hasAgent = !!(node.xray?.agentToken);
        if (topologyManaged && !hasAgent) {
            const message = 'topology-managed node has no agent token for user sync';
            logger.warn(`[Xray Sync] Node ${node.name}: ${message}`);
            await HyNode.updateOne({ _id: node._id }, {
                $set: { status: 'error', lastSync: new Date(), lastError: message, healthFailures: 0 },
            });
            await invalidateNodesCache();
            return false;
        }
        if (!topologyManaged && hasAgent) {
            try {
                // /restart blocks until Xray is running and users are restored (~2-3s)
                await this._agentRequest(node, 'POST', '/restart');
                logger.info(`[Xray Sync] Node ${node.name}: restarted via agent`);
            } catch (error) {
                if (fenced) return false;
                logger.warn(`[Xray Sync] Node ${node.name}: agent restart failed: ${error.message}`);
                if (error.code === 'AGENT_HTTP_ERROR') {
                    await HyNode.updateOne({ _id: node._id }, {
                        $set: { status: 'error', lastSync: new Date(), lastError: `Agent restart failed: ${error.message}`, healthFailures: 0 },
                    });
                    await invalidateNodesCache();
                    return false;
                }
            }
        } else if (!topologyManaged && (node.ssh?.password || node.ssh?.privateKey)) {
            const ssh = createSSH();
            try {
                await ssh.connect();
                await ssh.exec('systemctl restart xray');
                logger.info(`[Xray Sync] Node ${node.name}: restarted via SSH`);
            } catch (error) {
                if (fenced) return false;
                logger.warn(`[Xray Sync] Node ${node.name}: SSH restart failed: ${error.message}`);
            } finally {
                ssh.disconnect();
            }
        }

        // Step 3: Sync users via Agent (builds the runtime user list in Xray without restart)
        if (hasAgent) {
            try {
                const xray = node.xray || {};
                const userPayload = users.map(u => {
                    const flow = ((xray.security === 'reality' || xray.security === 'tls') && xray.transport === 'tcp')
                        ? (xray.flow || 'xtls-rprx-vision') : '';
                    return { id: u.xrayUuid, email: u.userId, flow };
                }).filter(u => u.id);

                await this._agentRequest(node, 'POST', '/sync', { users: userPayload });
                logger.info(`[Xray Sync] Node ${node.name}: synced ${userPayload.length} users via agent`);
            } catch (error) {
                if (fenced) return false;
                logger.warn(`[Xray Sync] Node ${node.name}: agent sync failed: ${error.message}`);
                if (topologyManaged || error.code === 'AGENT_HTTP_ERROR') {
                    await HyNode.updateOne({ _id: node._id }, {
                        $set: { status: 'error', lastSync: new Date(), lastError: `Agent user sync failed: ${error.message}`, healthFailures: 0 },
                    });
                    await invalidateNodesCache();
                    return false;
                }
            }
        }

        if (completionFailed) return false;
        const health = await this.checkXrayAgentHealth(node, { requireProof: true, lastSync: new Date() });
        if (!health.online) return false;
        await invalidateNodesCache();

        logger.info(`[Xray Sync] Node ${node.name}: sync complete, ${users.length} users`);
        return true;
    }

    /**
     * Collect traffic stats from Xray node via Agent GET /stats.
     * Response shape (agent v1.1.0+):
     *   { users: { <userId>: { tx, rx } }, node: { tx, rx } }
     * Node tx/rx come from Xray outbound stats (real traffic that traversed
     * Xray), not from summing per-user counters.
     */
    async collectXrayTrafficStats(node) {
        const nodeKey = node._id?.toString?.() || node.id || node.name;
        // Keep billing counters independent of recorded service readiness;
        // neither stats nor log-derived user activity can prove it.
        if (!node.xray?.agentToken) {
            return { onlineUserIds: [], nodeKey, ok: false };
        }
        const observedAt = performance.now();
        try {
            const response = await this._agentRequest(node, 'GET', '/stats');
            const data = response.data || {};
            const users = data.users || {};
            const nodeTraffic = data.node || { tx: 0, rx: 0 };
            const nodeTx = nodeTraffic.tx || 0;
            const nodeRx = nodeTraffic.rx || 0;

            if (node.status !== 'online') {
                // An old agent can still supply real counters. Drain them
                // without treating its user activity as an online session.
                await this.#storeXrayCounters(node, users, nodeTx, nodeRx, new Date());
                return { onlineUserIds: [], nodeKey, ok: false };
            }

            let agentOnlineUserIds = [];
            let agentOnlineAvailable = false;
            try {
                const onlineResponse = await this._agentRequest(node, 'GET', '/online');
                agentOnlineUserIds = extractAgentOnlineUserIds(onlineResponse.data || {});
                agentOnlineAvailable = true;
            } catch (_) {
                logger.debug(`[Agent Online] ${node.name}: /online unavailable, falling back to traffic deltas`);
            }
            const now = new Date();
            const snapshotKey = nodeKey;
            const previousUsers = this.xrayUserStatsSnapshots.get(snapshotKey) || {};
            const trafficActiveUserIds = extractXrayOnlineUserIds(users, {
                previousUsersStats: previousUsers,
                requireTrafficChange: true,
            });
            const activeUserIds = agentOnlineAvailable
                ? agentOnlineUserIds
                : trafficActiveUserIds;
            this.xrayUserStatsSnapshots.set(snapshotKey, users);

            let onlineWindowUserIds;
            if (agentOnlineAvailable) {
                // /online already applies the agent-side 45s timeout. Do not add
                // another panel-side grace window, otherwise disconnect becomes
                // ~90s+ stale.
                onlineWindowUserIds = agentOnlineUserIds.map(String);
                this.xrayNodeUserLastActive.set(snapshotKey, new Map(onlineWindowUserIds.map(userId => [userId, now.getTime()])));
            } else {
                const activityWindowMs = 90 * 1000;
                const nodeLastActive = this.xrayNodeUserLastActive.get(snapshotKey) || new Map();
                activeUserIds.forEach(userId => nodeLastActive.set(String(userId), now.getTime()));
                for (const [userId, lastActiveAt] of nodeLastActive.entries()) {
                    if (now.getTime() - lastActiveAt > activityWindowMs) nodeLastActive.delete(userId);
                }
                this.xrayNodeUserLastActive.set(snapshotKey, nodeLastActive);
                onlineWindowUserIds = [...nodeLastActive.keys()];
            }

            await this.#storeXrayCounters(node, users, nodeTx, nodeRx, now);

            // Online = users with explicit live/growing traffic observed recently.
            // cc-agent traffic events can be sparse/unstable between polls, so keep
            // a short per-node activity window to avoid flicker while still clearing
            // disconnected clients quickly.
            const activeUsers = onlineWindowUserIds.length;
            const { matchedCount } = await HyNode.updateOne({ _id: node._id, active: true, status: 'online' }, {
                $set: { onlineUsers: activeUsers },
            });
            if (!matchedCount) return { onlineUserIds: [], nodeKey, ok: false };

            if (nodeTx > 0 || nodeRx > 0 || activeUsers > 0) {
                logger.info(`[Agent Stats] ${node.name}: ${activeUsers} online, node ↑${(nodeTx / 1024 / 1024).toFixed(1)}MB ↓${(nodeRx / 1024 / 1024).toFixed(1)}MB`);
            }
            return { onlineUserIds: onlineWindowUserIds, nodeKey: snapshotKey, observedAt, ok: true };
        } catch (_) {
            logger.error(`[Agent Stats] ${node.name} collection failed`);
            return { onlineUserIds: [], nodeKey, ok: false };
        }
    }

    async #storeXrayCounters(node, users, nodeTx, nodeRx, now) {
        const userEntries = Object.entries(users);
        const bulkOps = [];

        for (const [email, traffic] of userEntries) {
            const tx = traffic.tx || 0;
            const rx = traffic.rx || 0;
            if (tx === 0 && rx === 0) continue;

            // email == userId (as set in configGenerator and agent)
            bulkOps.push({
                updateOne: {
                    filter: { userId: email },
                    update: {
                        $inc: { 'traffic.tx': tx, 'traffic.rx': rx },
                        $set: { 'traffic.lastUpdate': now },
                    },
                },
            });
        }

        if (bulkOps.length > 0) {
            const result = await HyUser.bulkWrite(bulkOps, { ordered: false });
            logger.debug(`[Agent Stats] ${node.name}: updated ${result.modifiedCount}/${bulkOps.length} users`);
            this.enforceTrafficLimit(userEntries.map(([email]) => email)).catch(() => {});
        }

        if (nodeTx > 0 || nodeRx > 0) {
            await HyNode.updateOne({ _id: node._id }, {
                $inc: { 'traffic.tx': nodeTx, 'traffic.rx': nodeRx }, $set: { 'traffic.lastUpdate': now },
            });
        }
    }

    // Xray health uses the API probe; user counts belong to traffic collection.
    async getXrayOnlineUsers(node) {
        await this.checkXrayAgentHealth(node);
        return 0;
    }

    // ==================== HYSTERIA / COMMON METHODS ====================

    /**
     * Update config on a specific node (dispatches by type).
     * Virtual nodes have no remote server — sync is a no-op.
     */
    async updateNodeConfig(node) {
        if (node.type === 'virtual') return;
        if (node.type === 'xray') {
            return this.updateXrayNodeConfig(node);
        }
        return this._updateHysteriaNodeConfig(node);
    }

    /**
     * Fire-and-forget config push after a settings save.
     *
     * Non-blocking: defers to the next tick via setImmediate so the HTTP
     * response is flushed before any SSH/Agent round-trip starts.
     *
     * Silently skipped when:
     *  - `updates` contains only cosmetic fields (see CONFIG_AFFECTING_FIELDS);
     *  - node is inactive or acts as a cascade bridge (cascade deploy owns those);
     *  - node has neither SSH credentials nor an agent token (never set up yet).
     *
     * @param {string} nodeId  - Node _id
     * @param {Object} [updates] - $set payload applied to the node. When omitted,
     *                             the push is assumed relevant and runs unconditionally.
     */
    schedulePush(nodeId, updates = null) {
        if (!hasConfigRelevantUpdates(updates)) return;
        setImmediate(async () => {
            try {
                const node = await HyNode.findById(nodeId);
                if (!node || !node.active) return;
                if (node.cascadeRole === 'bridge') return;

                const hasSsh = !!(node.ssh?.password || node.ssh?.privateKey);
                const hasAgent = !!(node.xray && node.xray.agentToken);
                if (!hasSsh && !hasAgent) return;

                await this.updateNodeConfig(node);
            } catch (error) {
                logger.warn(`[AutoPush] node ${nodeId}: ${error.message}`);
            }
        });
    }

    /**
     * Update Hysteria config on a specific node
     */
    async _updateHysteriaNodeConfig(node) {
        logger.info(`[Sync] Updating config for node ${node.name} (${node.ip})`);
        
        await HyNode.updateOne(
            { _id: node._id },
            { $set: { status: 'syncing' } }
        );
        
        const ssh = new NodeSSH(node);
        
        try {
            await ssh.connect();
            
            // Determine if this node uses TLS files (not ACME)
            const useTlsFiles = node.useTlsFiles || !node.domain;
            
            // For same-VPS nodes or nodes using TLS files, ensure certificates exist
            if (useTlsFiles || isSameVpsAsPanel(node)) {
                const panelCerts = getPanelCertificates(config.PANEL_DOMAIN);
                const certResult = await ssh.ensureCertificates(panelCerts);
                
                if (certResult.success) {
                    if (certResult.action === 'uploaded') {
                        logger.info(`[Sync] ${node.name}: certificates uploaded from panel`);
                    }
                } else {
                    logger.warn(`[Sync] ${node.name}: certificate issue - ${certResult.error}`);
                    logger.warn(`[Sync] ${node.name}: Hysteria may fail to start without valid certificates`);
                }
            }
            
            // Use custom config or generate automatically
            let configContent;
            const customConfig = (node.customConfig || '').trim();
            if (node.useCustomConfig && customConfig && customConfig.length > 50) {
                if (!customConfig.includes('listen:')) {
                    throw new Error('Custom config invalid: missing listen:');
                }
                if (!customConfig.includes('acme:') && !customConfig.includes('tls:')) {
                    throw new Error('Custom config invalid: missing acme: or tls:');
                }
                configContent = customConfig;
                logger.info(`[Sync] Using custom config for ${node.name}`);
            } else {
                if (node.useCustomConfig) {
                    logger.warn(`[Sync] Custom config for ${node.name} is empty or too short, using auto-generation`);
                }
                const authUrl = this.getAuthUrl();
                const settings = await Settings.get();
                const authInsecure = settings?.nodeAuth?.insecure ?? true;
                configContent = configGenerator.generateNodeConfig(node, authUrl, { authInsecure, useTlsFiles });
            }
            
            // Update config on node
            const success = await ssh.updateConfig(configContent);
            
            if (success) {
                const isRunning = await ssh.checkHysteriaStatus();
                
                await HyNode.updateOne(
                    { _id: node._id },
                    {
                        $set: {
                            status: isRunning ? 'online' : 'error',
                            lastSync: new Date(),
                            lastError: isRunning ? '' : 'Service not running after sync',
                            healthFailures: 0,
                        }
                    }
                );
                await invalidateNodesCache();
                
                logger.info(`[Sync] Node ${node.name}: config updated`);
                return true;
            } else {
                throw new Error('Failed to update config');
            }
        } catch (error) {
            logger.error(`[Sync] Node ${node.name} error: ${error.message}`);
            await HyNode.updateOne(
                { _id: node._id },
                { $set: { status: 'error', lastError: error.message, healthFailures: 0 } }
            );
            await invalidateNodesCache();
            webhook.emit(webhook.EVENTS.NODE_ERROR, { nodeId: node._id, name: node.name, error: error.message });
            return false;
        } finally {
            ssh.disconnect();
        }
    }

    /**
     * Update configs on all active nodes (parallel, up to 5 concurrent)
     */
    async syncAllNodes() {
        if (this.isSyncing) {
            logger.warn('[Sync] Sync already in progress');
            return;
        }
        
        this.isSyncing = true;
        const syncStart = Date.now();
        logger.info('[Sync] Starting sync for all nodes');
        
        try {
            const nodes = await HyNode.find({ active: true });
            
            // Parallel sync with concurrency limit
            const CONCURRENCY = require('./rebuildMode').isRebuildEnabled() ? 1 : 5;
            for (let i = 0; i < nodes.length; i += CONCURRENCY) {
                const batch = nodes.slice(i, i + CONCURRENCY);
                await Promise.allSettled(
                    batch.map(node => this.updateNodeConfig(node))
                );
            }
            
            this.lastSyncTime = new Date();
            logger.info('[Sync] Sync completed');
            webhook.emit(webhook.EVENTS.SYNC_COMPLETED, {
                nodesCount: nodes.length,
                duration: Math.round((Date.now() - syncStart) / 1000),
            });
        } finally {
            this.isSyncing = false;
        }
    }

    /**
     * Collect traffic stats from node and update users (dispatches by type).
     * Virtual nodes never carry traffic of their own.
     */
    async collectTrafficStats(node) {
        if (node.type === 'virtual') return;
        if (node.type === 'xray') {
            return this.collectXrayTrafficStats(node);
        }
        return this._collectHysteriaTrafficStats(node);
    }

    /**
     * Collect traffic stats from Hysteria node via HTTP API
     * Uses bulkWrite for optimization (99% fewer MongoDB queries)
     */
    async _collectHysteriaTrafficStats(node) {
        try {
            if (!node.statsPort || !node.statsSecret) {
                return;
            }
            
            const url = `http://${node.ip}:${node.statsPort}/traffic?clear=true`;
            
            const response = await axios.get(url, {
                headers: { Authorization: node.statsSecret },
                timeout: 10000,
            });
            
            const stats = response.data;
            
            // Sum node traffic
            let nodeTx = 0;
            let nodeRx = 0;
            
            // Prepare bulk operations for all users
            const bulkOps = [];
            const now = new Date();
            
            for (const [userId, traffic] of Object.entries(stats)) {
                nodeTx += traffic.tx || 0;
                nodeRx += traffic.rx || 0;
                
                bulkOps.push({
                    updateOne: {
                        filter: { userId },
                        update: {
                            $inc: {
                                'traffic.tx': traffic.tx || 0,
                                'traffic.rx': traffic.rx || 0,
                            },
                            $set: { 'traffic.lastUpdate': now }
                        }
                    }
                });
            }
            
            // Execute bulk update (1 query instead of N)
            if (bulkOps.length > 0) {
                const result = await HyUser.bulkWrite(bulkOps, { ordered: false });
                logger.debug(`[Stats] ${node.name}: Bulk updated ${result.modifiedCount}/${bulkOps.length} users`);

                // Enforce traffic limits on users whose counters just moved (fire-and-forget).
                this.enforceTrafficLimit(Object.keys(stats)).catch(() => {});
            }
            
            // Update node traffic
            await HyNode.updateOne(
                { _id: node._id },
                {
                    $inc: {
                        'traffic.tx': nodeTx,
                        'traffic.rx': nodeRx,
                    },
                    $set: { 'traffic.lastUpdate': now }
                }
            );
            
            logger.info(`[Stats] ${node.name}: ${Object.keys(stats).length} users, traffic: ↑${(nodeTx / 1024 / 1024).toFixed(1)}MB ↓${(nodeRx / 1024 / 1024).toFixed(1)}MB`);
        } catch (error) {
            logger.error(`[Stats] ${node.name} error: ${error.message}`);
        }
    }

    /**
     * Get online users from node (dispatches by type).
     * Virtual nodes are aggregators with no online state of their own.
     */
    async getOnlineUsers(node) {
        if (node.type === 'virtual') return 0;
        if (node.type === 'xray') {
            return this.getXrayOnlineUsers(node);
        }
        return this._getHysteriaOnlineUsers(node);
    }

    /**
     * Get online users from Hysteria node via HTTP Stats API
     */
    async _getHysteriaOnlineUsers(node) {
        try {
            // If Stats API not configured - skip, don't change status
            if (!node.statsPort || !node.statsSecret) {
                logger.debug(`[Stats] ${node.name}: Stats API not configured, skipping`);
                return 0;
            }
            
            const url = `http://${node.ip}:${node.statsPort}/online`;
            
            const response = await axios.get(url, {
                headers: { Authorization: node.statsSecret },
                timeout: 5000,
            });
            
            const online = Object.keys(response.data).length;
            
            const prevNode = await HyNode.findOneAndUpdate(
                { _id: node._id },
                { $set: { onlineUsers: online, status: 'online', healthFailures: 0 } }
            );

            if (prevNode && prevNode.status !== 'online') {
                await invalidateNodesCache();
                webhook.emit(webhook.EVENTS.NODE_ONLINE, { nodeId: node._id, name: node.name });
            }
            
            if (online > 0) {
                logger.info(`[Stats] ${node.name}: ${online} online`);
            }
            return online;
        } catch (error) {
            logger.warn(`[Stats] ${node.name}: Stats unavailable - ${error.message}`);

            const prevNode = await HyNode.findOneAndUpdate(
                { _id: node._id },
                {
                    $inc: { healthFailures: 1 },
                    $set: { lastError: `Stats: ${error.message}` },
                }
            );

            const failures = (prevNode?.healthFailures || 0) + 1;

            if (failures >= HEALTH_FAILURE_THRESHOLD && prevNode?.status === 'online') {
                await HyNode.updateOne({ _id: node._id }, { $set: { status: 'offline', onlineUsers: 0 } });
                await invalidateNodesCache();
                webhook.emit(webhook.EVENTS.NODE_OFFLINE, { nodeId: node._id, name: node.name, lastError: error.message });
                logger.warn(`[Stats] ${node.name}: marked offline after ${failures} consecutive failures`);
            }
            return 0;
        }
    }

    /**
     * Kick user from all nodes
     */
    async kickUser(userId) {
        const user = await HyUser.findOne({ userId }).populate('nodes', 'name type ip statsPort statsSecret');
        
        if (!user) {
            return;
        }
        
        for (const node of user.nodes) {
            try {
                // Virtual nodes have no remote service to kick from.
                if (node.type === 'virtual') continue;
                if (!node.statsPort || !node.statsSecret || !node.ip) continue;

                const url = `http://${node.ip}:${node.statsPort}/kick`;
                
                await axios.post(url, [userId], {
                    headers: {
                        Authorization: node.statsSecret,
                        'Content-Type': 'application/json',
                    },
                    timeout: 5000,
                });
                
                logger.info(`[Kick] ${userId} kicked from ${node.name}`);
            } catch (error) {
                logger.error(`[Kick] Kick error on ${node.name}: ${error.message}`);
            }
        }
    }

    /**
     * Collect log-derived online state from Xray agents only.
     * This is intentionally separate from /stats traffic accounting so the UI
     * lamp is not delayed by slower node traffic polls or gRPC stats resets.
     */
    async collectXrayAgentOnlineStates() {
        const nodes = await HyNode.find({ type: 'xray', active: true, status: 'online', 'xray.agentToken': { $exists: true, $ne: '' } });
        const activeXrayNodeKeys = new Set(nodes.map(node => node._id?.toString?.() || node.id || node.name));
        const CONCURRENCY = 8;

        for (let i = 0; i < nodes.length; i += CONCURRENCY) {
            const batch = nodes.slice(i, i + CONCURRENCY);
            const results = await Promise.allSettled(batch.map(async (node) => {
                const observedAt = performance.now();
                const response = await this._agentRequest(node, 'GET', '/online');
                return {
                    ok: true,
                    nodeKey: node._id?.toString?.() || node.id || node.name,
                    onlineUserIds: extractAgentOnlineUserIds(response.data || {}),
                    observedAt,
                };
            }));
            this.#recordOnlineSamples(results);
        }

        await this.#publishOnlineSamples(activeXrayNodeKeys, 10);
    }

    #recordOnlineSamples(results) {
        for (const result of results) {
            if (result.status !== 'fulfilled') continue;
            const sample = result.value;
            if (sample?.ok !== true || !sample.nodeKey || !Array.isArray(sample.onlineUserIds)
                || !Number.isFinite(sample.observedAt)) continue;
            const previous = this.xrayNodeOnlineUsers.get(sample.nodeKey);
            if (previous && previous.observedAt > sample.observedAt) continue;
            this.xrayNodeOnlineUsers.set(sample.nodeKey, { ids: sample.onlineUserIds, observedAt: sample.observedAt });
        }
    }

    async #publishOnlineSamples(activeXrayNodeKeys, ttl) {
        const merged = mergeNodeOnlineContributions(this.xrayNodeOnlineUsers, activeXrayNodeKeys, performance.now());
        this.xrayNodeOnlineUsers = merged.contributions;
        await cache.setXrayOnlineUsers([...merged.userIds], ttl);
    }

    /**
     * Collect stats from all nodes (parallel with concurrency limit)
     */
    async collectAllStats() {
        const nodes = await HyNode.find({ active: true });
        const activeXrayNodeKeys = new Set(nodes
            .filter(node => node.type === 'xray' && node.status === 'online')
            .map(node => node._id?.toString?.() || node.id || node.name));
        
        // Parallel processing with concurrency limit
        const CONCURRENCY = 5;
        for (let i = 0; i < nodes.length; i += CONCURRENCY) {
            const batch = nodes.slice(i, i + CONCURRENCY);
            const results = await Promise.allSettled(
                batch.flatMap(node => [
                    this.collectTrafficStats(node),
                    ...(node.type === 'xray' ? [] : [this.getOnlineUsers(node)])
                ])
            );
            this.#recordOnlineSamples(results);
        }

        await this.#publishOnlineSamples(activeXrayNodeKeys, Math.max(45, cache.ttl.ONLINE_SESSIONS || 10));
        
        // Update last stats collection time
        this.lastSyncTime = new Date();
        
        // Invalidate traffic stats cache (data updated)
        await cache.invalidateTrafficStats();
    }

    /**
     * Health check all nodes (parallel)
     */
    async healthCheck() {
        const nodes = await HyNode.find({ active: true });
        
        // Parallel check with concurrency limit
        const CONCURRENCY = 5;
        for (let i = 0; i < nodes.length; i += CONCURRENCY) {
            const batch = nodes.slice(i, i + CONCURRENCY);
            await Promise.allSettled(
                batch.map(node => this.getOnlineUsers(node))
            );
        }
    }

    /**
     * Atomically flip an enabled user to disabled, request runtime revocation,
     * invalidate caches and emit the appropriate webhook. A successful DB
     * update does not prove runtime revocation.
     *
     * Recheck both enabled and the reason at the write: a snapshot selected
     * by a scheduler may already have been renewed or reset by an operator.
     *
     * @param {object} user   plain user object; must have userId
     * @param {string} reason 'expired' | 'traffic'
     * @returns {Promise<boolean>} true if this call actually disabled the user
     */
    async disableUser(user, reason) {
        if (!user || !user.userId) return false;

        const filter = { userId: user.userId, enabled: true, ...(user._id ? { _id: user._id } : {}) };
        if (reason === 'expired') {
            filter.expireAt = { $ne: null, $lte: new Date() };
        } else if (reason === 'traffic') {
            filter.trafficLimit = { $gt: 0 };
            filter.$expr = { $gte: [
                { $add: [{ $ifNull: ['$traffic.tx', 0] }, { $ifNull: ['$traffic.rx', 0] }] },
                '$trafficLimit',
            ] };
        } else {
            return false;
        }
        const result = await HyUser.updateOne(
            filter,
            { $set: { enabled: false } }
        );
        if (result.modifiedCount === 0) return false;

        // subscriptionToken is needed to invalidate the subscription cache.
        // Most callers already pass it; fall back to a tiny lookup if missing.
        let token = user.subscriptionToken;
        if (!token) {
            const fresh = await HyUser.findOne(
                { userId: user.userId },
                { subscriptionToken: 1 }
            ).lean();
            token = fresh?.subscriptionToken;
        }

        await Promise.allSettled([
            this.removeUserFromAllXrayNodes(user),
            this.kickUser(user.userId),
            invalidateUserCache(user.userId, token),
        ]);

        const event = reason === 'traffic'
            ? webhook.EVENTS.USER_TRAFFIC_EXCEEDED
            : webhook.EVENTS.USER_EXPIRED;
        webhook.emit(event, { userId: user.userId, reason });

        logger.info(`[Disable] ${user.userId} (${reason})`);
        return true;
    }

    /**
     * Fast-path traffic enforcement triggered right after stats bulkWrite.
     * Looks only at users whose counters just moved; disables any that
     * crossed their limit. Full sweep on boot lives in expireScheduler.init.
     */
    async enforceTrafficLimit(userIds) {
        if (!userIds || userIds.length === 0) return;

        const users = await HyUser.find(
            { userId: { $in: userIds }, enabled: true, trafficLimit: { $gt: 0 } },
            { userId: 1, subscriptionToken: 1, trafficLimit: 1, 'traffic.tx': 1, 'traffic.rx': 1, xrayUuid: 1 }
        ).lean();

        const overLimit = users.filter(u =>
            (u.traffic?.tx || 0) + (u.traffic?.rx || 0) >= u.trafficLimit
        );
        if (overLimit.length === 0) return;

        await Promise.allSettled(overLimit.map(u => this.disableUser(u, 'traffic')));
    }

    /**
     * Setup port hopping on node
     */
    async setupPortHopping(node) {
        const ssh = new NodeSSH(node);
        
        try {
            await ssh.connect();
            await ssh.setupPortHopping(node.portRange);
            return true;
        } catch (error) {
            logger.error(`[PortHop] Error on ${node.name}: ${error.message}`);
            return false;
        } finally {
            ssh.disconnect();
        }
    }
}

const _service = new SyncService();
_service.ensureManualKeyLoaded = ensureManualKeyLoaded;
_service.checkPanelCertRotation = function() {
    return checkPanelCertRotation(_service);
};
module.exports = _service;
