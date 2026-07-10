/**
 * Access-logs provisioning / reconciliation.
 *
 * Reconciles the desired global access-logs setting against the actual per-node
 * state. For each eligible node it:
 *   - ensures (or revokes) an ingest credential,
 *   - flips the node's per-node accessLogs.enabled flag,
 *   - pushes fresh Xray + cc-agent configs so the log file is (de)activated and
 *     the agent starts/stops shipping.
 *
 * All node work is best-effort and isolated: one node failing to reconcile never
 * blocks the others and never marks the node offline. This is intentionally
 * decoupled from the request path — callers invoke reconcileAll() via
 * setImmediate so an Xray restart never blocks an HTTP response.
 */

const crypto = require('crypto');
const logger = require('../../utils/logger');
const appConfig = require('../../../config');
const credentialService = require('./credentialService');

const MIN_AGENT_VERSION = '1.4.0';

// Minimal semver-ish compare good enough for "x.y.z" agent versions. Missing or
// unparseable versions are treated as too old.
function agentVersionAtLeast(version, min) {
    if (!version || typeof version !== 'string') return false;
    const a = version.replace(/^v/, '').split('.').map(n => parseInt(n, 10) || 0);
    const b = min.split('.').map(n => parseInt(n, 10) || 0);
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
        const x = a[i] || 0;
        const y = b[i] || 0;
        if (x > y) return true;
        if (x < y) return false;
    }
    return true;
}

// Resolve the ingest URL to hand to agents. Explicit setting wins; otherwise it
// is derived from the panel base URL.
function resolveIngestUrl(settings) {
    const explicit = (settings?.accessLogs?.ingestUrl || '').trim();
    if (explicit) return explicit;
    const base = (appConfig.BASE_URL || '').replace(/\/+$/, '');
    return base ? `${base}/api/access-logs/ingest` : '';
}

// Eligibility: client-facing Xray nodes only (standalone/portal). Bridge/relay
// nodes never terminate client traffic, so they have no meaningful access log.
function isEligibleNode(node) {
    return node
        && node.type === 'xray'
        && ['standalone', 'portal'].includes(node.cascadeRole);
}

// Should THIS node be shipping, given the global setting + scope?
function nodeShouldShip(node, settings) {
    const al = settings?.accessLogs;
    if (!al || !al.enabled) return false;
    if (!isEligibleNode(node)) return false;
    if (al.nodeScope === 'selected') {
        const ids = (al.nodeIds || []).map(String);
        return ids.includes(String(node._id));
    }
    return true;
}

/**
 * Build the access_logs block for a node's cc-agent config. Returns a disabled
 * block when the node should not ship (so a previously-enabled agent gets turned
 * off cleanly). Used by nodeSetup.reloadCcAgent.
 */
async function buildNodeAccessLogsConfig(node) {
    const Settings = require('../../models/settingsModel');
    const settings = await Settings.get();

    if (!nodeShouldShip(node, settings)) {
        return { enabled: false };
    }

    const ingestUrl = resolveIngestUrl(settings);
    if (!ingestUrl) {
        return { enabled: false };
    }

    const { token } = await credentialService.ensureIngestToken(node);
    const insecureTls = !!(settings?.nodeAuth?.insecure);

    return {
        enabled: true,
        path: require('../configGenerator').XRAY_ACCESS_LOG_PATH,
        ingestUrl,
        ingestToken: token,
        insecureTls,
        spoolMaxBytes: 200 * 1024 * 1024,
        batchMaxEvents: 500,
        flushIntervalSeconds: 5,
        fileMaxBytes: 64 * 1024 * 1024,
    };
}

// Fingerprint of the effective access-log config for a node. When it matches
// the stored appliedFingerprint, the node already runs this exact config and
// the expensive push + Xray restart can be skipped. Covers EVERY input that
// lands in the agent's access_logs block: ingest URL, token (via hash), the
// TLS-verification mode, and the log path — so changing any of them forces a
// re-push, while unrelated settings saves stay no-ops.
function desiredFingerprint(shouldShip, settings, tokenHash) {
    if (!shouldShip) return 'disabled';
    const ingestUrl = resolveIngestUrl(settings);
    const insecureTls = !!(settings?.nodeAuth?.insecure);
    const logPath = require('../configGenerator').XRAY_ACCESS_LOG_PATH;
    return crypto.createHash('sha256')
        .update('v2|enabled|')
        .update(String(ingestUrl))
        .update('|')
        .update(String(tokenHash || ''))
        .update('|')
        .update(insecureTls ? 'itls1' : 'itls0')
        .update('|')
        .update(String(logPath))
        .digest('hex')
        .slice(0, 32);
}

/**
 * Reconcile a single node to its desired state. Pushes config via syncService so
 * both the Xray `log` section and the cc-agent `access_logs` block are updated.
 * Skips the push entirely when the node already runs the desired config, so
 * unrelated settings saves never restart Xray on the fleet.
 */
async function reconcileNode(node, settings) {
    const HyNode = require('../../models/hyNodeModel');
    const shouldShip = nodeShouldShip(node, settings);

    // Guard: agent must be new enough to run the shipping module.
    if (shouldShip && !agentVersionAtLeast(node.agentVersion, MIN_AGENT_VERSION)) {
        await HyNode.updateOne({ _id: node._id }, {
            $set: {
                'xray.accessLogs.enabled': false,
                'xray.accessLogs.status': 'agent-outdated',
                'xray.accessLogs.lastError': `cc-agent ${MIN_AGENT_VERSION}+ required`,
                'xray.accessLogs.lastReconcileAt': new Date(),
            },
        });
        logger.warn(`[AccessLogs] Node ${node.name}: agent too old for access logs`);
        return { node: node.name, status: 'agent-outdated' };
    }

    try {
        let tokenHash = '';
        if (shouldShip) {
            await credentialService.ensureIngestToken(node);
            const withHash = await HyNode.findById(node._id).select('xray.accessLogs.ingestTokenHash');
            tokenHash = withHash?.xray?.accessLogs?.ingestTokenHash || '';
        }

        const fingerprint = desiredFingerprint(shouldShip, settings, tokenHash);
        const applied = node.xray?.accessLogs?.appliedFingerprint || '';
        const currentStatus = node.xray?.accessLogs?.status || 'disabled';

        // No-op fast paths (skip the config push + Xray restart):
        //  - the node already runs this exact config and is healthy, OR
        //  - target is "disabled" and the node was never provisioned for access
        //    logs at all (disabled is the default state — nothing to undo).
        const neverProvisioned = !applied && !(node.xray?.accessLogs?.enabled);
        const alreadyApplied = fingerprint === applied
            && currentStatus !== 'error' && currentStatus !== 'pending';
        if (alreadyApplied || (!shouldShip && neverProvisioned)) {
            await HyNode.updateOne({ _id: node._id }, {
                $set: {
                    'xray.accessLogs.lastReconcileAt': new Date(),
                    'xray.accessLogs.appliedFingerprint': fingerprint,
                },
            });
            return { node: node.name, status: currentStatus, skipped: true };
        }

        if (!shouldShip) {
            await credentialService.revokeIngestToken(node._id);
        }

        // Persist the desired per-node flag BEFORE pushing config so the config
        // generator + agent-config builder read the new state.
        await HyNode.updateOne({ _id: node._id }, {
            $set: {
                'xray.accessLogs.enabled': shouldShip,
                'xray.accessLogs.status': shouldShip ? 'pending' : 'disabled',
                'xray.accessLogs.lastError': '',
                'xray.accessLogs.lastReconcileAt': new Date(),
            },
        });

        // Push config (restarts Xray + reloads cc-agent). Reload the fresh node
        // doc so the updated flag is reflected.
        const fresh = await HyNode.findById(node._id);
        const syncService = require('../syncService');
        await syncService.updateXrayNodeConfig(fresh);

        await HyNode.updateOne({ _id: node._id }, {
            $set: {
                'xray.accessLogs.status': shouldShip ? 'active' : 'disabled',
                'xray.accessLogs.appliedFingerprint': fingerprint,
            },
        });

        return { node: node.name, status: shouldShip ? 'active' : 'disabled' };
    } catch (err) {
        await HyNode.updateOne({ _id: node._id }, {
            $set: {
                'xray.accessLogs.status': 'error',
                'xray.accessLogs.lastError': String(err.message || err).slice(0, 500),
                'xray.accessLogs.lastReconcileAt': new Date(),
            },
        });
        logger.error(`[AccessLogs] Node ${node.name}: reconcile failed: ${err.message}`);
        return { node: node.name, status: 'error', error: err.message };
    }
}

// Single-flight guard: two quick settings saves must not run two overlapping
// reconciles (double Xray restarts). A save that lands mid-run schedules one
// follow-up pass so the latest desired state always wins.
let reconcileRunning = false;
let reconcileQueued = false;

/**
 * Reconcile every eligible node against the current global setting, then update
 * the global state (active/disabled/error) accordingly.
 */
async function reconcileAll() {
    if (reconcileRunning) {
        reconcileQueued = true;
        return { state: 'queued', results: [] };
    }
    reconcileRunning = true;
    try {
        const Settings = require('../../models/settingsModel');
        const HyNode = require('../../models/hyNodeModel');
        const settings = await Settings.get();
        const wantEnabled = !!settings?.accessLogs?.enabled;

        const nodes = await HyNode.find({
            type: 'xray',
            cascadeRole: { $in: ['standalone', 'portal'] },
        });

        const results = [];
        for (const node of nodes) {
            results.push(await reconcileNode(node, settings));
        }

        const anyError = results.some(r => r.status === 'error');
        let globalState;
        if (!wantEnabled) {
            globalState = 'disabled';
        } else if (anyError) {
            globalState = 'error';
        } else {
            globalState = 'active';
        }
        await Settings.update({ 'accessLogs.state': globalState });

        const skipped = results.filter(r => r.skipped).length;
        logger.info(`[AccessLogs] Reconcile complete: state=${globalState}, nodes=${results.length} (${skipped} unchanged)`);
        return { state: globalState, results };
    } finally {
        reconcileRunning = false;
        if (reconcileQueued) {
            reconcileQueued = false;
            setImmediate(() => { reconcileAll().catch(e => logger.error(`[AccessLogs] queued reconcile failed: ${e.message}`)); });
        }
    }
}

module.exports = {
    MIN_AGENT_VERSION,
    agentVersionAtLeast,
    resolveIngestUrl,
    isEligibleNode,
    nodeShouldShip,
    buildNodeAccessLogsConfig,
    reconcileNode,
    reconcileAll,
};
