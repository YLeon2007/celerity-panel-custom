'use strict';
// Disposable TEST-only diagnostics. Disabled unless both TEST runtime and the
// explicit on-disk switch are present. Delete the switch to stop logging.
const fs = require('node:fs');
const path = require('node:path');
const SWITCH = '/app/data/.test-topology-diagnostics-enabled';
const LOG = '/app/logs/topology-test-errors.log';
const ID = /^[a-f0-9]{24}$/i;
const CODE = /^(?:INVALID|SCOPE|TOPOLOGY|NODE|SIMPLE|CASCADE|STALE|UNCONFIRMED|ATTACH|FROZEN|UNSAFE|UNKNOWN|L2TP|PPP|USER|REMOTE|DEPLOYED|PORTAL|BRIDGE|OPERATION|INCOMPLETE|DISCONTINUOUS|SELF|CYCLE)[A-Z0-9_]{0,78}$/;
function safeCode(value) {
    return typeof value === 'string' && CODE.test(value) ? value : undefined;
}
function formatTopologyDiagnostic({ action, phase, revision, linkId, operationId, nodeId, groupId,
    error, now = new Date() }) {
    const entry = {
        time: now.toISOString(),
        action: typeof action === 'string' ? action.match(/^[a-z]+(?:[.][a-z]+)?/)?.[0] || 'unknown' : 'unknown',
        phase: typeof phase === 'string' ? phase.match(/^[a-z]+(?:[.-][a-z]+)*/) ?.[0] || 'unknown' : 'unknown',
        code: safeCode(error?.code) || 'UNKNOWN',
    };
    if (Number.isSafeInteger(revision) && revision >= 0) entry.revision = revision;
    if (typeof linkId === 'string' && ID.test(linkId)) entry.linkId = linkId;
    if (typeof operationId === 'string' && ID.test(operationId)) entry.operationId = operationId;
    if (typeof nodeId === 'string' && ID.test(nodeId)) entry.nodeId = nodeId;
    if (typeof groupId === 'string' && ID.test(groupId)) entry.groupId = groupId;
    const cause = safeCode(error?.causeCode);
    if (cause) entry.causeCode = cause;
    const errors = Array.isArray(error?.errors) ? error.errors.slice(0, 20) : [];
    const validation = errors.map(item => {
        const safe = safeCode(item?.code);
        if (!safe) return null;
        const row = { code: safe };
        for (const key of ['linkId','nodeId','sourceNodeId','targetNodeId','groupId']) {
            if (typeof item[key] === 'string' && ID.test(item[key])) row[key] = item[key];
        }
        return row;
    }).filter(Boolean);
    if (validation.length) entry.validation = validation;
    return entry;
}
function logTopologyTestFailure(input) {
    if (process.env.TOPOLOGY_TEST_EXECUTION_ENABLED !== 'true' || !fs.existsSync(SWITCH)) return;
    try {
        const text = `${JSON.stringify(formatTopologyDiagnostic(input))}\n`;
        if (fs.existsSync(LOG) && fs.statSync(LOG).size > 5 * 1024 * 1024) {
            fs.renameSync(LOG, `${LOG}.1`);
        }
        fs.appendFileSync(LOG, text, { encoding: 'utf8', mode: 0o600, flag: 'a' });
    } catch {
        // Diagnostics must never alter the API outcome or stringify arbitrary errors.
    }
}
module.exports = { formatTopologyDiagnostic, logTopologyTestFailure, SWITCH, LOG };
