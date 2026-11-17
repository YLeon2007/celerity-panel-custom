'use strict';
// Disposable TEST-only diagnostics. Disabled unless both TEST runtime and the
// explicit on-disk switch are present. Delete the switch to stop logging.
const fs = require('node:fs');
const path = require('node:path');
const SWITCH = '/app/data/.test-topology-diagnostics-enabled';
const LOG = '/app/logs/topology-test-errors.log';
const ID = /^[a-f0-9]{24}$/i;
const CODE = /^(?:APPLIED|INVALID|SCOPE|TOPOLOGY|NODE|SIMPLE|CASCADE|STALE|UNCONFIRMED|ATTACH|FROZEN|UNSAFE|UNKNOWN|L2TP|PPP|USER|REMOTE|DEPLOYED|PORTAL|BRIDGE|OPERATION|INCOMPLETE|DISCONTINUOUS|SELF|CYCLE)[A-Z0-9_]{0,78}$/;
function safeCode(value) {
    return typeof value === 'string' && CODE.test(value) ? value : undefined;
}
function formatTopologyDiagnostic({ action, phase, revision, linkId, operationId, nodeId, groupId,
    error, now = new Date() }) {
    const entry = {
        time: now.toISOString(),
        action: typeof action === 'string' ? action.match(/^[a-z]+(?:[.][a-z]+)?/)?.[0] || 'unknown' : 'unknown',
        phase: typeof phase === 'string' ? phase.slice(0, 80).match(/^[a-z][a-z0-9]*(?:[.-][a-z][a-z0-9]*)*/) ?.[0] || 'unknown' : 'unknown',
        code: safeCode(error?.code) || 'UNKNOWN',
    };
    // Only fixed source filenames/line numbers and fixed class names, never
    // error.message, arbitrary stack text, attached payloads or credentials.
    if (['Error','TypeError','ReferenceError','TopologyDeploymentRepositoryError','TopologyOperationCoordinatorError',
        'MongoServerError','MongoNetworkError','ValidationError','CastError','StrictModeError'].includes(error?.name)) entry.errorType = error.name;
    if (typeof error?.stack === 'string') {
        const files = ['src/routes/cascadeTopologyDeploy.js','src/modules/relay-l2tp/repositories/topologyDeploymentRepository.js','src/modules/relay-l2tp/services/topologyOperationCoordinator.js','src/modules/relay-l2tp/services/topologyIntentService.js',
            'src/modules/relay-l2tp/repositories/topologyV2Settlement.js',
            'src/modules/relay-l2tp/workers/topologyOperationWorker.js',
            'src/modules/relay-l2tp/services/topologyOperationFinalizer.js',
            'src/modules/relay-l2tp/repositories/topologyOperationFinalizationRepository.js',
            'src/modules/relay-l2tp/services/topologyOperationExecutor.js'];
        const frames = [];
        for (const file of files) {
            let from = 0;
            do {
                const at = error.stack.indexOf(file + ':', from);
                if (at < 0) break;
                const match = error.stack.slice(at + file.length, at + file.length + 16).match(/^:(\d{1,6}):(\d{1,6})/);
                const frame = match && file + ':' + match[1] + ':' + match[2];
                if (frame && !frames.includes(frame)) frames.push(frame);
                from = at + file.length + 1;
            } while (file.endsWith('/topologyV2Settlement.js') && frames.length < 3);
        }
        if (frames.length) entry.sourceFrames = frames.slice(0,3);
    }
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
        // Explicit disposable TEST switch only. Preserve the original terminal
        // exception before the worker maps it to its public generic outcome.
        // This separate private file is never returned by an API or printed.
        if (['worker.v2-terminal','worker.verify','worker.commit','worker.prepare','worker.binding-reservation','worker.prepared-continuation'].includes(input.phase)) {
            const error = input.error;
            const causes = [];
            for (let cause = error?.cause; cause && causes.length < 4; cause = cause.cause) {
                causes.push({ name: cause.name, code: cause.code, message: cause.message, stack: cause.stack,
                    transientTransaction: cause.hasErrorLabel?.('TransientTransactionError') === true,
                    unknownCommit: cause.hasErrorLabel?.('UnknownTransactionCommitResult') === true });
            }
            fs.appendFileSync('/app/logs/topology-test-primary.private.log', JSON.stringify({
                time: new Date().toISOString(), operationId: input.operationId, nodeId: input.nodeId,
                name: error?.name, code: error?.code, message: error?.message,
                stack: error?.stack,
                ...(causes.length ? { causes } : {}),
            }) + '\n', { encoding: 'utf8', mode: 0o600, flag: 'a' });
        }
    } catch {
        // Diagnostics must never alter the API outcome or stringify arbitrary errors.
    }
}
module.exports = { formatTopologyDiagnostic, logTopologyTestFailure, SWITCH, LOG };
