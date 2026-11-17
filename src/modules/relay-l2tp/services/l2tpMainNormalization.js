'use strict';

const { createHash, randomUUID } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const mongoose = require('mongoose');
const STEPS = Object.freeze(['backup', 'compose_xray_fragment', 'validate_xray', 'activate_xray']);
const fail = code => { throw Object.assign(new Error(code), { code }); };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const stateFields = 'node status desiredState routeGroup activePathKey appliedTopologyRevision secretRevision clientCidr localAddress poolStart poolEnd dnsServers tproxyPort fwmark routeTable';

function normalizationDiagnostic(error, phase) {
    const frame = String(error?.stack || '').match(/\b(src\/(?:modules|services)\/[A-Za-z0-9_./-]+\.js:\d+:\d+)\)?(?:\n|$)/)?.[1];
    return { phase, name: ['Error', 'TypeError', 'SyntaxError', 'RangeError'].includes(error?.name) ? error.name : 'Error',
        ...(typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,79}$/.test(error.code) ? { code: error.code } : {}),
        ...(frame ? { sourceFrame: frame } : {}),
        ...(['NODE_EXECUTION_UNAVAILABLE', 'MAIN_NORMALIZATION_READBACK_FAILED'].includes(error?.message)
            ? { reason: error.message } : {}) };
}

// Read-only witness, including service identity. No credentials/config bytes leave
// the guest. MAIN activation must not mutate/restart PPP or the topology profile.
function normalizationProbe() {
    return `import os,json,hashlib,subprocess
os.chdir('/')
def digest(p):
 try:
  f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NOATIME);s=os.fstat(f);b=os.read(f,4194305);os.close(f)
  return {'sha256':hashlib.sha256(b).hexdigest(),'mode':s.st_mode,'uid':s.st_uid,'gid':s.st_gid,'inode':s.st_ino,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns}
 except FileNotFoundError:return None
paths=['/usr/local/etc/xray-bridge/config.json','/etc/ipsec.conf','/etc/ipsec.secrets','/etc/xl2tpd/xl2tpd.conf','/etc/ppp/options.xl2tpd','/etc/ppp/chap-secrets']
p=subprocess.run(['systemctl','show','xray-bridge.service','xl2tpd.service','strongswan-starter.service','-p','Id','-p','MainPID','-p','InvocationID','-p','ActiveState'],capture_output=True,text=True,timeout=10)
assert p.returncode==0
main=digest('/usr/local/etc/xray/config.json')
s=subprocess.run(['systemctl','is-active','xray.service'],capture_output=True,text=True,timeout=5)
print(json.dumps({'mainHash':main['sha256'],'active':s.returncode==0 and s.stdout=='active\\n','protected':{'files':{p:digest(p) for p in paths},'services':p.stdout}}))
`;
}

// A finite MAIN-only operation reuses the existing counted standalone admission,
// held L2TP lock, fragment composer and native backup/activation artifacts. It does
// not enqueue install, resolve PSK/users, publish an installed path or touch LNS.
function createL2tpMainNormalizer({ authorization, RelayL2tpState, CascadeRouteGroup, CascadeLink,
    CascadeTopologyState, L2tpOperation, remoteAdmissionRepository: admissions,
    lockService, candidateService, transportResolver, clock }) {
    return async nodeId => {
        if (authorization.executionContext?.target !== 'test') fail('MAIN_NORMALIZATION_UNAVAILABLE');
        nodeId = String(nodeId);
        if (!mongoose.Types.ObjectId.isValid(nodeId)) fail('INVALID_NODE_ID');
        const operationId = new mongoose.Types.ObjectId().toString(), owner = `main-normalize:${randomUUID()}`;
        const admissionId = await admissions.acquire({ nodeId });
        let lock, documentCreated = false, dispatched = false, completed = false, transport, phase = 'acquire';
        const readState = () => RelayL2tpState.findOne({ node: nodeId }).select(stateFields).lean();
        try {
            const acquired = await lockService.acquire({ node: nodeId, owner, operationId, leaseMs: 120000 });
            if (!acquired?.ok || !acquired.lock?.generation) fail('NODE_OPERATION_LOCK_CONFLICT');
            lock = acquired.lock;
            const state = await readState();
            if (state?.status !== 'installed' || state.desiredState !== 'installed'
                || !state.activePathKey || !Number.isSafeInteger(state.secretRevision) || state.secretRevision < 1) fail('L2TP_NOT_INSTALLED');
            const group = await CascadeRouteGroup.findById(state.routeGroup).lean();
            const path = group?.paths?.find(p => p.pathKey === state.activePathKey && p.enabled !== false);
            if (!path?.linkIds?.length) fail('TOPOLOGY_L2TP_PATH_UNAVAILABLE');
            const link = await CascadeLink.findById(path.linkIds[0]).lean();
            if (String(link?.portalNode) !== nodeId) fail('TOPOLOGY_L2TP_PATH_UNAVAILABLE');
            const topology = await CascadeTopologyState.findById('singleton').lean();
            const plan = { ok: true, operationId, relayId: nodeId, routeGroupId: String(state.routeGroup),
                selectedPathKey: state.activePathKey, nextHopNodeId: String(link.bridgeNode), topologyRevision: topology.revision,
                desired: Object.fromEntries(['clientCidr','localAddress','poolStart','poolEnd','dnsServers','tproxyPort','fwmark','routeTable']
                    .map(k => [k, state[k]])), steps: STEPS.map(type => ({ type })) };
            plan.desired.credentialRevision = state.secretRevision;
            await L2tpOperation.create({ _id: operationId, node: nodeId, kind: 'repair', status: 'running',
                executionContext: authorization.executionContext, admissionId, leaseOwner: owner,
                leaseUntil: lock.leaseUntil, ownerGeneration: 1, attempts: 1, progress: 0,
                topologyRevision: plan.topologyRevision, routeGroupId: plan.routeGroupId,
                idempotencyKey: `normalize-main:${operationId}`, plan, startedAt: clock.now() });
            documentCreated = true;
            const fence = async () => {
                if (!same(state, await readState())) fail('MAIN_NORMALIZATION_STATE_CHANGED');
                const row = await lockService.repository.findByNode(nodeId);
                if (!row || row.generation !== lock.generation || row.owner !== owner || row.operationId !== operationId
                    || row.leaseUntil <= clock.now()) fail('NODE_OPERATION_LOCK_LOST');
            };
            phase = 'held_scope';
            const result = await candidateService.withLockedPreparation({ lock, lockService, clock,
                standaloneAdmission: { id: admissionId, repository: admissions } }, async () => {
                phase = 'state_fence';
                await fence();
                phase = 'prepare_normalization';
                await candidateService.prepareNormalization({ plan });
                phase = 'before_readback';
                const before = await candidateService.normalizationReadback(nodeId);
                phase = 'build_candidate';
                const candidate = await candidateService.buildCandidate({ plan });
                const content = candidate.content;
                if (typeof content !== 'string') fail('XRAY_CANDIDATE_FAILED');
                phase = 'resolve_transport';
                transport = await transportResolver({ nodeId, executionContext: authorization.executionContext });
                dispatched = true;
                await transport.uploadRootFile({ operationId, type: 'xrayCandidate', path: 'xray-candidate.json',
                    content, owner: 'root', group: 'root', mode: 0o600 });
                for (const command of STEPS) {
                    await fence();
                    const receipt = await transport.runArtifactCommand({ operationId, command });
                    if (receipt?.ok !== true) fail('MAIN_NORMALIZATION_COMMAND_FAILED');
                }
                const after = await candidateService.normalizationReadback(nodeId);
                if (after.mainHash !== sha(content) || after.active !== true || !same(before.protected, after.protected)) {
                    fail('MAIN_NORMALIZATION_READBACK_FAILED');
                }
                await fence();
                return { operationId, beforeHash: before.mainHash, candidateHash: sha(content),
                    mainHash: after.mainHash, protectedExact: true, steps: [...STEPS] };
            });
            const saved = await L2tpOperation.updateOne({ _id: operationId, status: 'running', leaseOwner: owner },
                { $set: { status: 'succeeded', progress: 100, finishedAt: clock.now(), leaseUntil: null } });
            if (saved.matchedCount !== 1) fail('MAIN_NORMALIZATION_SETTLEMENT_FAILED');
            const readback = await L2tpOperation.findById(operationId).lean();
            if (readback?.status !== 'succeeded' || readback.progress !== 100) fail('MAIN_NORMALIZATION_SETTLEMENT_FAILED');
            const released = await lockService.releaseVerified({ node: nodeId, owner, operationId, generation: lock.generation });
            if (released?.ok !== true) fail('MAIN_NORMALIZATION_RELEASE_FAILED');
            lock = null;
            await admissions.release(admissionId); completed = true;
            return { ...result, status: 'succeeded' };
        } catch (error) {
            if (documentCreated && !dispatched) await L2tpOperation.updateOne({ _id: operationId, status: 'running', leaseOwner: owner },
                { $set: { status: 'failed', finishedAt: clock.now(), leaseUntil: null, errorCode: error.code || 'MAIN_NORMALIZATION_REFUSED',
                    errorMessage: JSON.stringify(normalizationDiagnostic(error, phase)) } });
            if (dispatched || error.remoteOutcomeUncertain) {
                await admissions.markRecoveryRequired(admissionId);
                error.remoteOutcomeUncertain = true; // retained original journal/lock, never a fake rollback
            } else {
                if (lock) {
                    const released = await lockService.releaseVerified({ node: nodeId, owner, operationId, generation: lock.generation });
                    if (released?.ok !== true) { await admissions.markRecoveryRequired(admissionId); throw error; }
                }
                await admissions.release(admissionId); completed = true;
            }
            throw Object.assign(new Error(error.code || 'MAIN_NORMALIZATION_FAILED'), { code: error.code || 'MAIN_NORMALIZATION_FAILED', operationId });
        } finally {
            transport?.nodeSSH?.disconnect();
            // No background writer, optimistic release or implicit retry.
        }
    };
}
module.exports = { createL2tpMainNormalizer, normalizationProbe, normalizationDiagnostic, STEPS };
