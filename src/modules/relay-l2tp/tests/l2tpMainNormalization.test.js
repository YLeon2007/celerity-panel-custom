'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createL2tpMainNormalizer, STEPS } = require('../services/l2tpMainNormalization');
test('normalization diagnostic retains allowlisted source location, never arbitrary error text or secrets',()=>{
 const {normalizationDiagnostic}=require('../services/l2tpMainNormalization');
 const error=new TypeError('secret mongodb://credentials/config bytes');
 error.stack='TypeError: secret\n    at Object.prepare (/app/src/modules/relay-l2tp/services/topologyL2tpInstallComposition.js:104:47)\n    at /private/secret.js:1:2';
 assert.deepEqual(normalizationDiagnostic(error,'prepare_normalization'),{phase:'prepare_normalization',name:'TypeError',sourceFrame:'src/modules/relay-l2tp/services/topologyL2tpInstallComposition.js:104:47'});
 error.code='secret://token';assert.equal(JSON.stringify(normalizationDiagnostic(error,'held_scope')).includes('secret'),false);
});
const id = n => n.toString(16).padStart(24, '0');
function fixture(options = {}) {
 const calls = [], state = { node: id(1), status: 'installed', desiredState: 'installed', routeGroup: id(2), activePathKey: 'main', secretRevision: 2, tproxyPort: 12345 };
 const q = value => ({ select() { return this; }, async lean() { return structuredClone(value); } });
 let operation, released = false, recovered = false;
 const content = '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}';
 const digest = createHash('sha256').update(content).digest('hex');
 const lock = { node: id(1), generation: 'g1', leaseUntil: new Date(Date.now()+120000) };
 const deps = {
  authorization: { executionContext: { target: 'test', hostIdentity: 'test.infograd.online' } },
  RelayL2tpState: { findOne: () => q(options.notInstalled ? null : state) },
  CascadeRouteGroup: { findById: () => q({ paths: [{ pathKey: 'main', linkIds: [id(3)] }] }) },
  CascadeLink: { findById: () => q({ portalNode: id(1), bridgeNode: id(4) }) },
  CascadeTopologyState: { findById: () => q({ revision: 2 }) },
  L2tpOperation: { async create(value) { operation = structuredClone(value); calls.push('durable-repair'); },
   async updateOne(filter, update) { Object.assign(operation, update.$set); return { matchedCount: 1 }; }, findById: () => q(operation) },
  remoteAdmissionRepository: { async acquire() { calls.push('counted-admission'); return 'admission'; },
   async release() { calls.push('release-admission'); released = true; }, async markRecoveryRequired() { calls.push('retain-admission'); recovered = true; } },
  lockService: { async acquire(value) { Object.assign(lock, value); calls.push('lock'); return { ok: true, lock }; },
   repository: { async findByNode() { return lock; } }, async releaseVerified() { calls.push('release-lock'); return { ok: true }; } },
  candidateService: { async withLockedPreparation(request, callback) { assert.equal(request.standaloneAdmission.id, 'admission'); return callback(); },
   async prepareNormalization() { calls.push('real-ingress-proof'); if (options.missingIngress) throw Object.assign(new Error('missing'), { code: 'TOPOLOGY_L2TP_PATH_UNAVAILABLE' }); },
   async normalizationReadback() { const after = calls.includes('activate_xray'); return { mainHash: after ? digest : 'before', active: true,
    protected: { ppp: options.drift && after ? 'changed' : 'exact', sidecar: 'exact' } }; },
   async buildCandidate() { calls.push('native-composition'); return { content }; } },
  async transportResolver() { return { async uploadRootFile(request) { assert.equal(request.mode, 0o600); calls.push('upload'); },
   async runArtifactCommand({ command }) { calls.push(command); return { ok: true }; }, nodeSSH: { disconnect() { calls.push('disconnect'); } } }; },
  clock: { now: () => new Date() },
 };
 return { deps, run: createL2tpMainNormalizer(deps), calls, operation: () => operation, released: () => released, recovered: () => recovered };
}
test('MAIN normalizer satisfies the real native transport command contract, not only a stub',async()=>{
 const f=fixture(),{L2tpNodeTransport}=require('../services/l2tpNodeTransport');
 f.deps.transportResolver=async()=>new L2tpNodeTransport({executionContext:f.deps.authorization.executionContext,nodeSSH:{
  async exec(command){f.calls.push(command.includes('artifact-receiver')?'upload':command.match(/--command ([a-z_]+)/)[1]);return {code:0,stdout:'',stderr:''};},disconnect(){f.calls.push('disconnect');}
 }});
 const result=await createL2tpMainNormalizer(f.deps)(id(1));assert.equal(result.status,'succeeded');assert.deepEqual(f.calls.filter(x=>STEPS.includes(x)),STEPS);
});
test('MAIN normalization uses native backup/compose/validate/activate only; no install, account, PSK or LNS replay', async () => {
 const f = fixture(), result = await f.run(id(1));
 assert.equal(result.status, 'succeeded'); assert.equal(result.protectedExact, true);
 assert.deepEqual(result.steps, STEPS); assert.equal(f.operation().kind, 'repair');
 assert.equal(f.operation().status, 'succeeded'); assert.equal(f.released(), true); assert.equal(f.recovered(), false);
 assert.deepEqual(f.calls, ['counted-admission','lock','durable-repair','real-ingress-proof','native-composition','upload',...STEPS,'release-lock','release-admission','disconnect']);
});
test('missing live ingress refuses before upload and releases only positively undispatched operation', async () => {
 const f = fixture({ missingIngress: true }); await assert.rejects(f.run(id(1)), { code: 'TOPOLOGY_L2TP_PATH_UNAVAILABLE' });
 assert.equal(f.calls.includes('upload'), false); assert.equal(f.operation().status, 'failed'); assert.equal(f.released(), true);
});
test('PPP/SIDECAR drift after MAIN activation retains original native journal/admission/lock; never fake success', async () => {
 const f = fixture({ drift: true }); await assert.rejects(f.run(id(1)), { code: 'MAIN_NORMALIZATION_READBACK_FAILED' });
 assert.equal(f.operation().status, 'running'); assert.equal(f.recovered(), true); assert.equal(f.released(), false); assert.equal(f.calls.includes('release-lock'), false);
});
test('not-installed relay cannot use MAIN-only repair', async () => {
 const f = fixture({ notInstalled: true }); await assert.rejects(f.run(id(1)), { code: 'L2TP_NOT_INSTALLED' }); assert.equal(f.calls.includes('upload'), false); assert.equal(f.released(), true);
});
