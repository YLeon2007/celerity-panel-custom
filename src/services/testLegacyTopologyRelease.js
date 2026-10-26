'use strict';
// Internal finite TEST maintenance only. No model import, route or runtime DDL.
const { createHash, randomUUID } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const { BSON } = require('mongodb');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST, matchesTopologyExecutionContext }
    = require('../modules/relay-l2tp/domain/topologyExecutionContext');
const NODES = Object.freeze(['6ab189dc63913ebd4a917399', '6ab18adc63913ebd4a917471',
    '6ab18d9c63913ebd4a917670', '6ab4b53bc4c0304573e06c72', '6ab93ad2646b4b7d2f43c907']);
const PROFILES = Object.freeze({
    'xray-main': Object.freeze({ config: '/usr/local/etc/xray/config.json', unit: '/etc/systemd/system/xray.service', service: 'xray' }),
    'xray-bridge': Object.freeze({ config: '/usr/local/etc/xray-bridge/config.json', unit: '/etc/systemd/system/xray-bridge.service', service: 'xray-bridge' }),
});
const COLLECTION = 'testlegacytopologyreleases', ID = 'test-legacy-current-v1';
const DEPLOYMENT = Object.freeze({ database: 'hysteria', setName: 'rs0', replicaSetId: '6ab3717b28a9e4d82b5ee86a' });
const OPT = Object.freeze({ readPreference: 'primary', readConcern: { level: 'majority' }, maxTimeMS: 5000, timeoutMS: 5000 });
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const str = (v, re) => typeof v === 'string' && re.test(v);
const digest = v => str(v, /^[a-f0-9]{64}$/);
const nodeRef = v => (typeof v === 'string' || v instanceof BSON.ObjectId) && NODES.includes(String(v));
const exact = (v, keys) => v && Object.getPrototypeOf(v) === Object.prototype && same(Object.keys(v).sort(), [...keys].sort());
const need = ok => { if (!ok) throw Object.assign(new Error('TEST_LEGACY_RELEASE_UNKNOWN_RETAINED'), { code: 'TEST_LEGACY_RELEASE_UNKNOWN_RETAINED' }); };
const freeze = v => { if (v && typeof v === 'object') { Object.values(v).forEach(freeze); Object.freeze(v); } return v; };
// Canonical extended JSON retains BSON types, buffers and every unprojected
// history field. Object keys/documents are unordered; embedded arrays are not.
function canonical(value) {
    const sort = v => Array.isArray(v) ? v.map(sort) : v && typeof v === 'object'
        ? Object.fromEntries(Object.keys(v).sort().map(k => [k, sort(v[k])])) : v;
    return JSON.stringify(sort(BSON.EJSON.serialize(value, { relaxed: false })));
}
const hash = v => createHash('sha256').update(canonical(v)).digest('hex');
function flags(env) {
    return env?.TOPOLOGY_TEST_EXECUTION_ENABLED === 'false' && env?.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED === 'false'
        && ['test.infograd.online', 'lm1.infograd.online'].includes(env.PANEL_DOMAIN);
}
function deploymentValid(v) {
    return exact(v, ['database', 'setName', 'replicaSetId']) && typeof v.database === 'string' && v.database.length > 0
        && typeof v.setName === 'string' && v.setName.length > 0 && str(v.replicaSetId, /^[a-f0-9]{24}$/);
}
function artifact(v) {
    return exact(v, ['state']) && v.state === 'absent'
        || exact(v, ['state', 'sha256', 'uid', 'gid', 'mode']) && v.state === 'present' && digest(v.sha256)
            && [v.uid, v.gid, v.mode].every(Number.isSafeInteger) && v.uid >= 0 && v.gid >= 0 && v.mode >= 0 && v.mode <= 4095;
}
function baselineValid(v) {
    return Array.isArray(v) && v.length === NODES.length && v.every((n, i) => exact(n, ['node', 'nodeIdentity', 'profiles'])
        && n.node === NODES[i] && exact(n.nodeIdentity, ['machineId', 'sshHostKeySha256'])
        && str(n.nodeIdentity.machineId, /^[a-f0-9]{32}$/) && digest(n.nodeIdentity.sshHostKeySha256)
        && Array.isArray(n.profiles) && n.profiles.length === 2 && n.profiles.every((p, j) =>
            exact(p, ['profile', 'config', 'unit', 'additionalUnitFiles', 'serviceActive', 'serviceEnabled']) && p.profile === Object.keys(PROFILES)[j]
            && artifact(p.config) && artifact(p.unit) && ['active', 'inactive'].includes(p.serviceActive)
            && Array.isArray(p.additionalUnitFiles) && p.additionalUnitFiles.length <= 32
            && p.additionalUnitFiles.every((f, k, all) => exact(f, ['path', 'artifact'])
                && typeof f.path === 'string' && f.path.startsWith(PROFILES[p.profile].unit + '.d/')
                && /^[A-Za-z0-9_-][A-Za-z0-9_.-]*\.conf$/.test(f.path.slice((PROFILES[p.profile].unit + '.d/').length))
                && f.artifact?.state === 'present' && artifact(f.artifact) && (k === 0 || all[k - 1].path < f.path))
            && ['enabled', 'disabled', 'masked', 'not-found'].includes(p.serviceEnabled)
            && (p.unit.state !== 'absent' || p.serviceActive === 'inactive' && p.serviceEnabled === 'not-found')));
}
async function rows(db, name) {
    const found = await db.collection(name).find({}, { ...OPT, limit: 1001 }).toArray();
    need(Array.isArray(found) && found.length <= 1000);
    need(Buffer.byteLength(canonical(found)) <= 32 * 1024 * 1024);
    return found;
}
async function deployment(db) {
    const result = await db.admin().command({ replSetGetConfig: 1 }, { readPreference: 'primary', maxTimeMS: 5000, timeoutMS: 5000 });
    need(result.config?.settings?.replicaSetId instanceof BSON.ObjectId);
    const value = { database: db.databaseName, setName: result.config?._id, replicaSetId: String(result.config?.settings?.replicaSetId) };
    need(deploymentValid(value) && same(value, DEPLOYMENT)); return value;
}
async function snapshot(db, { maintenance, nodeId } = {}) {
    const names = ['topologyoperations', 'hynodes', 'topologyconfigowners', 'topologyexecutionenrollments',
        'topologyexecutionbindings', 'cascadetopologystates', 'remoteadmissions', 'nodeoperationlocks'];
    const values = await Promise.all(names.map(name => rows(db, name)));
    const [history, nodes, owners, enrollments, bindings, states, admissions, locks] = values;
    need(history.every(o => ['succeeded', 'failed', 'rolled_back'].includes(o.status)
        && (o.executionContext === undefined || matchesTopologyExecutionContext(o.executionContext, TEST))
        && Array.isArray(o.nodes) && o.nodes.every(n => nodeRef(n.node))
        && o.heldTopologyAdmission !== true && (o.heldTopologyAdmission === undefined || o.heldTopologyAdmission === false)
        && o.pppWait === undefined && o.v2Terminal === undefined));
    // No adoption/handback invention: this bounded legacy installation has none.
    need(owners.length === 0 && enrollments.length === 0 && bindings.length === 0);
    need(nodes.length === 5 && nodes.every(n => nodeRef(n._id)) && same(nodes.map(n => String(n._id)).sort(), NODES));
    const nodeBindings = nodes.map(n => {
        need(typeof n.ip === 'string' && n.ip.length > 0 && n.ssh && typeof n.ssh === 'object' && !Array.isArray(n.ssh));
        return { node: String(n._id), endpointCredentialSha256: hash({ ip: n.ip, ssh: n.ssh,
            // Do not bind mutable generated config/user/service status forever.
            agentToken: n.xray?.agentToken, paths: n.paths, type: n.type, virtual: n.virtual }) };
    }).sort((a, b) => a.node.localeCompare(b.node));
    need(states.length === 1 && states[0]._id === 'singleton' && states[0].topologyAdmissionCount === 0
        && Number.isSafeInteger(states[0].remoteAdmissionCount) && states[0].remoteAdmissionCount >= 0
        && states[0].remoteDrain === undefined && states[0].replacementReservation === undefined);
    need(admissions.every(a => ['completed', 'running', 'queued', 'recovery_required'].includes(a.phase)));
    const active = admissions.filter(a => a.phase !== 'completed');
    need(active.length === states[0].remoteAdmissionCount);
    if (maintenance) {
        need(active.length === 0 && locks.length === 0);
        const [intents, queues, l2tp] = await Promise.all(['topologycreateintents', 'topologyintentqueuestates', 'l2tpoperations'].map(n => rows(db, n)));
        need(intents.every(o => ['succeeded', 'failed'].includes(o.status))
            && (queues.length === 0 || queues.length === 1 && queues[0]._id === 'create-v1' && queues[0].outstanding === 0)
            && l2tp.every(o => ['succeeded', 'failed', 'rolled_back', 'cancelled'].includes(o.status)));
    } else if (locks.length || active.length) {
        // Recognition is not lock/admission authority. Only an already-held
        // server-owned classic/L2TP scope may pass its OWN current generation.
        need(locks.length === 1 && String(locks[0].node) === nodeId);
        await require('./classicNodeConfigWrite').assertHeldL2tpNodeConfigWrite(nodeId);
        need(active.every(a => a.phase === 'running' && a.nodeId === nodeId && a.operationId === locks[0].operationId));
    }
    const historySha256 = hash(history.map(canonical).sort());
    return { deployment: await deployment(db), historySha256, nodeBindings };
}
function validReceipt(r) {
    return exact(r, ['_id', 'version', 'executionContext', 'panelHost', 'deployment', 'nodeBindings', 'historySha256',
        'acceptedBaseline', 'proofId', 'maintenanceId', 'oldBackend', 'acceptedAt'])
        && r._id === ID && r.version === 1 && matchesTopologyExecutionContext(r.executionContext, TEST)
        && ['test.infograd.online', 'lm1.infograd.online'].includes(r.panelHost) && same(r.deployment, DEPLOYMENT)
        && digest(r.historySha256) && Array.isArray(r.nodeBindings) && r.nodeBindings.length === 5
        && r.nodeBindings.every((n, i) => exact(n, ['node', 'endpointCredentialSha256']) && n.node === NODES[i] && digest(n.endpointCredentialSha256))
        && baselineValid(r.acceptedBaseline) && str(r.proofId, UUID) && str(r.maintenanceId, UUID)
        && exact(r.oldBackend, ['instanceId', 'pid', 'processStartTime', 'processTree', 'dispatch'])
        && typeof r.oldBackend.instanceId === 'string' && r.oldBackend.instanceId.length > 0
        && Number.isSafeInteger(r.oldBackend.pid) && r.oldBackend.pid > 0
        && typeof r.oldBackend.processStartTime === 'string' && r.oldBackend.processStartTime.length > 0
        && r.oldBackend.processTree === 'stopped' && r.oldBackend.dispatch === 'disabled'
        && r.acceptedAt instanceof Date && Number.isFinite(r.acceptedAt.getTime());
}
async function hasTestLegacyTopologyRelease({ db, nodeId, env = process.env }) {
    if (!NODES.includes(nodeId) || !flags(env)) return false;
    const selectedEnv = { ...env };
    const found = await rows(db, COLLECTION);
    if (!found.length) return false;
    need(found.length === 1 && validReceipt(found[0]));
    const r = found[0];
    need(r.panelHost === selectedEnv.PANEL_DOMAIN);
    const current = await snapshot(db, { nodeId });
    need(same(current, { deployment: r.deployment, historySha256: r.historySha256, nodeBindings: r.nodeBindings }));
    return true;
}
class TestLegacyTopologyRelease {
    #db; #authority; #deployment; #baseline; #env; #used = false;
    constructor({ db, executionContext, expectedDeployment, acceptedBaseline, withVerifiedMaintenance, env = process.env } = {}) {
        need(db && typeof db.collection === 'function' && matchesTopologyExecutionContext(executionContext, TEST)
            && deploymentValid(expectedDeployment) && same(expectedDeployment, DEPLOYMENT) && baselineValid(acceptedBaseline) && flags(env)
            && typeof withVerifiedMaintenance === 'function');
        this.#db = db; this.#authority = withVerifiedMaintenance; this.#env = env;
        this.#deployment = freeze(structuredClone(expectedDeployment)); this.#baseline = freeze(structuredClone(acceptedBaseline));
    }
    async retire() {
        need(!this.#used); this.#used = true;
        const initial = await snapshot(this.#db, { maintenance: true });
        need(flags(this.#env) && same(initial.deployment, this.#deployment));
        need((await rows(this.#db, COLLECTION)).length === 0);
        const binding = freeze({ version: 1, action: 'accept-current-test-legacy-baseline', receiptId: ID, nonce: randomUUID(),
            executionContext: TEST, panelHost: this.#env.PANEL_DOMAIN, ...initial, acceptedBaseline: this.#baseline,
            paths: PROFILES, deadline: Date.now() + 300000 });
        let open = true, invoked = false, finished = false, poisoned = false, pending, confirmed;
        const callback = proof => {
            if (!open || invoked) { poisoned = true; need(false); }
            invoked = true;
            pending = (async () => {
                need(proof?.authority === 'test-legacy-maintenance-v1' && same(proof.binding, binding)
                    && typeof proof.recheck === 'function');
                const check = async () => {
                    try {
                        need(open && !poisoned && Date.now() < binding.deadline && flags(this.#env) && this.#env.PANEL_DOMAIN === binding.panelHost);
                        const observed = await proof.recheck(binding);
                        need(open && !poisoned && Date.now() < binding.deadline && same(observed, this.#baseline)
                            && flags(this.#env) && this.#env.PANEL_DOMAIN === binding.panelHost);
                    } catch (e) { poisoned = true; throw e; }
                };
                const fresh = async () => {
                    await check(); const now = await snapshot(this.#db, { maintenance: true });
                    await check(); need(same(now, initial));
                };
                await fresh();
                const receipt = { _id: ID, version: 1, executionContext: TEST, panelHost: binding.panelHost, ...initial,
                    acceptedBaseline: this.#baseline, proofId: proof.proofId, maintenanceId: proof.maintenanceId,
                    oldBackend: structuredClone(proof.oldBackend), acceptedAt: new Date() };
                need(validReceipt(receipt));
                // Only this verified maintenance scope provisions the namespace.
                // Existing/foreign namespace is not silently adopted or repaired.
                await check();
                const namespaces = await this.#db.listCollections({ name: COLLECTION },
                    { nameOnly: true, readPreference: 'primary', maxTimeMS: 5000, timeoutMS: 5000 }).toArray();
                need(Array.isArray(namespaces) && namespaces.length === 0); await check();
                await this.#db.createCollection(COLLECTION, { writeConcern: { w: 'majority' }, maxTimeMS: 5000, timeoutMS: 5000 });
                await fresh();
                need((await rows(this.#db, COLLECTION)).length === 0); await check();
                need((await this.#db.collection(COLLECTION).insertOne(receipt,
                    { writeConcern: { w: 'majority' }, maxTimeMS: 5000, timeoutMS: 5000 })).acknowledged === true);
                await fresh();
                const found = await rows(this.#db, COLLECTION);
                need(found.length === 1 && same(found[0], receipt)); await check();
                confirmed = found[0]; finished = true;
            })();
            return pending;
        };
        try { await this.#authority({ binding }, callback); need(finished && !poisoned); }
        finally { open = false; if (pending) await pending.catch(() => {}); }
        need(invoked && finished); return confirmed;
    }
}
module.exports = { TestLegacyTopologyRelease, hasTestLegacyTopologyRelease };
