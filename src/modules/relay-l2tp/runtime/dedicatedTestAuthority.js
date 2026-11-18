'use strict';
// Supported, opt-in TEST activation for genuinely dedicated Linux node runtimes.
// Shared-host migration remains on the existing physical-authority path. A
// hostname/flag, missing DB row or empty client list does not qualify a runtime.
const fs = require('node:fs');
const { createHash, randomUUID } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');
const { freeze, UUID, validTerminalReceipt } = require('../models/topologyExecutionBindingContract');
const CONFIG = '/etc/celerity/topology-test-dedicated.json';
const sha = x => createHash('sha256').update(x).digest('hex');
function fail(code = 'TOPOLOGY_TEST_DEDICATED_UNPROVEN') { throw Object.assign(new Error(code), { code }); }
function need(x) { if (!x) fail(); }
function privateRead(p) {
    for (let q = p;; q = require('node:path').dirname(q)) {
        const s = fs.lstatSync(q); need(s.uid === 0 && !(s.mode & 0o022) && !s.isSymbolicLink());
        if (q === '/') break;
    }
    const f = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try { const s = fs.fstatSync(f); need(s.isFile() && !(s.mode & 0o007) && s.size < 1048576); return fs.readFileSync(f); }
    finally { fs.closeSync(f); }
}
function validate(config) {
    need(config?.version === 1 && same(config.executionContext, TEST)
        && /^[a-f0-9]{64}$/.test(config.applicationSha256)
        && config.predecessor?.status === 'joined-and-removed' && config.predecessor.exit === 0
        && Number.isSafeInteger(config.predecessor.pid) && config.predecessor.pid > 1
        && /^[0-9]+$/.test(config.predecessor.processStartTime)
        && /^[a-f0-9]{64}$/.test(config.predecessor.instanceId)
        && Array.isArray(config.nodes) && config.nodes.length > 0 && config.nodes.length <= 8);
    for (const field of ['nodeId', 'machineId', 'hostKeySha256']) {
        need(new Set(config.nodes.map(n => n[field])).size === config.nodes.length);
    }
    need(new Set(config.nodes.map(n => n.endpoint.ip + ':' + n.endpoint.port)).size === config.nodes.length);
    for (const n of config.nodes) {
        need(/^[a-f0-9]{24}$/.test(n.nodeId) && ['xray-main', 'xray-bridge'].includes(n.targetProfile)
            && /^[a-f0-9]{32}$/.test(n.machineId) && /^[a-f0-9]{64}$/.test(n.hostKeySha256)
            && /^[a-f0-9]{64}$/.test(n.provisionSha256) && UUID.test(n.maintenanceId)
            && require('node:net').isIP(n.endpoint?.ip) && n.endpoint.port === 2223
            && n.endpoint.username === 'root' && typeof n.privateKeyPath === 'string'
            && n.privateKeyPath.startsWith('/etc/celerity/'));
    }
    if (config.bootstrapFailure !== undefined) {
        const b = config.bootstrapFailure;
        need(/^[a-f0-9]{24}$/.test(b.operationId) && b.failureCode === 'SFTP_SUBSYSTEM_UNAVAILABLE'
            && b.hostBootId === config.hostBootId && /^[a-f0-9]{64}$/.test(b.appLogSha256)
            && typeof b.finishedAt === 'string' && Number.isFinite(Date.parse(b.finishedAt))
            && b.stoppedApp?.status === 'exited' && b.stoppedApp.pid === 0 && b.stoppedApp.exitCode === 1
            && /^[a-f0-9]{64}$/.test(b.stoppedApp.id));
    }
    return freeze(structuredClone(config));
}
async function connect(pin, read) {
    const { Client } = require('ssh2'); const client = new Client();
    const readyTimeout = 10000;
    const channel = await new Promise((resolve, reject) => {
        let settled = false;
        const finish = (error, stream) => {
            if (settled) return;
            settled = true; clearTimeout(timer);
            if (error) reject(error); else resolve(stream);
        };
        // ssh2 clears readyTimeout on authentication, before exec is acknowledged.
        // Keep one setup budget across both waits; no re-open after expiry.
        const timer = setTimeout(() => finish(new Error('DEDICATED_AUTHORITY_OPEN_TIMEOUT')), readyTimeout);
        client.on('error', finish);
        client.once('close', () => finish(new Error('CHANNEL_LOST')));
        client.once('ready', () => {
            if (settled) return;
            try {
                client.exec('/usr/bin/python3 -I -B /usr/local/libexec/celerity-test-dedicated-node', (e, stream) => finish(e, stream));
            } catch (e) { finish(e); }
        });
        try {
            client.connect({ host: pin.endpoint.ip, port: pin.endpoint.port, username: pin.endpoint.username,
                privateKey: read(pin.privateKeyPath), readyTimeout,
                // Liveness must not undercut the existing 10s observation deadline.
                keepaliveInterval: 1000, keepaliveCountMax: 12,
                hostVerifier: b => Buffer.isBuffer(b) && sha(b) === pin.hostKeySha256 });
        } catch (e) { finish(e); }
    }).catch(e => { client.destroy(); throw e; });
    let alive = true, buffer = '', pending;
    const close = () => { alive = false; pending?.reject(new Error('CHANNEL_LOST')); pending = undefined; client.end(); };
    channel.on('close', close); channel.on('error', close); channel.stderr.on('data', close);
    channel.on('data', b => {
        buffer += b.toString(); if (buffer.length > 8388608) return close();
        let i;
        while ((i = buffer.indexOf('\n')) >= 0) {
            const line = buffer.slice(0, i); buffer = buffer.slice(i + 1);
            try { const v = JSON.parse(line); need(pending && v.nonce === pending.nonce); const p = pending; pending = undefined; p.resolve(v); }
            catch { close(); }
        }
    });
    return { get alive() { return alive; }, close,
        async originals(value) { return (await this.observe(undefined, undefined, undefined, value)).originals; },
        async observe(cancelPrepare, noDispatch, nativeCloseAbsent, originals) {
        need(alive && !pending); const nonce = randomUUID(); let timeout;
        try { return await new Promise((resolve, reject) => { timeout = setTimeout(() => { close(); reject(new Error('OBSERVATION_TIMEOUT')); }, originals ? 130000 : 10000); pending = { nonce, resolve, reject }; channel.write(JSON.stringify({ nonce, ...(cancelPrepare ? { cancelPrepare } : {}), ...(noDispatch ? { noDispatch } : {}), ...(nativeCloseAbsent ? { nativeCloseAbsent } : {}), ...(originals ? { originals } : {}) }) + '\n'); }); }
        finally { clearTimeout(timeout); }
    } };
}
function createDedicatedTestAuthority({ config: input, read = privateRead, open = pin => connect(pin, read), predecessorAbsent } = {}) {
    const config = validate(input);
    const absent = predecessorAbsent ?? (() => {
        // A missing bind mount is not proof of an absent process. The ordinary
        // app container mounts the real host proc read-only at this fixed path.
        need(fs.statfsSync('/hostproc').type === 0x9fa0);
        need(fs.readFileSync('/hostproc/sys/kernel/random/boot_id', 'utf8').trim() === config.hostBootId);
        need(fs.readFileSync('/hostproc/1/stat', 'utf8').length > 0);
        return !fs.existsSync('/hostproc/' + config.predecessor.pid);
    });
    let busy = false, poisoned = false, enrolled = false;
    // Explicit internal capture opts into one retained transport/OFD epoch.
    // Ordinary dedicated startup keeps its prior per-invocation semantics.
    let retaining = false, dispatchClosed = false;
    const retainedChannels = new Map(), originals = new Map();
    let classicRestore;
    return Object.freeze({ executionContext: TEST,
        async withHeldAuthority(context, work) {
            need(same(context, TEST) && !busy && !poisoned && absent()); busy = true;
            const channels = retaining ? retainedChannels : new Map(); let openScope = true;
            const startedAt = Date.now(); let refreshCount = 0, observationCount = 0, maxObservationMs = 0;
            const observations = new Map();
            const refresh = async () => {
                refreshCount++;
                need(openScope && !poisoned && absent());
                await Promise.all(config.nodes.map(async n => {
                    const before = Date.now();
                    const c = channels.get(n.nodeId); need(c?.alive); const v = await c.observe();
                    observationCount++; maxObservationMs = Math.max(maxObservationMs, Date.now() - before);
                    need(openScope && c.alive && v.provision?.nodeId === n.nodeId
                        && v.provision.targetProfile === n.targetProfile && v.provision.machineId === n.machineId
                        && v.provision.applicationSha256 === config.applicationSha256
                        && sha(JSON.stringify(v.provision)) === n.provisionSha256 && UUID.test(v.bootId));
                    observations.set(n.nodeId, v);
                    const original = originals.get(n.nodeId);
                    if (original && !original.released) {
                        const held = await c.originals({ action: original.restored ? 'verify' : 'read' });
                        need(c.alive && held.epoch === original.epoch && same(held.holder, original.holder)
                            && held.bundleSha256 === original.bundleSha256 && held.ownerGeneration === original.generation
                            && held.holder.bootId === v.bootId);
                    }
                }));
            };
            const oldBackend = freeze({ processTree: 'stopped', dispatch: 'disabled',
                instanceId: config.predecessor.instanceId, pid: config.predecessor.pid,
                processStartTime: config.predecessor.processStartTime });
            const pinFor = id => { const n = config.nodes.find(n => n.nodeId === id); need(n); return n; };
            try {
                for (const n of config.nodes) if (!channels.has(n.nodeId)) channels.set(n.nodeId, await open(n));
                await refresh();
                return await work(Object.freeze({ assertHeld: refresh,
                    async captureOriginals() {
                        await refresh();
                        need(retaining && !dispatchClosed && originals.size === 0);
                        for (const n of config.nodes) {
                            const held = await channels.get(n.nodeId).originals({ action: 'capture' });
                            need(UUID.test(held.epoch) && /^[a-f0-9]{64}$/.test(held.bundleSha256)
                                && held.phase === 'captured-held' && held.ownerGeneration === null
                                && held.holder.nodeId === n.nodeId && held.holder.machineId === n.machineId
                                && held.holder.targetProfile === n.targetProfile && held.holder.bootId === observations.get(n.nodeId).bootId
                                && same(held.readback, observations.get(n.nodeId).provision.originalSnapshot));
                            originals.set(n.nodeId, { ...held, generation: null, restored: false, handed: false, released: false });
                        }
                        await refresh();
                        return freeze(config.nodes.map(n => ({ nodeId:n.nodeId, epoch:originals.get(n.nodeId).epoch,
                            holder:originals.get(n.nodeId).holder, maintenanceId:n.maintenanceId, bundleSha256:originals.get(n.nodeId).bundleSha256 })));
                    },
                    async readOriginalRestoreCurrent() {
                        await refresh();
                        need(dispatchClosed && originals.size === config.nodes.length); const pins = {};
                        for (const n of config.nodes) pins[n.nodeId] = await channels.get(n.nodeId).originals({action:'current'});
                        await refresh(); return freeze(pins);
                    },
                    async restoreOriginals(pins) {
                        await refresh();
                        need(dispatchClosed && originals.size === config.nodes.length && pins
                            && same(Object.keys(pins).sort(), config.nodes.map(n=>n.nodeId).sort()));
                        // All participants acquire/validate actual CURRENT before any stop/write.
                        for (const n of config.nodes) {
                            const o=originals.get(n.nodeId); need(o.generation && !o.restored);
                            const held=await channels.get(n.nodeId).originals({action:'prepare',epoch:o.epoch,
                                ownerGeneration:o.generation,current:pins[n.nodeId]});
                            need(held.epoch===o.epoch && same(held.holder,o.holder) && held.ownerGeneration===o.generation);
                        }
                        for (const n of config.nodes) {
                            const o=originals.get(n.nodeId), held=await channels.get(n.nodeId).originals({action:'restore'});
                            need(held.phase==='restored-held' && held.epoch===o.epoch && same(held.holder,o.holder)
                                && held.bundleSha256===o.bundleSha256 && held.ownerGeneration===o.generation);
                            o.restored=true;
                        }
                        await refresh();
                    },
                    async releaseOriginals() {
                        await refresh();
                        need(dispatchClosed && config.nodes.every(n=>originals.get(n.nodeId)?.handed));
                        await refresh();
                        for (const n of config.nodes) {
                            const o=originals.get(n.nodeId), r=await channels.get(n.nodeId).originals({action:'release'});
                            need(r.phase==='handback-released' && r.epoch===o.epoch && r.ownerGeneration===o.generation);
                            o.released=true;
                        }
                    },
                    async readCurrentHealth() {
                        await refresh();
                        return freeze(config.nodes.map(n=>{
                            const v=observations.get(n.nodeId),j=v.journal,g=j?.generations?.[j.head],p=v.current[n.targetProfile];
                            return {nodeId:n.nodeId,endpoint:n.endpoint,configSha256:p?.configSha256,healthy:g?.phase==='closed'
                                && g.binding.nodeId===n.nodeId && g.binding.candidateHash==='sha256:'+p.configSha256
                                && p.serviceActive==='active' && v.runnerIdle===true};
                        }));
                    },
                    async withCapturedTestOwnerEnrollment(callback) {
                        need(!enrolled); await refresh();
                        const nodes = config.nodes.map(n => {
                            const v = observations.get(n.nodeId); need(v.journal === null);
                            const snapshot = v.current[n.targetProfile];
                            need(same(snapshot, v.provision.originalSnapshot));
                            return freeze({ nodeId: n.nodeId, targetProfile: n.targetProfile, endpoint: n.endpoint,
                                bootstrapPristine: v.bootstrapPristine === true,
                                l2tpUnconfigured: v.l2tpUnconfigured === true,
                                nodeIdentity: { machineId: n.machineId, sshHostKeySha256: n.hostKeySha256 }, bootId: v.bootId,
                                originalSnapshot: { proofRef: 'dedicated-' + n.maintenanceId, ...Object.fromEntries(Object.entries(snapshot).filter(([k]) => k !== 'source')) } });
                        });
                        const result = await callback(freeze({ nodes, ...(config.bootstrapFailure ? { bootstrapFailure: config.bootstrapFailure } : {}) }), refresh); enrolled = true; return result;
                    },
                    async withBootstrapCancellation({ operationId, bindings, readOnly = false, reservations = [] }, callback) {
                        need(config.bootstrapFailure?.operationId === operationId && Array.isArray(bindings) && bindings.length > 0);
                        await refresh();
                        for (const n of config.nodes) need(same(observations.get(n.nodeId).current[n.targetProfile], observations.get(n.nodeId).provision.originalSnapshot));
                        const proofs = [];
                        for (const b of bindings) {
                            const n = pinFor(b.nodeId), v = observations.get(b.nodeId);
                            need(b.operationId === operationId && b.executionContext === TEST.hostIdentity && b.bootId === v.bootId
                                && b.targetProfile === n.targetProfile && same(b.nodeIdentity, { machineId: n.machineId, sshHostKeySha256: n.hostKeySha256 }));
                            const reply = readOnly ? { terminalProof: { ...v.journal?.generations?.[b.generation]?.commands?.[b.commandIds.close]?.receipt, command: 'status' } }
                                : await channels.get(b.nodeId).observe(b);
                            need(validTerminalReceipt(reply.terminalProof, b) && reply.terminalProof.terminalOutcome === 'cancelled');
                            proofs.push(freeze(reply.terminalProof));
                        }
                        await refresh();
                        for (let i = 0; i < bindings.length; i++) {
                            const b = bindings[i], j = observations.get(b.nodeId).journal, g = j?.generations?.[b.generation];
                            need(j?.head === b.generation && g?.phase === 'closed'
                                && same({ ...g.commands[b.commandIds.close].receipt, command: 'status' }, proofs[i]));
                        }
                        const noDispatch = [];
                        need(!reservations.length || readOnly);
                        for (const reservation of reservations) {
                            const n = pinFor(reservation.nodeId);
                            const v = await channels.get(n.nodeId).observe(undefined, reservation);
                            need(same(v.noDispatch, { ...reservation, bootId: observations.get(n.nodeId).bootId,
                                runnerIdle:true, generationAbsent:true, operationAbsent:true, backupAbsent:true }));
                            noDispatch.push(v.noDispatch);
                        }
                        await refresh();
                        return callback(freeze({ proofs, noDispatch, inventory: config.nodes.map(n => ({nodeId:n.nodeId, targetProfile:n.targetProfile, endpoint:n.endpoint, bootId:observations.get(n.nodeId).bootId, nodeIdentity:{machineId:n.machineId,sshHostKeySha256:n.hostKeySha256}})) }), refresh);
                    },
                    async withAbsentSuccessorCancellation({ bindings, reservations }, callback) {
                        need(Array.isArray(bindings) && bindings.length > 0 && bindings.length <= config.nodes.length
                            && bindings.length === reservations.length && new Set(bindings.map(b => b.nodeId)).size === bindings.length);
                        await refresh();
                        const before = new Map();
                        // Validate every participant before the first native close.
                        for (const b of bindings) {
                            const n = pinFor(b.nodeId), v = observations.get(b.nodeId), j = v.journal;
                            const prior = j?.generations?.[b.predecessorGeneration], g = j?.generations?.[b.generation];
                            need(b.executionContext === TEST.hostIdentity && b.bootId === v.bootId && b.targetProfile === n.targetProfile
                                && b.maintenanceId === n.maintenanceId && same(b.endpoint, n.endpoint)
                                && same(b.nodeIdentity, { machineId: n.machineId, sshHostKeySha256: n.hostKeySha256 })
                                && v.runnerIdle === true && prior?.phase === 'closed'
                                && same({ ...prior.commands?.[b.predecessorReceipt?.commandId]?.receipt, command:'status' }, b.predecessorReceipt)
                                && prior.binding.candidateHash === 'sha256:' + v.current[n.targetProfile].configSha256
                                && v.current[n.targetProfile].serviceActive === 'active'
                                && (g ? j.head === b.generation && g.phase === 'closed'
                                    && Object.keys(g.commands).length === 1
                                    && validTerminalReceipt({ ...g.commands[b.commandIds.close]?.receipt, command: 'status' }, b)
                                    && g.commands[b.commandIds.close].receipt.terminalOutcome === 'cancelled'
                                    : j.head === b.predecessorGeneration));
                            if (!g) {
                                const r = Object.fromEntries(['nodeId','operationId','generation','backupId','targetProfile'].map(k => [k,b[k]]));
                                const p = await channels.get(b.nodeId).observe(undefined, r);
                                need(same(p.noDispatch, { ...r, bootId:b.bootId, runnerIdle:true, generationAbsent:true, operationAbsent:true, backupAbsent:true }));
                            }
                            const next = reservations.find(r => r.nodeId === b.nodeId);
                            need(next && next.targetProfile === b.targetProfile && next.operationId !== b.operationId);
                            const nextRead = await channels.get(b.nodeId).observe(undefined, next);
                            need(same(nextRead.noDispatch, { ...next, bootId:b.bootId, runnerIdle:true, generationAbsent:true, operationAbsent:true, backupAbsent:true }));
                            before.set(b.nodeId, v.current);
                        }
                        const proofs = [];
                        for (const b of bindings) {
                            const reply = await channels.get(b.nodeId).observe(undefined, undefined, b);
                            need(validTerminalReceipt(reply.terminalProof, b) && reply.terminalProof.terminalOutcome === 'cancelled');
                            proofs.push(reply.terminalProof);
                        }
                        await refresh();
                        const noDispatch = [];
                        for (let i=0; i<bindings.length; i++) {
                            const b=bindings[i], v=observations.get(b.nodeId), g=v.journal?.generations?.[b.generation], r=reservations[i];
                            need(v.journal.head === b.generation && g?.phase === 'closed' && same(v.current,before.get(b.nodeId))
                                && same({ ...g.commands[b.commandIds.close]?.receipt, command:'status' },proofs[i])
                                && r.nodeId === b.nodeId && r.targetProfile === b.targetProfile);
                            const p=await channels.get(b.nodeId).observe(undefined,r);
                            need(same(p.noDispatch,{...r,bootId:b.bootId,runnerIdle:true,generationAbsent:true,operationAbsent:true,backupAbsent:true}));
                            noDispatch.push(p.noDispatch);
                        }
                        return callback(freeze({proofs,noDispatch}),refresh);
                    },
                    async withUndispatchedPreparation(bindings, callback) {
                        need(Array.isArray(bindings) && bindings.length > 0 && bindings.length <= config.nodes.length
                            && new Set(bindings.map(b => b.nodeId)).size === bindings.length);
                        await refresh(); const nodes = [];
                        for (const b of bindings) {
                            const n = pinFor(b.nodeId), v = observations.get(b.nodeId);
                            need(b.executionContext === TEST.hostIdentity && b.bootId === v.bootId && b.targetProfile === n.targetProfile
                                && b.maintenanceId === n.maintenanceId && same(b.endpoint,n.endpoint)
                                && same(b.nodeIdentity,{machineId:n.machineId,sshHostKeySha256:n.hostKeySha256}));
                            const reservation = Object.fromEntries(['nodeId','operationId','generation','backupId','targetProfile'].map(k=>[k,b[k]]));
                            const p = await channels.get(n.nodeId).observe(undefined,reservation);
                            need(p.bootId === v.bootId && p.runnerIdle === true && same(p.journal,v.journal) && same(p.current,v.current));
                            nodes.push({nodeId:b.nodeId,bootId:p.bootId,runnerIdle:p.runnerIdle,noDispatch:p.noDispatch,journal:p.journal,current:p.current});
                        }
                        return callback(freeze({nodes}),refresh);
                    },
                    async withRetainedVerifyObservation(bindings, callback) {
                        need(Array.isArray(bindings) && bindings.length>0 && bindings.length<=config.nodes.length
                            && new Set(bindings.map(b=>b.nodeId)).size===bindings.length);await refresh();
                        const nodes=bindings.map(b=>{
                            const n=pinFor(b.nodeId),v=observations.get(b.nodeId);
                            need(b.executionContext===TEST.hostIdentity && b.bootId===v.bootId && b.targetProfile===n.targetProfile && b.maintenanceId===n.maintenanceId
                                && (b.endpoint===undefined||same(b.endpoint,n.endpoint)) && (b.nodeIdentity===undefined||same(b.nodeIdentity,{machineId:n.machineId,sshHostKeySha256:n.hostKeySha256}))
                                && v.runnerIdle===true);
                            return {nodeId:b.nodeId,bootId:v.bootId,runnerIdle:v.runnerIdle,journal:v.journal,current:v.current,l2tpUnconfigured:v.l2tpUnconfigured===true};
                        });
                        return callback(freeze({nodes}),refresh);
                    },
                    async restoreClassicSnapshots(pins, restore) {
                        await refresh();
                        need(dispatchClosed && !classicRestore && originals.size === 0
                            && pins.length === config.nodes.length);
                        const accepted = new Map();
                        for (const n of config.nodes) {
                            const p = pins.find(p => p.nodeId === n.nodeId), v = observations.get(n.nodeId), g = v.journal?.generations?.[v.journal.head];
                            need(p && p.targetProfile === n.targetProfile && UUID.test(p.ownerGeneration)
                                && same(p.nodeIdentity, { machineId:n.machineId, sshHostKeySha256:n.hostKeySha256 })
                                && same({ source:'node-readback', ...p.originalSnapshot }, v.provision.originalSnapshot)
                                && v.runnerIdle === true && (!v.journal || g?.phase === 'closed'
                                    && g.binding.candidateHash === 'sha256:' + v.current[n.targetProfile].configSha256));
                            accepted.set(n.nodeId, { generation:p.ownerGeneration, handed:false });
                        }
                        await restore(); await refresh();
                        for (const n of config.nodes) need(same(observations.get(n.nodeId).current[n.targetProfile], observations.get(n.nodeId).provision.originalSnapshot));
                        classicRestore = accepted;
                    },
                    async releaseClassicSnapshots() {
                        await refresh();
                        need(dispatchClosed && classicRestore?.size === config.nodes.length);
                        for (const n of config.nodes) need(classicRestore.get(n.nodeId)?.handed === true
                            && same(observations.get(n.nodeId).current[n.targetProfile], observations.get(n.nodeId).provision.originalSnapshot));
                    },
                    async withVerifiedMaintenance({ binding, proofRef }, callback) {
                        await refresh(); const n = pinFor(binding.node); const v = observations.get(n.nodeId);
                        need(['adopt','handback'].includes(binding.action) && binding.profile === n.targetProfile
                            && proofRef === 'dedicated-' + n.maintenanceId
                            && same(binding.nodeIdentity, { machineId: n.machineId, sshHostKeySha256: n.hostKeySha256 }));
                        const original=originals.get(n.nodeId);
                        if (binding.action==='adopt') {
                            need(!dispatchClosed && v.journal===null && same(v.current[n.targetProfile],v.provision.originalSnapshot));
                            if (retaining) {
                                need(original && original.generation===null);
                                const held=await channels.get(n.nodeId).originals({action:'bind',ownerGeneration:binding.nextGeneration});
                                need(held.ownerGeneration===binding.nextGeneration && held.epoch===original.epoch
                                    && same(held.holder,original.holder) && held.bundleSha256===original.bundleSha256);
                                // Cache bound BEFORE owner callback; a failed CAS is retained, not undone.
                                original.generation=binding.nextGeneration;
                            }
                        } else if (classicRestore) need(dispatchClosed && !classicRestore.get(n.nodeId)?.handed
                            && classicRestore.get(n.nodeId)?.generation === binding.generation
                            && same(v.current[n.targetProfile],v.provision.originalSnapshot));
                        else need(dispatchClosed && original?.restored && !original.handed
                            && original.generation===binding.generation && same(v.current[n.targetProfile],v.provision.originalSnapshot));
                        const check=async()=>{
                            await refresh(); need(same(observations.get(n.nodeId).current[n.targetProfile],v.provision.originalSnapshot));
                            if (binding.action==='adopt') need(observations.get(n.nodeId).journal===null);
                        };
                        await check();
                        const result=await callback(freeze({ status: 'verified', authority: 'external-maintenance-v1', binding,
                            proofId: randomUUID(), maintenanceId: n.maintenanceId, maintenance: 'held',
                            allWriters: 'drained', oldBackend, readback: v.current[n.targetProfile] }), check);
                        await check(); if(binding.action==='handback') {
                            if (classicRestore) classicRestore.get(n.nodeId).handed=true;
                            else original.handed=true;
                        }
                        return result;
                    },
                    async withVerifiedAuthority(challenge, callback) {
                        need(!dispatchClosed);
                        await refresh(); const e = challenge.enrollment; const n = pinFor(e.nodeId); const v = observations.get(n.nodeId);
                        const identity = { machineId: n.machineId, sshHostKeySha256: n.hostKeySha256 };
                        need(same(challenge.executionContext, TEST) && same(e.endpoint, n.endpoint)
                            && same(e.nodeIdentity, identity) && e.targetProfile === n.targetProfile && e.bootId === v.bootId);
                        let predecessor;
                        if (challenge.predecessor) {
                            const prior = challenge.predecessor.binding; const j = v.journal;
                            const record = j?.generations?.[prior.generation];
                            need(record?.phase === 'closed');
                            const stored = record.commands?.[prior.commandIds.close];
                            need(stored?.state === 'completed' && stored.command === 'close'
                                && stored.receipt?.command === 'close');
                            // The node observer just read the exact journal under
                            // held exclusion, as in withBootstrapCancellation(readOnly).
                            // Project its stored close response as the current status;
                            // never mutate the historical response or replay close.
                            const receipt = { ...stored.receipt, command: 'status' };
                            need(validTerminalReceipt(receipt, prior));
                            predecessor = { bindingId: challenge.predecessor.bindingId, generation: prior.generation,
                                headGeneration: j.head, bootId: v.bootId, status: 'terminal', receipt };
                        } else if (challenge.action === 'enroll') {
                            need(v.journal === null && e.predecessorGeneration === 'none');
                            predecessor = { generation: 'none', bootId: v.bootId, status: 'empty', protocolVersion: 2,
                                journal: 'absent', legacyState: 'absent', writers: 'excluded' };
                        } else {
                            const j = v.journal;
                            if (challenge.action === 'reconcile-pristine') need(j === null
                                && e.predecessorGeneration === 'none'
                                && same(v.current[n.targetProfile], v.provision.originalSnapshot));
                            else need(j === null || j.head === challenge.expected?.generation);
                            predecessor = { generation: e.predecessorGeneration, bootId: v.bootId, status: 'pre-enrolled' };
                        }
                        return callback(freeze({ authority: 'external-execution-maintenance-v1', status: 'verified', challenge,
                            proofId: randomUUID(), maintenanceId: n.maintenanceId, maintenance: 'held', allWriters: 'drained',
                            bootstrapWriters: 'excluded', owner: 'topology', physicalIdentity: identity, predecessor, oldBackend,
                            connectionAttestation: { authority: 'server-physical-ssh-endpoint-v1', endpoint: n.endpoint,
                                physicalIdentity: identity, maintenanceId: n.maintenanceId, aliases: 'excluded',
                                hostKeyDigest: 'raw-ssh-public-key-sha256', endpointReassignment: 'excluded' } }));
                    },
                }));
            } catch (e) { poisoned = true; throw e; }
            finally {
                openScope = false; if (!retaining) for (const c of channels.values()) c.close(); busy = false;
                console.info(JSON.stringify({ event: 'dedicated-test-authority', elapsedMs: Date.now() - startedAt,
                    refreshCount, observationCount, maxObservationMs, retained: poisoned }));
            }
        },
        async captureOriginals() {
            need(!busy && !poisoned && !retaining && config.nodes.length===2
                && new Set(config.nodes.map(n=>n.targetProfile)).size===2); retaining=true;
            return this.withHeldAuthority(TEST,c=>c.captureOriginals());
        },
        async restoreClassicSnapshots(pins, restore) {
            if (retaining) {
                this.drainOriginals();
                const current = await this.readOriginalRestoreCurrent();
                return this.restoreOriginals(current);
            }
            need(!busy && !poisoned && !dispatchClosed && originals.size === 0);
            // This closes actual future dispatch in this same producer; no
            // historical holder, boot ID or original epoch is reconstructed.
            dispatchClosed=true; retaining=true;
            return this.withHeldAuthority(TEST, c=>c.restoreClassicSnapshots(pins, restore));
        },
        async releaseClassicSnapshots() {
            if (!classicRestore) return this.releaseOriginals();
            await this.withHeldAuthority(TEST, c=>c.releaseClassicSnapshots());
            this.close();
        },
        drainOriginals() {
            // Real admission closure in this sole controller; no boolean attestor.
            // lifecycle.run joins each work callback before clearing busy.
            need(retaining && !busy && !poisoned && !dispatchClosed
                && config.nodes.every(n=>originals.get(n.nodeId)?.generation));
            dispatchClosed=true;
        },
        async readOriginalRestoreCurrent() { return this.withHeldAuthority(TEST,c=>c.readOriginalRestoreCurrent()); },
        async restoreOriginals(pins) { return this.withHeldAuthority(TEST,c=>c.restoreOriginals(structuredClone(pins))); },
        async releaseOriginals() { return this.withHeldAuthority(TEST,c=>c.releaseOriginals()); },
        async readCurrentHealth() { return this.withHeldAuthority(TEST,c=>c.readCurrentHealth()); },
        close() { poisoned = true; for (const c of retainedChannels.values()) c.close(); },
    });
}
function createRootDedicatedTestAuthority({ env = process.env, read = privateRead } = {}) {
    if (env.TOPOLOGY_TEST_STARTUP_MODE !== 'dedicated-runtime-v1') return undefined;
    require('../../../../scripts/test-topology-owner').assertTestContext(env);
    return createDedicatedTestAuthority({ config: JSON.parse(read(CONFIG)), read });
}
module.exports = { createRootDedicatedTestAuthority, createDedicatedTestAuthority, validateDedicatedTestConfig: validate };
