'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

// Entry-point ordering/error seam only, not a startup timing or serving proof.
// All schemas and route imports are real; Mongo, runtime and cache boundaries
// are intercepted so a late classic init can be held independently of topology.
for (const rejectInit of [false, true]) test(`classic startup joins late ordinary schema init and drains its peer (${rejectInit ? 'failure' : 'success'})`, async t => {
    const directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'classic-init-barrier-'));
    t.after(() => fs.rm(directory, { recursive: true, force: true }));
    const settings = path.join(directory, 'settings.json');
    await fs.writeFile(settings, JSON.stringify({ version: 1, context: 'test.infograd.online',
        stateDirectory: directory, listenAddress: '127.0.0.1', environment: {
            PANEL_DOMAIN: 'test.infograd.online', ACME_EMAIL: 'unit@example.invalid',
            ENCRYPTION_KEY: 'a'.repeat(64), SESSION_SECRET: 'b'.repeat(64),
            MONGO_URI: 'mongodb://127.0.0.1:1/ordering_only', REDIS_URL: 'redis://127.0.0.1:1',
            USE_CADDY: 'true', PORT: '12345', L2TP_EXECUTION_ENABLED: 'false', L2TP_MIGRATIONS_ENABLED: 'false',
            TOPOLOGY_TEST_EXECUTION_ENABLED: 'false', TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false',
            L2TP_PRODUCTION_EXECUTION_ENABLED: 'false',
        } }), { mode: 0o600 });
    const probe = `
        const Module = require('node:module'), fs = require('node:fs');
        const entry = process.argv[1], rejectInit = process.argv[2] === 'true';
        const compile = Module.prototype._compile;
        Module.prototype._compile = function(bytes, file) {
            return compile.call(this, process.env.C3_BASELINE_INDEX && file === entry ? fs.readFileSync(process.env.C3_BASELINE_INDEX, 'utf8') : bytes, file);
        };
        const deferred = () => { let resolve, reject; const promise = new Promise((a,b) => { resolve=a; reject=b; }); promise.catch(() => {}); return {promise,resolve,reject}; };
        const late=deferred(), peer=deferred();
        let cacheEntered=false, errors=0, stopped=false, disconnected=false, exitCode=null, modelCount;
        const realExit=process.exit.bind(process);
        process.exit=code => { exitCode=code; };
        const load=Module._load;
        Module._load=function(id) {
            const value=load.apply(this,arguments);
            if(id==='mongoose') {
                value.connect=async () => {
                    modelCount=Object.keys(value.models).length;
                    for(const m of Object.values(value.models)) m.$init=Promise.resolve();
                    value.models.ServerGroup.$init=late.promise;
                    value.models.StatsSnapshot.$init=peer.promise;
                };
                value.disconnect=async () => { disconnected=true; };
            }
            if(id==='./src/utils/logger') {
                value.error=()=>{ errors++; };
            }
            if(id==='./src/services/cacheService') value.connect=async()=>{ cacheEntered=true; return new Promise(()=>{}); };
            if(id==='./src/modules/l2tpRuntimeLifecycleHook') return { ...value, createL2tpRootLifecycle:()=>({
                async startAfterDatabase() {
                    setTimeout(()=>{
                        const before=cacheEntered;
                        if(rejectInit) late.reject(new Error('late classic index failure')); else late.resolve();
                        setTimeout(()=>{
                            const whilePeerHeld={errors,stopped,disconnected,cacheEntered};
                            peer.resolve();
                            setTimeout(()=>{
                                console.log('CLASSIC_INIT_RESULT:'+JSON.stringify({before,whilePeerHeld,after:cacheEntered,errors,stopped,disconnected,exitCode,modelCount}));
                                realExit(0);
                            },80);
                        },80);
                    },80);
                },
                async stop(){ stopped=true; },
            }) };
            return value;
        };
        require(entry);
    `;
    const result = spawnSync(process.execPath, ['-e', probe, path.resolve(__dirname, '../../../index.js'), String(rejectInit)], {
        env: { ...process.env, C3_SETTINGS: settings }, encoding: 'utf8', timeout: 15000,
    });
    assert.equal(result.status, 0, result.stderr + result.stdout);
    const row = JSON.parse(result.stdout.split('\n').find(line => line.startsWith('CLASSIC_INIT_RESULT:')).slice(20));
    assert.equal(row.modelCount, 25);
    assert.equal(row.before, false, 'cache/HTTP startup must not pass an unresolved ordinary model');
    assert.deepEqual(row.whilePeerHeld, { errors: 0, stopped: false, disconnected: false, cacheEntered: false },
        'neither failure cleanup nor success may escape the admitted sibling barrier');
    assert.equal(row.after, !rejectInit);
    if (rejectInit) {
        assert.ok(row.errors > 0);
        assert.equal(row.stopped, true);
        assert.equal(row.disconnected, true);
        assert.equal(row.exitCode, 1);
    } else {
        assert.equal(row.errors, 0);
        assert.equal(row.exitCode, null);
    }
});
