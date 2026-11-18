'use strict';
// Test child of rebuildPanelAcceptance. Run the application's real index, auth,
// routes, locks, compiler and DB service; replace only external dependencies.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const http = require('node:http');
const {spawnSync} = require('node:child_process');
const dir = fs.realpathSync(process.cwd());
assert.ok(process.send && process.env.NODE_ENV === 'test');
assert.ok(dir.startsWith(fs.realpathSync(process.env.TMPDIR) + '/panel-'));
const db = new URL(process.env.MONGO_URI);
assert.equal(db.hostname, '127.0.0.1');
assert.match(db.pathname, /^\/c3_installed_edit_[a-f0-9]{32}$/);
assert.equal(process.env.USE_CADDY, 'true');
// No node agent, SSH, public listener or external service can be reached.
const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function(...args) {
    const [opts] = Array.isArray(args[0]) ? args[0] : net._normalizeArgs(args);
    assert.ok(opts.host === db.hostname && Number(opts.port) === Number(db.port), 'not the fixture Mongo');
    return connect.apply(this, args);
};
const listen = net.Server.prototype.listen;
net.Server.prototype.listen = function(port, callback) {
    assert.ok(this instanceof http.Server && String(port) === '0' && typeof callback === 'function');
    return listen.call(this, 0, '127.0.0.1', () => { callback(); process.send({port:this.address().port}); });
};
require('node-cron').schedule = () => ({stop() {}});
const cache = require('../../cacheService');
cache.connect = async () => { cache.redis = {status:'ready'}; }; // API keys in Mongo; no Redis session I/O
require('../../accessLogs/processService').start = () => {};
require('../../syncService').healthCheck = async () => {};
require('../../statsService').saveHourlySnapshot = async () => {};
const event = (kind,id) => fs.appendFileSync(path.join(dir,'events'), `${kind}:${id}\n`);
require('../../rebuildTransport').createTransport = node => {
    const id = String(node._id); assert.match(id,/^[a-f\d]{24}$/);
    const file = profile => { assert.ok(['main','bridge'].includes(profile)); return path.join(dir,`${id}-${profile}.json`); };
    const staged = new Set();
    return {
        async read(profile) {
            try { return JSON.parse(fs.readFileSync(file(profile),'utf8')); }
            catch (e) { if (e.code === 'ENOENT' && profile === 'bridge') return null; throw e; }
        },
        async stagePair(pair) {
            event('stage',id);
            for (const {profile,config} of pair) {
                const candidate = file(profile) + '.candidate.json';
                fs.writeFileSync(candidate, JSON.stringify(config), {mode:0o600,flag:'wx'}); staged.add(candidate);
                const check = spawnSync(process.env.C3_XRAY,['run','-test','-config',candidate],{
                    env:{...process.env,XRAY_LOCATION_ASSET:path.dirname(process.env.C3_XRAY)},stdio:'ignore',timeout:12000});
                if(check.status !== 0) throw Object.assign(new Error('parser refused candidate'),{code:'REBUILD_PARSER_FAILED'});
            }
        },
        async putPair(pair) {
            event('put',id);
            if (fs.existsSync(path.join(dir,`interrupt-${id}`))) throw Object.assign(new Error('simulated disconnect'),{code:'REBUILD_TEST_INTERRUPTED'});
            for (const {profile} of pair) fs.renameSync(file(profile)+'.candidate.json',file(profile));
            event('written',id);
        },
        async close() { for (const candidate of staged) fs.rmSync(candidate,{force:true}); }
    };
};
process.once('disconnect',()=>process.exit(1));
require('../../../../index');
