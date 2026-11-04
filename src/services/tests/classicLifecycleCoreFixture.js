'use strict';
// Local persistence/SSH boundary for the actual classic completion producer.
// Configs come from product generators; the service, completion checks, node
// lock helper/service/repository and wrapper settlement remain real. No sockets.
const assert = require('node:assert/strict');
const Module = require('node:module');
const fs = require('node:fs');
const path = require('node:path');
const generator = require('../configGenerator');
const MAIN = '/usr/local/etc/xray/config.json';
const TRANSIT = '/usr/local/etc/xray-bridge/config.json';
function load(file, replacements) {
    const filename = path.resolve(__dirname, '..', file);
    const mod = new Module(filename, module);
    mod.filename = filename; mod.paths = Module._nodeModulePaths(path.dirname(filename));
    mod.require = id => Object.hasOwn(replacements, id) ? replacements[id] : Module.prototype.require.call(mod, id);
    mod._compile(fs.readFileSync(filename, 'utf8'), filename);
    return mod.exports;
}
function createClassicLifecycleCoreFixture({ models, rows, calls, state, env, options }) {
    assert.ok(options.t, 'actual producer fixture needs test-owned environment cleanup');
    const saved = Object.fromEntries(Object.keys(env).map(key => [key, process.env[key]]));
    for (const [key, value] of Object.entries(env)) {
        if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    options.t.after(() => {
        for (const [key, value] of Object.entries(saved)) {
            if (value === undefined) delete process.env[key]; else process.env[key] = value;
        }
    });
    const target = rows.CascadeLink[0];
    const [source, bridge] = [target.portalNode, target.bridgeNode].map(id => rows.HyNode.find(n => n._id === id));
    const populated = link => ({ ...link, portalNode: rows.HyNode.find(n => n._id === link.portalNode),
        bridgeNode: rows.HyNode.find(n => n._id === link.bridgeNode) });
    const main = { inbounds: [{ tag: 'vless-in', port: 443, protocol: 'vless',
        settings: { clients: [{ id: 'local-existing-user', email: 'local-client' }] } }],
    outbounds: [{ tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }],
    routing: { domainStrategy: 'IPIfNonMatch', rules: [{ type: 'field', ip: ['geoip:private'], outboundTag: 'block' }] } };
    if (options.applied !== false) generator.applyReversePortal(main, [populated(target)], ['vless-in']);
    const bridgeLinks = rows.CascadeLink.filter(link => link.bridgeNode === bridge._id
        && (link !== target || options.applied !== false)).map(populated);
    const files = new Map([[`${source._id}:${MAIN}`, JSON.stringify(main)],
        [`${source._id}:${TRANSIT}`, JSON.stringify({ inbounds: [], localPreserved: 'source-other-profile' })],
        [`${bridge._id}:${MAIN}`, JSON.stringify({ inbounds: [], outbounds: [], routing: { rules: [] }, localPreserved: 'bridge-main' })],
        [`${bridge._id}:${TRANSIT}`, bridgeLinks.length ? generator.generateCombinedBridgeConfig(bridgeLinks)
            : require('../classicPortalBridgeBootstrap').IDLE_BYTES]]);
    const original = new Map(files), commands = [], receipts = [];
    calls.core = { files, original, commands, receipts };
    class SSH {
        constructor(node) { this.node = node; }
        async connect() { assert.equal(rows.NodeOperationLock.length, 2, 'both real node generations held'); }
        disconnect() {}
        async exec(command, execOptions = {}) {
            const nodeId = this.node._id;
            assert.equal(calls.transactionActive, false, 'no transport in retryable settlement transaction');
            assert.equal(rows.NodeOperationLock.length, 2);
            assert.ok(rows.CascadeLink.some(link => link._id === target._id), 'DB row survives remote cleanup');
            commands.push({ nodeId, command });
            await options.beforeExec?.({ command, rows, state: state(), files });
            const marker = command.match(/C3_SCOPED_DONE_[a-f0-9]+/);
            assert.ok(marker, 'actual producer uses an invocation-specific completion marker');
            let stdout = '';
            if (command.includes('C3_READ_CONFIG')) {
                const file = command.match(/\/usr\/local\/etc\/xray(?:-bridge)?\/config\.json(?:\.[a-f0-9]+\.stage)?/)[0];
                stdout = files.get(`${nodeId}:${file}`) ?? 'C3_CONFIG_ABSENT';
            } else if (command.includes('systemctl show')) {
                const file = command.includes('xray-bridge') ? TRANSIT : MAIN;
                stdout = `ActiveState=active\nNeedDaemonReload=no\nExecStart={ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config ${file} ; }\n`;
            } else if (execOptions.stdin !== undefined) {
                const stage = command.match(/\/usr\/local\/etc\/xray(?:-bridge)?\/[^'\s]+\.stage/)[0];
                files.set(`${nodeId}:${stage}`, String(execOptions.stdin));
            } else if (command.includes('mv --')) {
                const stage = command.match(/\/usr\/local\/etc\/xray(?:-bridge)?\/[^'\s]+\.stage/)[0];
                files.set(`${nodeId}:${stage.replace(/\.[a-f0-9]+\.stage$/, '')}`, files.get(`${nodeId}:${stage}`));
                files.delete(`${nodeId}:${stage}`);
            } else if (command.includes('ss -tnH')) {
                if (options.established !== false) stdout = `0 0 ${source.ip}:${target.tunnelPort} ${bridge.ip}:49900\n`;
            } else if (command.includes('/usr/local/bin/xray run -test')) {
                const stage = command.match(/\/usr\/local\/etc\/xray(?:-bridge)?\/[^'\s]+\.stage/)[0];
                JSON.parse(files.get(`${nodeId}:${stage}`)); // syntax only, not a real Xray validation
            } else assert.ok(command.includes('ss -H -ltnp') || command.includes('ufw allow'),
                'refuse unmodeled transport commands instead of fabricating their success');
            await options.afterExec?.({ command, rows, state: state(), files });
            return { code: 0, stdout: `${stdout}\n${marker[0]}\n`, stderr: '' };
        }
    }
    const localHeld = load('classicNodeConfigWrite.js', {
        '../modules/relay-l2tp/models/nodeOperationLockModel': models.NodeOperationLock,
        './topologyConfigOwnership': { topologyManagesNodeConfig: async () => false },
    });
    const services = new Map();
    async function run(method, input) {
        // Independent wrapper borrowing must use the very same ALS instance.
        const independent = !!input.scopedExecutionContext;
        if (!services.has(independent)) services.set(independent, load('cascadeService.js', {
            '../models/cascadeLinkModel': models.CascadeLink, '../models/hyNodeModel': models.HyNode,
            '../models/settingsModel': {}, './nodeSSH': SSH,
            './classicNodeConfigWrite': independent ? require('../classicNodeConfigWrite') : localHeld,
            '../modules/relay-l2tp/models/cascadeTopologyStateModel': models.CascadeTopologyState,
            '../modules/relay-l2tp/models/relayL2tpStateModel': models.RelayL2tpState,
            './cacheService': {}, '../utils/logger': { info() {}, error() {}, warn() {} }, './webhookService': {},
            './topologyConfigOwnership': { APPLIED_LINK_STATUSES: ['staged', 'deployed', 'online'],
                topologyManagesNodeConfig: async () => false, usesTestTopologyConfig: () => false },
            '../modules/relay-l2tp/services/legacyCascadeUndeploy': { trackLegacyCascadeUndeploy() { throw Error('not a legacy undeploy test'); } },
        }));
        const result = await services.get(independent)[method](input);
        receipts.push(structuredClone(result));
        return result;
    }
    return { deployScopedClassicLink: input => run('deployScopedClassicLink', input),
        removeScopedClassicLink: input => run('removeScopedClassicLink', input) };
}
module.exports = { createClassicLifecycleCoreFixture };
