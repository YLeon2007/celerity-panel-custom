'use strict';

const assert = require('assert');
const Module = require('module');

process.env.PANEL_DOMAIN ||= 'panel.example.com';
process.env.ACME_EMAIL ||= 'admin@example.com';
process.env.ENCRYPTION_KEY ||= '0123456789abcdef0123456789abcdef';
process.env.SESSION_SECRET ||= 'test-session-secret-0123456789abcdef';

let saveCount = 0;
let invalidateCount = 0;
let schedulePushCount = 0;

class FakeHyNode {
    constructor(data) {
        Object.assign(this, JSON.parse(JSON.stringify(data)));
        this._id = 'fake-node-id';
    }

    async save() {
        saveCount += 1;
        return this;
    }

    static async findOne() {
        return null;
    }
}

const cryptoService = {
    generateNodeSecret: () => 'synthetic-stats-secret',
    encryptSshCredentials: value => ({ ...value, encrypted: true }),
};
const logger = { info() {}, warn() {}, error() {}, debug() {} };
const cache = {
    async invalidateNodes() { invalidateCount += 1; },
    async invalidateAllSubscriptions() { invalidateCount += 1; },
    async invalidateDashboardCounts() { invalidateCount += 1; },
};

function invalidCreateData(conflict = 'main') {
    const data = {
        name: `invalid-hy-create-${conflict}`,
        ip: '203.0.113.70',
        type: 'xray',
        port: 9443,
        ssh: { username: 'root', password: 'synthetic' },
        xray: {
            transport: 'tcp',
            security: 'reality',
            inboundTag: 'vless-in',
            apiPort: 61000,
            agentPort: 62080,
            extraInbounds: [],
            hysteria: {
                enabled: true,
                port: 9443,
                inboundTag: 'hysteria-in',
                obfs: '',
                udpIdleTimeout: 60,
                masquerade: {
                    type: 'string',
                    content: 'Not Found',
                    statusCode: 404,
                    url: 'https://example.com',
                },
            },
        },
    };
    if (conflict === 'api') data.xray.hysteria.port = data.xray.apiPort;
    if (conflict === 'agent') data.xray.hysteria.port = data.xray.agentPort;
    if (conflict === 'extra') {
        data.xray.hysteria.port = 24443;
        data.xray.extraInbounds = [{
            id: 'extra-conflict', label: 'Extra conflict', port: 24443,
            inboundTag: 'extra-in', transport: 'tcp', security: 'reality',
        }];
    }
    if (conflict === 'tag') {
        data.xray.hysteria.port = 24443;
        data.xray.hysteria.inboundTag = data.xray.inboundTag;
    }
    return data;
}

function installStubs() {
    const originalLoad = Module._load;
    Module._load = function patchedLoad(request, parent, isMain) {
        const parentFile = parent?.filename || '';
        if (parentFile.endsWith('/src/routes/nodes.js')) {
            const stubs = {
                '../models/hyNodeModel': FakeHyNode,
                '../models/hyUserModel': {},
                '../models/serverGroupModel': {},
                '../services/cryptoService': cryptoService,
                '../services/nodeSetup': {},
                '../services/syncService': {
                    schedulePush() { schedulePushCount += 1; },
                },
                '../utils/logger': logger,
                '../middleware/auth': {
                    requireScope: () => (_req, _res, next) => next(),
                },
                '../utils/helpers': {
                    async invalidateNodesCache() { invalidateCount += 1; },
                },
            };
            if (Object.prototype.hasOwnProperty.call(stubs, request)) return stubs[request];
        }
        if (parentFile.endsWith('/src/mcp/tools/nodes.js')) {
            const stubs = {
                '../../models/hyNodeModel': FakeHyNode,
                '../../models/hyUserModel': {},
                '../../services/cacheService': cache,
                '../../services/cryptoService': cryptoService,
                '../../utils/logger': logger,
            };
            if (Object.prototype.hasOwnProperty.call(stubs, request)) return stubs[request];
        }
        return originalLoad.call(this, request, parent, isMain);
    };
    return () => { Module._load = originalLoad; };
}

function createResponse() {
    return {
        statusCode: 200,
        body: undefined,
        status(code) { this.statusCode = code; return this; },
        json(payload) { this.body = payload; return this; },
    };
}

async function invokeRestCreate(router, body) {
    const layer = router.stack.find(item => item.route?.path === '/' && item.route?.methods?.post);
    assert(layer, 'REST POST / route must exist');
    const handlers = layer.route.stack.map(item => item.handle);
    const req = { body, params: {}, headers: {} };
    const res = createResponse();
    let index = 0;
    const next = async error => {
        if (error) throw error;
        const handler = handlers[index++];
        if (handler) await handler(req, res, next);
    };
    await next();
    return res;
}

(async () => {
    const restore = installStubs();
    let router;
    let manageNode;
    try {
        delete require.cache[require.resolve('../src/routes/nodes')];
        delete require.cache[require.resolve('../src/mcp/tools/nodes')];
        router = require('../src/routes/nodes');
        manageNode = require('../src/mcp/tools/nodes').manageNode;
    } finally {
        restore();
    }

    const cases = [
        ['main', /already used by main VLESS inbound/i],
        ['api', /already used by API/i],
        ['agent', /already used by agent/i],
        ['extra', /already used by native Hysteria inbound/i],
        ['tag', /must differ from the main VLESS tag/i],
    ];
    for (const [conflict, expected] of cases) {
        const rest = await invokeRestCreate(router, invalidCreateData(conflict));
        assert.strictEqual(rest.statusCode, 400, `REST must reject ${conflict} conflict`);
        assert.match(rest.body.error, expected);

        const mcp = await manageNode({ action: 'create', data: invalidCreateData(conflict) }, () => {});
        assert.strictEqual(mcp.code, 400, `MCP must reject ${conflict} conflict`);
        assert.match(mcp.error, expected);
    }
    assert.strictEqual(saveCount, 0, 'REST/MCP invalid creates must all fail before save');
    assert.strictEqual(invalidateCount, 0, 'REST/MCP invalid creates must not invalidate caches');
    assert.strictEqual(schedulePushCount, 0, 'REST/MCP invalid creates must not schedule sync');

    console.log('xray create validation path tests passed');
})().catch(error => {
    console.error(error);
    process.exit(1);
});
