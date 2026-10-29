'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const Module = require('node:module');
const fs = require('node:fs');
const path = require('node:path');
for (const code of ['CLASSIC_DEPLOY_PORT_CONFLICT', 'CLASSIC_DEPLOY_PORT_CHECK_UNAVAILABLE']) {
    test(`MCP preserves safe port refusal ${code} without backend text`, async () => {
        const filename = path.resolve(__dirname, '../mcp.js');
        const mod = new Module(filename, module); mod.filename = filename; mod.paths = module.paths;
        const logs = [];
        mod.require = name => {
            if (name === '../services/mcpService') return { async callTool() { throw Object.assign(Error('password=secret'), { code }); } };
            if (name === '../utils/logger') return { warn: x => logs.push(x) };
            if (name === '../middleware/auth') return { requireScope: () => (req, res, next) => next() };
            return Module.prototype.require.call(mod, name);
        };
        mod._compile(fs.readFileSync(filename, 'utf8'), filename);
        const app = express(); app.use(express.json()); app.use(mod.exports);
        const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
        try {
            const response = await fetch(`http://127.0.0.1:${server.address().port}/`, { method: 'POST', headers: { 'content-type': 'application/json' },
                body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'manage_cascade', arguments: {} } }) });
            const text = await response.text();
            assert.doesNotMatch(text + JSON.stringify(logs), /password|secret/);
            const payload = JSON.parse(text.split('\n').find(line => line.startsWith('data: ')).slice(6));
            assert.equal(payload.result.isError, true);
            assert.equal(JSON.parse(payload.result.content[0].text).code, code);
        } finally { await new Promise(resolve => server.close(resolve)); }
    });
}
