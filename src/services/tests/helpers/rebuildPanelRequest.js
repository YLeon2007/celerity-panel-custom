'use strict';

const { Duplex } = require('node:stream');
const { IncomingMessage, ServerResponse } = require('node:http');

// Same in-memory HTTP objects as the rebuild Remove fixture. Set a synthetic
// peer IP for the real Express rate limiter, and EOF for unmatched routes.
function request(app, url, { method = 'POST', session, sessionID, headers, body = {}, ip = '192.0.2.10' } = {}) {
    return new Promise((resolve, reject) => {
        const wire = [];
        const socket = new Duplex({ read() {}, write(chunk, _, done) { wire.push(chunk.toString()); done(); } });
        socket.remoteAddress = ip;
        const req = new IncomingMessage(socket);
        Object.assign(req, { method, url, headers: { host: 'panel.fixture.invalid', ...headers }, body, session, sessionID });
        req.push(null);
        const res = new ServerResponse(req);
        res.assignSocket(socket);
        res.once('error', reject);
        res.once('finish', () => {
            const [, ...payload] = wire.join('').split('\r\n\r\n');
            resolve({ status: res.statusCode, headers: res.getHeaders(), body: payload.join('\r\n\r\n') });
            socket.destroy();
        });
        app(req, res);
    });
}

module.exports = { request };
