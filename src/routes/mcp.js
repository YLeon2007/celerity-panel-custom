/**
 * MCP Router — Model Context Protocol endpoint (MCP spec 2024-11-05)
 *
 * Implements two transports:
 *
 * 1. Streamable HTTP (primary, what Cursor/Claude use by default)
 *    POST /api/mcp
 *    - Request:  JSON-RPC 2.0 { jsonrpc, id, method, params }
 *    - Response: application/json for sync methods (initialize, ping)
 *                text/event-stream for streaming methods (tools/call with long ops)
 *    - Streaming SSE events use: event: message  data: <JSON-RPC response>
 *    - Progress/log events use:  event: progress / event: log  (non-JSON-RPC)
 *
 * 2. Legacy SSE transport (fallback for older clients)
 *    GET  /api/mcp/sse      — opens SSE stream, sends endpoint URL
 *    POST /api/mcp/messages — receives JSON-RPC requests, responds via SSE stream
 *
 * Auth: Bearer <api_key> with mcp:enabled scope, or admin session cookie.
 */

const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const mcpService = require('../services/mcpService');
const logger = require('../utils/logger');
const { requireScope } = require('../middleware/auth');

const SERVER_INFO = { name: 'celerity', version: '1.0.0' };
const PROTOCOL_VERSION = '2024-11-05';
const CAPABILITIES = { tools: {}, prompts: {} };

// Active legacy-SSE sessions: sessionId -> res (the open SSE response)
const sseSessions = new Map();

// All MCP requests require mcp:enabled scope (admin session bypasses it)
router.use(requireScope('mcp:enabled'));

// ─── Helpers ─────────────────────────────────────────────────────────────────

function jsonRpcOk(id, result) {
    return { jsonrpc: '2.0', id: id ?? null, result };
}

function jsonRpcErr(id, code, message) {
    return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

/** Write a JSON-RPC SSE message event */
function sseMessage(res, payload) {
    if (res.writableEnded) return;
    res.write(`event: message\ndata: ${JSON.stringify(payload)}\n\n`);
}

/** Write a non-JSON-RPC progress or log event (for streaming tool ops) */
function sseEvent(res, event, data) {
    if (res.writableEnded) return;
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

function initSSEHeaders(res) {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();
}

function startHeartbeat(req, res) {
    const iv = setInterval(() => {
        if (res.writableEnded) return clearInterval(iv);
        res.write(': ping\n\n');
    }, 20000);
    req.on('close', () => clearInterval(iv));
    return () => clearInterval(iv);
}

// ─── Core dispatcher ─────────────────────────────────────────────────────────

/**
 * Dispatch a JSON-RPC request.
 * @param {object}   rpc      - parsed JSON-RPC body
 * @param {object}   apiKey   - req.apiKey or null (admin session)
 * @param {Function} emitProg - (event, data) for progress/log events on SSE stream
 * @param {Function} translate - request-local i18n translator
 * @returns {{ sync: boolean, result?: object, error?: object }}
 */
async function dispatch(rpc, apiKey, emitProg, translate) {
    const { id, method, params = {} } = rpc;

    // ── initialize ──────────────────────────────────────────────────────────
    if (method === 'initialize') {
        return {
            sync: true,
            result: jsonRpcOk(id, {
                protocolVersion: PROTOCOL_VERSION,
                capabilities: CAPABILITIES,
                serverInfo: SERVER_INFO,
            }),
        };
    }

    // ── notifications/initialized (no response needed) ──────────────────────
    if (method === 'notifications/initialized') {
        return { sync: true, result: null }; // No response for notifications
    }

    // ── ping ─────────────────────────────────────────────────────────────────
    if (method === 'ping') {
        return { sync: true, result: jsonRpcOk(id, {}) };
    }

    // ── tools/list ───────────────────────────────────────────────────────────
    if (method === 'tools/list') {
        const tools = mcpService.listTools(apiKey);
        return { sync: true, result: jsonRpcOk(id, { tools }) };
    }

    // ── tools/call ───────────────────────────────────────────────────────────
    if (method === 'tools/call') {
        const toolName = params.name;
        const toolArgs = params.arguments || {};
        if (!toolName) {
            return { sync: true, result: jsonRpcErr(id, -32602, 'Missing params.name') };
        }
        try {
            const toolResult = await mcpService.callTool(toolName, toolArgs, apiKey, emitProg, translate);
            if (toolResult && toolResult.error) {
                // Soft error from handler (e.g. not found)
                return {
                    sync: false,
                    result: jsonRpcOk(id, {
                        content: [{ type: 'text', text: JSON.stringify(toolResult) }],
                        isError: true,
                    }),
                };
            }
            return {
                sync: false,
                result: jsonRpcOk(id, {
                    content: [{ type: 'text', text: JSON.stringify(toolResult) }],
                }),
            };
        } catch (err) {
            if (['CLASSIC_DEPLOY_PORT_CONFLICT', 'CLASSIC_DEPLOY_PORT_CHECK_UNAVAILABLE', 'CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED'].includes(err?.code)) {
                const message = err.code === 'CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED'
                    ? 'Configuration was applied and verified, but the tunnel has no confirmed connection. Check connectivity between nodes. Retry and checked deletion remain available.'
                    : err.code === 'CLASSIC_DEPLOY_PORT_CONFLICT'
                    ? 'The tunnel port is already in use on the source node; edit the port and retry'
                    : 'Port inspection was unavailable; no deployment was started';
                logger.warn(`[MCP] Tool refusal: ${err.code}`);
                return { sync: false, result: jsonRpcOk(id, { isError: true,
                    content: [{ type: 'text', text: JSON.stringify({ code: err.code, message }) }] }) };
            }
            logger.warn(`[MCP] Tool error ${toolName}: ${err.message}`);
            let msg = err.message;
            if (err.name === 'ZodError') {
                msg = 'Invalid arguments: ' + err.errors.map(e => `${e.path.join('.')}: ${e.message}`).join('; ');
            }
            return {
                sync: false,
                result: jsonRpcOk(id, {
                    content: [{ type: 'text', text: msg }],
                    isError: true,
                }),
            };
        }
    }

    // ── prompts/list ─────────────────────────────────────────────────────────
    if (method === 'prompts/list') {
        const prompts = mcpService.listPrompts();
        return { sync: true, result: jsonRpcOk(id, { prompts }) };
    }

    // ── prompts/get ──────────────────────────────────────────────────────────
    if (method === 'prompts/get') {
        if (!params?.name) {
            return { sync: true, result: jsonRpcErr(id, -32602, 'Missing params.name') };
        }
        try {
            const prompted = mcpService.getPrompt(params.name, params.arguments || {});
            return { sync: true, result: jsonRpcOk(id, prompted) };
        } catch (err) {
            return { sync: true, result: jsonRpcErr(id, -32602, err.message) };
        }
    }

    // ── Unknown method ───────────────────────────────────────────────────────
    return {
        sync: true,
        result: jsonRpcErr(id, -32601, `Method not found: ${method}`),
    };
}

// ─── 1. Streamable HTTP transport ─────────────────────────────────────────────

router.post('/', async (req, res) => {
    const rpc = req.body;

    if (!rpc || !rpc.method) {
        return res.status(400).json(jsonRpcErr(null, -32600, 'Invalid Request: missing method'));
    }

    const apiKey = req.apiKey || null;
    const wantsSSE = req.headers.accept && req.headers.accept.includes('text/event-stream');

    // For streaming calls, use SSE; for everything else plain JSON
    const useSSE = wantsSSE || rpc.method === 'tools/call';

    if (useSSE) {
        initSSEHeaders(res);
        const stopHeartbeat = startHeartbeat(req, res);

        const emitProg = (event, data) => sseEvent(res, event, data);

        try {
            const { result } = await dispatch(rpc, apiKey, emitProg, res.locals.t);
            if (result !== null) {
                sseMessage(res, result);
            }
        } catch (err) {
            logger.error(`[MCP] Dispatch error: ${err.message}`);
            sseMessage(res, jsonRpcErr(rpc.id ?? null, -32603, 'Internal error'));
        } finally {
            stopHeartbeat();
            res.end();
        }
        return;
    }

    // Sync JSON response (initialize, ping, tools/list, prompts/list, etc.)
    try {
        const { result } = await dispatch(rpc, apiKey, () => {}, res.locals.t);
        if (result === null) return res.status(202).end(); // notification
        return res.json(result);
    } catch (err) {
        logger.error(`[MCP] Dispatch error: ${err.message}`);
        return res.json(jsonRpcErr(rpc.id ?? null, -32603, 'Internal error'));
    }
});

// ─── 2. Legacy SSE transport ──────────────────────────────────────────────────

/**
 * GET /api/mcp/sse
 * Opens the SSE channel and tells the client where to POST messages.
 */
router.get('/sse', (req, res) => {
    const sessionId = crypto.randomUUID();
    initSSEHeaders(res);
    const stopHeartbeat = startHeartbeat(req, res);

    sseSessions.set(sessionId, res);
    logger.info(`[MCP] Legacy SSE session opened: ${sessionId}`);

    // Tell client the messages endpoint
    const base = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
    res.write(`event: endpoint\ndata: ${JSON.stringify(`${base}/api/mcp/messages?sessionId=${sessionId}`)}\n\n`);

    req.on('close', () => {
        sseSessions.delete(sessionId);
        stopHeartbeat();
        logger.info(`[MCP] Legacy SSE session closed: ${sessionId}`);
    });
});

/**
 * POST /api/mcp/messages?sessionId=<id>
 * Receives JSON-RPC from legacy SSE clients, sends response over the SSE stream.
 */
router.post('/messages', async (req, res) => {
    const { sessionId } = req.query;
    const sseRes = sseSessions.get(sessionId);

    if (!sseRes || sseRes.writableEnded) {
        return res.status(400).json({ error: 'Session not found or closed' });
    }

    const rpc = req.body;
    if (!rpc || !rpc.method) {
        return res.status(400).json(jsonRpcErr(null, -32600, 'Invalid Request'));
    }

    // Acknowledge immediately
    res.status(202).end();

    const apiKey = req.apiKey || null;
    const emitProg = (event, data) => sseEvent(sseRes, event, data);

    try {
        const { result } = await dispatch(rpc, apiKey, emitProg, res.locals.t);
        if (result !== null) {
            sseMessage(sseRes, result);
        }
    } catch (err) {
        logger.error(`[MCP] Legacy session error: ${err.message}`);
        sseMessage(sseRes, jsonRpcErr(rpc.id ?? null, -32603, 'Internal error'));
    }
});

// ─── Convenience JSON endpoints ───────────────────────────────────────────────

router.get('/tools', (req, res) => {
    res.json({ tools: mcpService.listTools(req.apiKey || null) });
});

router.get('/prompts', (req, res) => {
    res.json({ prompts: mcpService.listPrompts() });
});

module.exports = router;
