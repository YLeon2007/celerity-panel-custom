'use strict';

const { detectLanguage, t } = require('./i18n');

// Immediately after the global JSON parser: preserve its limit and leave
// other routes, URL-encoded bodies, and other parse failures on their old path.
module.exports = function mcpJsonLimitError(err, req, res, next) {
    if (err.type !== 'entity.too.large' || err.status !== 413 ||
        req.method !== 'POST' || !/^\/api\/mcp\/?$/i.test(req.path)) {
        return next(err);
    }

    const lang = detectLanguage(req);
    return res.status(413).set('Content-Language', lang).json({
        jsonrpc: '2.0',
        id: null, // The body was not parsed, so there is no trusted request ID.
        error: { code: -32000, message: t('mcp.jsonBodyTooLarge', lang) },
    });
};
