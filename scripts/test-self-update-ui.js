const assert = require('assert');
const fs = require('fs');
const path = require('path');

const updateRoutes = fs.readFileSync(path.join(__dirname, '..', 'src/routes/panel/update.js'), 'utf8');
const appJs = fs.readFileSync(path.join(__dirname, '..', 'public/js/app.js'), 'utf8');

assert(
    updateRoutes.includes('const updateStatusLimiter = rateLimit') && updateRoutes.includes('max: 600'),
    'status polling must have a high dedicated rate limit'
);
assert(
    updateRoutes.includes("router.get('/update/status', updateStatusLimiter"),
    'status route must use updateStatusLimiter, not the low mutation limiter'
);
assert(
    appJs.includes('transientFailures') && appJs.includes('i18n.reconnecting'),
    'update modal polling must survive transient backend/rate-limit failures'
);

console.log('self-update UI tests passed');
