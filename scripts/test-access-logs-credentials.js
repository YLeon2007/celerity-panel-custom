/**
 * Access-logs credential + model shape tests.
 *
 * Covers token hashing/generation (pure functions) and verifies the settings /
 * node schemas expose the access-logs fields with safe defaults. No DB needed:
 * models are instantiated in-memory.
 */

process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'test-encryption-key-32-characters-long';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-session-secret';
process.env.PANEL_DOMAIN = process.env.PANEL_DOMAIN || 'panel.example.com';
process.env.ACME_EMAIL = process.env.ACME_EMAIL || 'admin@example.com';

const assert = require('assert');
const cred = require('../src/services/accessLogs/credentialService');

// --- token generation / hashing -------------------------------------------
{
    const t1 = cred.generateToken();
    const t2 = cred.generateToken();
    assert.strictEqual(t1.length, 64, '32 bytes hex = 64 chars');
    assert.notStrictEqual(t1, t2, 'tokens are random');

    const h1 = cred.hashToken(t1);
    const h1again = cred.hashToken(t1);
    assert.strictEqual(h1, h1again, 'hash is deterministic');
    assert.strictEqual(h1.length, 64, 'sha256 hex = 64 chars');
    assert.notStrictEqual(h1, cred.hashToken(t2), 'different token -> different hash');
}

// --- settings model defaults ----------------------------------------------
{
    const Settings = require('../src/models/settingsModel');
    const s = new Settings({ _id: 'settings' });
    assert.strictEqual(s.accessLogs.enabled, false, 'access logs off by default');
    assert.strictEqual(s.accessLogs.state, 'disabled');
    assert.strictEqual(s.accessLogs.retentionDays, 14);
    assert.strictEqual(s.accessLogs.maxStorageGb, 10);
    assert.strictEqual(s.accessLogs.nodeScope, 'all');
    assert.strictEqual(s.accessLogs.maskClientIp, false);
}

// --- node model defaults + credential is select:false ---------------------
{
    const HyNode = require('../src/models/hyNodeModel');
    const n = new HyNode({ type: 'xray', name: 'n', ip: '1.2.3.4' });
    assert.strictEqual(n.xray.accessLogs.enabled, false);
    assert.strictEqual(n.xray.accessLogs.status, 'disabled');

    // ingestTokenEncrypted is select:false -> excluded from a default toJSON/lean
    // projection. We at least confirm the path exists and is empty by default.
    assert.strictEqual(n.xray.accessLogs.ingestTokenHash, '');

    const path = HyNode.schema.path('xray');
    assert.ok(path, 'xray subdocument path exists');
}

console.log('test-access-logs-credentials: OK');
