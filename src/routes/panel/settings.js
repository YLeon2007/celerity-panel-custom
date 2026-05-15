/**
 * Panel routes: settings, backup settings, API keys, webhooks.
 */

const router = require('express').Router();
const bcrypt = require('bcryptjs');
const multer = require('multer');

const HyUser = require('../../models/hyUserModel');
const HyNode = require('../../models/hyNodeModel');
const Settings = require('../../models/settingsModel');
const Admin = require('../../models/adminModel');
const ApiKey = require('../../models/apiKeyModel');
const cryptoService = require('../../services/cryptoService');
const totpService = require('../../services/totpService');
const webhookService = require('../../services/webhookService');
const cache = require('../../services/cacheService');
const hwidDeviceService = require('../../services/hwidDeviceService');
const homepageService = require('../../services/homepageService');
const { invalidateSettingsCache } = require('../../utils/helpers');
const config = require('../../../config');
const logger = require('../../utils/logger');
const {
    render,
    parseBool,
    clearPanelTotpPending,
    redirectSettingsSecurity,
    SETTINGS_TOTP_ACTIONS,
} = require('./helpers');

// ==================== SETTINGS ====================

// GET /settings
router.get('/settings', async (req, res) => {
    try {
        const ssl = {
            enabled: !!config.PANEL_DOMAIN,
            domain: config.PANEL_DOMAIN || null,
        };

        const [admin, settingsDoc, apiKeys] = await Promise.all([
            Admin.findOne({ username: req.session.adminUsername }),
            Settings.get(),
            ApiKey.listKeys(),
        ]);

        // Convert to plain object before mutating to avoid Mongoose change tracking
        const settings = settingsDoc ? settingsDoc.toObject() : settingsDoc;

        // Decrypt secrets for form display (stored encrypted since P1-encrypt-secrets)
        if (settings?.webhook?.secret) {
            settings.webhook.secret = cryptoService.decryptSafe(settings.webhook.secret);
        }
        if (settings?.backup?.s3?.secretAccessKey) {
            settings.backup.s3.secretAccessKey = cryptoService.decryptSafe(settings.backup.s3.secretAccessKey);
        }

        let topHwidUsers = [];
        try {
            const cacheKey = 'panel:topHwidUsers';
            if (cache.isConnected()) {
                const raw = await cache.redis.get(cacheKey);
                if (raw) {
                    topHwidUsers = JSON.parse(raw);
                }
            }
            if (!Array.isArray(topHwidUsers) || topHwidUsers.length === 0) {
                const rows = await hwidDeviceService.topUsersByDeviceCount(10);
                topHwidUsers = await Promise.all(
                    rows.map(async (r) => {
                        const u = await HyUser.findOne({ userId: r.userId }).select('username').lean();
                        return { ...r, username: u?.username || '' };
                    })
                );
                if (cache.isConnected() && topHwidUsers.length > 0) {
                    await cache.redis.setex(cacheKey, 60, JSON.stringify(topHwidUsers));
                }
            }
        } catch (e) {
            logger.warn(`[Panel] topHwidUsers: ${e.message}`);
        }

        const homepageInfo = {
            mode: homepageService.getMode(),
            hasCustom: homepageService.hasCustom(),
            customSize: homepageService.getCustomSize(),
            maxBytes: homepageService.MAX_CUSTOM_BYTES,
        };

        render(res, 'settings', {
            title: res.locals.locales.settings.title,
            page: 'settings',
            ssl,
            admin,
            settings,
            apiKeys,
            validScopes: ApiKey.VALID_SCOPES,
            webhookEvents: Object.values(webhookService.EVENTS),
            topHwidUsers,
            homepageInfo,
            message: req.query.message || null,
            error: req.query.error || null,
        });
    } catch (error) {
        logger.error('[Panel] GET /settings error:', error.message);
        res.status(500).send('Error: ' + error.message);
    }
});

// POST /settings - Save settings
router.post('/settings', async (req, res) => {
    try {
        const { reloadSettings } = require('../../../index');
        
        // Build updates only from fields that the submitted form actually contains.
        // Each settings card lives in its own <form>, so when the user saves one
        // card, request body only carries that card's fields. Unconditionally
        // applying parseInt with `|| default` would silently reset settings from
        // other cards on every save.
        const updates = {};

        // Helper: include a setting only when present in the request body.
        const setIfPresent = (key, parser) => {
            if (req.body[key] !== undefined) updates[key] = parser(req.body[key]);
        };
        const setBool = (key) => {
            if (req.body[key] !== undefined) updates[key] = req.body[key] === 'on';
        };

        // System tab: load balancing, cache TTLs, SSH pool, node auth.
        // The whole tab posts as a single form, so any number input that is
        // always rendered (cache.subscriptionTTL) being present means this
        // is a System tab submit. For checkboxes inside that form an absent
        // key means "unchecked", so force-apply booleans on this branch.
        const systemTabSubmit = req.body['cache.subscriptionTTL'] !== undefined;
        if (systemTabSubmit) {
            updates['loadBalancing.enabled']        = req.body['loadBalancing.enabled']        === 'on';
            updates['loadBalancing.hideOverloaded'] = req.body['loadBalancing.hideOverloaded'] === 'on';
            updates['loadBalancing.hideOffline']    = req.body['loadBalancing.hideOffline']    === 'on';
        }
        setIfPresent('cache.subscriptionTTL', v => parseInt(v) || 3600);
        setIfPresent('cache.userTTL', v => parseInt(v) || 900);
        setIfPresent('cache.onlineSessionsTTL', v => parseInt(v) || 10);
        setIfPresent('cache.activeNodesTTL', v => parseInt(v) || 30);
        setIfPresent('rateLimit.subscriptionPerMinute', v => parseInt(v) || 100);
        setBool('sshPool.enabled');
        setIfPresent('sshPool.maxIdleTime', v => parseInt(v) || 120);
        setIfPresent('sshPool.connectTimeout', v => parseInt(v) || 15);
        setIfPresent('sshPool.keepAliveInterval', v => parseInt(v) || 30);
        setIfPresent('sshPool.maxRetries', v => parseInt(v) || 2);
        setBool('nodeAuth.insecure');

        // Hysteria IP device limit (its own card on the Subscription tab).
        if (req.body['_hyLimitSettings'] !== undefined) {
            const grace = parseInt(req.body['deviceGracePeriod'], 10);
            updates['deviceGracePeriod'] = Number.isFinite(grace) ? Math.min(60, Math.max(1, grace)) : 15;
        }
        
        // Webhook settings (only when the dedicated webhook form is submitted)
        if (req.body['_webhookSettings'] !== undefined) {
            updates['webhook.enabled'] = req.body['webhook.enabled'] === 'on';
            updates['webhook.url'] = req.body['webhook.url'] || '';
            const rawWebhookSecret = req.body['webhook.secret'] || '';
            updates['webhook.secret'] = rawWebhookSecret ? cryptoService.encrypt(rawWebhookSecret) : '';
            const rawEvents = req.body['webhook.events'];
            updates['webhook.events'] = rawEvents
                ? (Array.isArray(rawEvents) ? rawEvents : [rawEvents])
                : [];
        }

        // Subscription settings
        if (req.body['_subscriptionSettings'] !== undefined) {
            updates['subscription.supportUrl']     = req.body['subscription.supportUrl'] || '';
            updates['subscription.webPageUrl']     = req.body['subscription.webPageUrl'] || '';
            updates['subscription.happProviderId'] = req.body['subscription.happProviderId'] || '';
            updates['subscription.logoUrl']        = req.body['subscription.logoUrl'] || '';
            updates['subscription.pageTitle']      = req.body['subscription.pageTitle'] || '';

            const rawInterval = parseInt(req.body['subscription.updateInterval'], 10);
            updates['subscription.updateInterval'] = isNaN(rawInterval) ? 12 : Math.min(168, Math.max(1, rawInterval));

            let parsedButtons = [];
            try { parsedButtons = JSON.parse(req.body['subscription.buttonsJson'] || '[]'); } catch {}
            if (!Array.isArray(parsedButtons)) parsedButtons = [];
            updates['subscription.buttons'] = parsedButtons
                .filter(b => b && b.label && b.url)
                .slice(0, 10)
                .map(b => ({ label: String(b.label).trim(), url: String(b.url).trim(), icon: String(b.icon || '').trim() }));

            // HAPP-specific settings (only when this request includes any subscription.happ.* field — avoids wiping HAPP when saving the main subscription card alone)
            const hasHappInBody = Object.keys(req.body).some(k => k.startsWith('subscription.happ.'));
            if (hasHappInBody) {
                const VALID_PING_TYPES = ['', 'proxy', 'proxy-head', 'tcp', 'icmp'];
                const rawPingType = req.body['subscription.happ.pingType'] || '';
                updates['subscription.happ.announce']     = String(req.body['subscription.happ.announce'] || '').trim().slice(0, 200);
                updates['subscription.happ.hideSettings'] = req.body['subscription.happ.hideSettings'] === 'on';
                updates['subscription.happ.notifyExpire'] = req.body['subscription.happ.notifyExpire'] === 'on';
                updates['subscription.happ.alwaysHwid']   = req.body['subscription.happ.alwaysHwid'] === 'on';
                updates['subscription.happ.pingType']     = VALID_PING_TYPES.includes(rawPingType) ? rawPingType : '';
                updates['subscription.happ.pingUrl']      = String(req.body['subscription.happ.pingUrl'] || '').trim().slice(0, 500);
                updates['subscription.happ.colorProfile'] = (() => {
                    const raw = String(req.body['subscription.happ.colorProfile'] || '').trim();
                    if (!raw) return '';
                    if (raw.length > 5120) return '';
                    try {
                        const parsed = JSON.parse(raw);
                        if (typeof parsed !== 'object' || Array.isArray(parsed) || parsed === null) return '';
                        return JSON.stringify(parsed);
                    } catch {
                        return '';
                    }
                })();

                const VALID_HWID_MODES = ['off', 'permissive', 'strict'];
                const rawHwidMode = String(req.body['subscription.happ.hwid.mode'] || 'off');
                updates['subscription.happ.hwid.mode'] = VALID_HWID_MODES.includes(rawHwidMode) ? rawHwidMode : 'off';
                const cleanDays = parseInt(req.body['subscription.happ.hwid.inactiveDeviceCleanupDays'], 10);
                updates['subscription.happ.hwid.inactiveDeviceCleanupDays'] = Number.isFinite(cleanDays)
                    ? Math.min(3650, Math.max(7, cleanDays))
                    : 90;
                const rl = parseInt(req.body['subscription.happ.hwid.upsertRateLimitPerMinute'], 10);
                updates['subscription.happ.hwid.upsertRateLimitPerMinute'] = Number.isFinite(rl)
                    ? Math.min(600, Math.max(1, rl))
                    : 60;
                updates['subscription.happ.hwid.maxDevicesAnnounce'] = String(
                    req.body['subscription.happ.hwid.maxDevicesAnnounce'] || ''
                ).trim().slice(0, 300);
                // Multiline soft-block remarks. Each non-empty line becomes a
                // separate fake server (parseRemarkLines in subscription.js
                // dedupes and caps per-line length). Here we only normalize
                // line endings and bound the total payload size to keep
                // settings docs small.
                const sanitizeRemark = (raw) => String(raw || '')
                    .replace(/\r\n?/g, '\n')
                    .replace(/[ \t]+\n/g, '\n')
                    .trim()
                    .slice(0, 1500);
                updates['subscription.happ.hwid.notSupportedRemark'] = sanitizeRemark(
                    req.body['subscription.happ.hwid.notSupportedRemark']
                );
                updates['subscription.happ.hwid.maxDevicesRemark'] = sanitizeRemark(
                    req.body['subscription.happ.hwid.maxDevicesRemark']
                );
            }
        }

        // Homepage mode (decoy/custom). File upload has its own endpoint.
        let homepageModeChanged = null;
        if (req.body['_homepageSettings'] !== undefined) {
            const VALID_MODES = ['nginx', 'custom'];
            const mode = String(req.body['homepage.mode'] || 'nginx');
            const safeMode = VALID_MODES.includes(mode) ? mode : 'nginx';
            updates['homepage.mode'] = safeMode;
            homepageModeChanged = safeMode;
        }

        // Routing settings
        if (req.body['_routingSettings'] !== undefined) {
            updates['routing.enabled'] = req.body['routing.enabled'] === 'on';
            updates['routing.dns.domestic'] = (req.body['routing.dns.domestic'] || '77.88.8.8').trim();
            updates['routing.dns.remote']   = (req.body['routing.dns.remote']   || 'tls://1.1.1.1').trim();
            let parsedRules = [];
            try { parsedRules = JSON.parse(req.body['routing.rulesJson'] || '[]'); } catch {}
            if (!Array.isArray(parsedRules)) parsedRules = [];
            const VALID_ACTIONS = ['direct', 'block'];
            const VALID_TYPES   = ['domain_suffix', 'domain_keyword', 'domain', 'geosite', 'geoip', 'ip_cidr'];
            updates['routing.rules'] = parsedRules
                .filter(r => r && VALID_ACTIONS.includes(r.action) && VALID_TYPES.includes(r.type) && r.value)
                .slice(0, 200)
                .map(r => ({
                    action:  r.action,
                    type:    r.type,
                    value:   String(r.value).trim(),
                    comment: String(r.comment || '').trim().slice(0, 100),
                    enabled: r.enabled !== false,
                }));
            // Invalidate all cached subscriptions so clients receive updated rules immediately
            await cache.invalidateAllSubscriptions();
        }

        // Backup settings
        if (req.body['_backupSettings'] || req.body['backup.enabled'] !== undefined) {
            updates['backup.enabled'] = req.body['backup.enabled'] === 'on';
            updates['backup.intervalHours'] = parseInt(req.body['backup.intervalHours']) || 24;
            updates['backup.keepLast'] = parseInt(req.body['backup.keepLast']) || 7;
            // S3
            updates['backup.s3.enabled'] = req.body['backup.s3.enabled'] === 'on';
            updates['backup.s3.endpoint'] = req.body['backup.s3.endpoint'] || '';
            updates['backup.s3.region'] = req.body['backup.s3.region'] || 'us-east-1';
            updates['backup.s3.bucket'] = req.body['backup.s3.bucket'] || '';
            updates['backup.s3.prefix'] = req.body['backup.s3.prefix'] || 'backups';
            updates['backup.s3.accessKeyId'] = req.body['backup.s3.accessKeyId'] || '';
            if (req.body['backup.s3.secretAccessKey']) {
                updates['backup.s3.secretAccessKey'] = cryptoService.encrypt(req.body['backup.s3.secretAccessKey']);
            }
            updates['backup.s3.keepLast'] = parseInt(req.body['backup.s3.keepLast']) || 30;
        }
        
        await Settings.update(updates);
        
        await invalidateSettingsCache();
        try {
            if (cache.isConnected()) await cache.redis.del('panel:topHwidUsers');
        } catch (_e) { /* ignore */ }
        await reloadSettings();

        // Drop subscription cache so load-balancing toggles take effect now,
        // not after subscriptionTTL (up to 1 h).
        if (systemTabSubmit) {
            await cache.invalidateAllSubscriptions();
        }
        
        const sshPool = require('../../services/sshPoolService');
        await sshPool.reloadSettings();

        if (homepageModeChanged) {
            await homepageService.setMode(homepageModeChanged);
        }

        logger.info(`[Panel] Settings updated`);
        
        res.redirect('/panel/settings?message=' + encodeURIComponent('Настройки сохранены'));
    } catch (error) {
        logger.error('[Panel] Settings save error:', error.message);
        res.redirect('/panel/settings?error=' + encodeURIComponent(`${res.locals.t?.('common.error') || 'Error'}: ${error.message}`));
    }
});

// POST /settings/password - Change password
router.post('/settings/password', async (req, res) => {
    try {
        const currentPassword = String(req.body.currentPassword || '');
        const newPassword = String(req.body.newPassword || '');
        const confirmPassword = String(req.body.confirmPassword || '');

        if (!currentPassword || !newPassword || !confirmPassword) {
            return redirectSettingsSecurity(res, { error: 'Заполните все поля' });
        }

        if (newPassword.length < 6) {
            return redirectSettingsSecurity(res, { error: 'Новый пароль должен быть минимум 6 символов' });
        }

        if (newPassword !== confirmPassword) {
            return redirectSettingsSecurity(res, { error: res.locals.t?.('settings.passwordsMismatch') || 'Passwords do not match' });
        }

        const admin = await Admin.verifyPassword(req.session.adminUsername, currentPassword);
        if (!admin) {
            return redirectSettingsSecurity(res, { error: res.locals.t?.('auth.invalidCurrentPassword') || 'Invalid current password' });
        }

        if (!admin.twoFactor?.enabled) {
            await Admin.changePassword(req.session.adminUsername, newPassword);

            logger.info(`[Panel] Password changed for: ${req.session.adminUsername}`);
            return redirectSettingsSecurity(res, { message: res.locals.t?.('auth.passwordChanged') || 'Password successfully changed' });
        }

        if (!admin.twoFactor.secretEncrypted) {
            logger.warn(`[Panel] Missing TOTP secret for enabled 2FA on password change: ${req.session.adminUsername} (IP: ${req.ip})`);
            return redirectSettingsSecurity(res, { error: res.locals.t?.('auth.totpConfigError') || 'TOTP configuration error' });
        }

        const newPasswordHash = await bcrypt.hash(newPassword, 12);
        req.session.panelTotpPending = {
            type: 'settings',
            action: 'password_change',
            username: req.session.adminUsername,
            returnTo: '/panel/settings?tab=security',
            payload: {
                newPasswordHash,
            },
            createdAt: Date.now(),
        };

        return res.redirect('/panel/totp');
    } catch (error) {
        logger.error('[Panel] Password change error:', error.message);
        return redirectSettingsSecurity(res, { error: error.message });
    }
});

// POST /settings/totp/start - Start enable/rotate flow
router.post('/settings/totp/start', async (req, res) => {
    try {
        const intent = String(req.body.intent || '').trim();
        const currentPassword = String(req.body.currentPassword || '');

        if (!['enable', 'rotate'].includes(intent)) {
            clearPanelTotpPending(req);
            return redirectSettingsSecurity(res, { error: res.locals.t?.('auth.totpFlowError') || 'Invalid TOTP action' });
        }

        if (!currentPassword) {
            clearPanelTotpPending(req);
            return redirectSettingsSecurity(res, { error: res.locals.t?.('auth.enterCurrentPassword') || 'Enter current password' });
        }

        const admin = await Admin.verifyPassword(req.session.adminUsername, currentPassword);
        if (!admin) {
            clearPanelTotpPending(req);
            return redirectSettingsSecurity(res, { error: res.locals.t?.('auth.invalidCurrentPassword') || 'Invalid current password' });
        }

        if (intent === 'enable') {
            if (admin.twoFactor?.enabled) {
                clearPanelTotpPending(req);
                return redirectSettingsSecurity(res, { error: res.locals.t?.('auth.totpAlreadyEnabled') || 'TOTP is already enabled' });
            }

            const enrollment = await totpService.generateEnrollmentData({ username: admin.username });
            req.session.panelTotpPending = {
                type: 'settings',
                action: 'totp_enable_enroll',
                username: admin.username,
                returnTo: '/panel/settings?tab=security',
                secretEncrypted: enrollment.secretEncrypted,
                createdAt: Date.now(),
            };

            return res.redirect('/panel/totp');
        }

        if (!admin.twoFactor?.enabled || !admin.twoFactor?.secretEncrypted) {
            clearPanelTotpPending(req);
            return redirectSettingsSecurity(res, { error: res.locals.t?.('auth.totpRequiredForRotate') || 'TOTP must be enabled to rotate' });
        }

        req.session.panelTotpPending = {
            type: 'settings',
            action: 'totp_rotate_verify_current',
            username: admin.username,
            returnTo: '/panel/settings?tab=security',
            payload: {
                currentSecretEncrypted: admin.twoFactor.secretEncrypted,
            },
            createdAt: Date.now(),
        };

        return res.redirect('/panel/totp');
    } catch (error) {
        clearPanelTotpPending(req);
        logger.error('[Panel] Settings TOTP start error:', error.message);
        return redirectSettingsSecurity(res, { error: res.locals.t?.('auth.totpFlowError') || 'Error starting TOTP flow' });
    }
});

// POST /settings/totp/disable - Disable TOTP for current admin
router.post('/settings/totp/disable', async (req, res) => {
    try {
        const currentPassword = String(req.body.currentPassword || '');

        if (!currentPassword) {
            return redirectSettingsSecurity(res, { error: res.locals.t?.('auth.enterCurrentPassword') || 'Enter current password' });
        }

        const admin = await Admin.verifyPassword(req.session.adminUsername, currentPassword);
        if (!admin) {
            return redirectSettingsSecurity(res, { error: res.locals.t?.('auth.invalidCurrentPassword') || 'Invalid current password' });
        }

        if (!admin.twoFactor?.enabled || !admin.twoFactor?.secretEncrypted) {
            return redirectSettingsSecurity(res, { error: res.locals.t?.('auth.totpAlreadyDisabled') || 'TOTP is already disabled' });
        }

        req.session.panelTotpPending = {
            type: 'settings',
            action: 'totp_disable_verify_current',
            username: admin.username,
            returnTo: '/panel/settings?tab=security',
            payload: {
                currentSecretEncrypted: admin.twoFactor.secretEncrypted,
            },
            createdAt: Date.now(),
        };

        return res.redirect('/panel/totp');
    } catch (error) {
        logger.error('[Panel] Settings TOTP disable error:', error.message);
        return redirectSettingsSecurity(res, { error: res.locals.t?.('auth.totpDisableError') || 'Error disabling TOTP' });
    }
});

// POST /settings/reset-traffic - Reset traffic counters for all users
router.post('/settings/reset-traffic', async (req, res) => {
    try {
        const result = await HyUser.updateMany(
            {},
            {
                $set: {
                    'traffic.tx': 0,
                    'traffic.rx': 0,
                    'traffic.lastUpdate': new Date()
                }
            }
        );
        
        logger.warn(`[Panel] Traffic reset for ${result.modifiedCount} users by admin: ${req.session.adminUsername}`);
        
        const users = await HyUser.find({}).select('userId subscriptionToken').lean();
        const invalidateTasks = users.flatMap((user) => {
            const tasks = [() => cache.invalidateUser(user.userId)];
            if (user.subscriptionToken) {
                tasks.push(() => cache.invalidateSubscription(user.subscriptionToken));
            }
            return tasks;
        });

        const BATCH_SIZE = 100;
        for (let i = 0; i < invalidateTasks.length; i += BATCH_SIZE) {
            await Promise.all(invalidateTasks.slice(i, i + BATCH_SIZE).map((task) => task()));
        }
        
        await cache.invalidateDashboardCounts();
        await cache.invalidateTrafficStats();
        
        res.json({ 
            success: true, 
            count: result.modifiedCount,
            message: `Трафик сброшен у ${result.modifiedCount} пользователей`
        });
    } catch (error) {
        logger.error('[Panel] Traffic reset error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// POST /settings/reset-stats - Reset statistics
router.post('/settings/reset-stats', async (req, res) => {
    try {
        const StatsSnapshot = require('../../models/statsSnapshotModel');
        const result = await StatsSnapshot.deleteMany({});
        
        logger.warn(`[Panel] Stats reset: ${result.deletedCount} snapshots deleted by admin: ${req.session.adminUsername}`);
        
        const statsService = require('../../services/statsService');
        await statsService.invalidateCache();
        
        res.json({ 
            success: true, 
            count: result.deletedCount,
            message: `Удалено ${result.deletedCount} записей статистики`
        });
    } catch (error) {
        logger.error('[Panel] Stats reset error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== HOMEPAGE ====================

// In-memory upload (one small file). Disk write is handled atomically by homepageService.
const homepageUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: homepageService.MAX_CUSTOM_BYTES, files: 1 },
});

// POST /settings/homepage/upload - replace custom homepage HTML
router.post('/settings/homepage/upload', (req, res) => {
    homepageUpload.single('file')(req, res, async (err) => {
        if (err) {
            const msg = err.code === 'LIMIT_FILE_SIZE'
                ? `File too large (max ${homepageService.MAX_CUSTOM_BYTES} bytes)`
                : err.message;
            return res.redirect('/panel/settings?tab=security&error=' + encodeURIComponent(msg));
        }
        if (!req.file) {
            return res.redirect('/panel/settings?tab=security&error=' + encodeURIComponent('No file uploaded'));
        }
        try {
            await homepageService.setCustom(req.file.buffer);
            await Settings.update({ 'homepage.mode': 'custom' });
            await homepageService.setMode('custom');
            logger.info(`[Panel] Homepage custom HTML uploaded (${req.file.buffer.length} bytes) by ${req.session.adminUsername}`);
            return res.redirect('/panel/settings?tab=security&message=' + encodeURIComponent('Главная страница обновлена'));
        } catch (error) {
            logger.error(`[Panel] Homepage upload error: ${error.message}`);
            return res.redirect('/panel/settings?tab=security&error=' + encodeURIComponent(error.message));
        }
    });
});

// POST /settings/homepage/reset - drop custom HTML, revert to fake nginx
router.post('/settings/homepage/reset', async (req, res) => {
    try {
        await homepageService.clearCustom();
        await Settings.update({ 'homepage.mode': 'nginx' });
        logger.info(`[Panel] Homepage reset to default by ${req.session.adminUsername}`);
        return res.redirect('/panel/settings?tab=security&message=' + encodeURIComponent('Главная страница сброшена'));
    } catch (error) {
        logger.error(`[Panel] Homepage reset error: ${error.message}`);
        return res.redirect('/panel/settings?tab=security&error=' + encodeURIComponent(error.message));
    }
});

// POST /settings/flush-cache - Flush all Redis cache
router.post('/settings/flush-cache', async (req, res) => {
    try {
        const result = await cache.flushAll();
        
        if (result.success) {
            logger.info(`[Panel] Cache flushed by admin: ${req.session.adminUsername}`);
            res.json({ success: true, message: 'Cache cleared' });
        } else {
            res.status(500).json({ success: false, error: result.error || 'Failed to flush cache' });
        }
    } catch (error) {
        logger.error('[Panel] Cache flush error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== BACKUP SETTINGS ====================

// POST /settings/create-backup - Create backup now
router.post('/settings/create-backup', async (req, res) => {
    try {
        const backupService = require('../../services/backupService');
        const settings = await Settings.get();
        
        const result = await backupService.createBackup(settings);
        
        res.json({
            success: true,
            filename: result.filename,
            size: result.sizeMB,
        });
    } catch (error) {
        logger.error(`[Backup] Manual backup error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

// POST /settings/test-s3 - Test S3 connection
router.post('/settings/test-s3', async (req, res) => {
    try {
        const backupService = require('../../services/backupService');
        const { endpoint, region, bucket, accessKeyId, secretAccessKey } = req.body;
        
        if (!bucket || !accessKeyId || !secretAccessKey) {
            return res.status(400).json({ error: 'Bucket, Access Key и Secret Key обязательны' });
        }
        
        const result = await backupService.testS3Connection({
            endpoint,
            region: region || 'us-east-1',
            bucket,
            accessKeyId,
            secretAccessKey,
        });
        
        if (result.success) {
            res.json({ success: true });
        } else {
            res.status(400).json({ error: result.error });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// GET /settings/backups - List local backups
router.get('/settings/backups', async (req, res) => {
    try {
        const backupService = require('../../services/backupService');
        const backups = await backupService.listBackups();
        res.json({ backups });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// GET /settings/backups-s3 - List S3 backups
router.get('/settings/backups-s3', async (req, res) => {
    try {
        const backupService = require('../../services/backupService');
        const settings = await Settings.get();
        
        if (!settings?.backup?.s3?.enabled) {
            return res.json({ backups: [], error: 'S3 not configured' });
        }
        
        const backups = await backupService.listS3Backups(settings);
        res.json({ backups });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// GET /settings/backups/download - Download a local backup file
// Query: ?name=hysteria-backup-YYYY-MM-DDTHH-mm-ss.tar.gz
router.get('/settings/backups/download', async (req, res) => {
    try {
        const backupService = require('../../services/backupService');
        const fsSync = require('fs');

        const name = String(req.query.name || '');
        const localPath = backupService.getLocalBackupPath(name);

        let stats;
        try {
            stats = await require('fs').promises.stat(localPath);
        } catch {
            return res.status(404).json({ error: 'Backup file not found' });
        }

        const safeName = require('path').basename(localPath);
        res.setHeader('Content-Type', 'application/gzip');
        res.setHeader('Content-Length', stats.size);
        res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
        res.setHeader('Cache-Control', 'no-store');

        const stream = fsSync.createReadStream(localPath);
        stream.on('error', (err) => {
            logger.error(`[Backup] Local download stream error: ${err.message}`);
            if (!res.headersSent) res.status(500).end();
            else res.destroy(err);
        });
        stream.pipe(res);

        logger.info(`[Panel] Backup download (local): ${safeName} by ${req.session.adminUsername}`);
    } catch (error) {
        logger.error(`[Panel] Backup download error: ${error.message}`);
        if (!res.headersSent) res.status(400).json({ error: error.message });
    }
});

// GET /settings/backups-s3/download - Download an S3 backup file
// Query: ?key=<full S3 object key>
router.get('/settings/backups-s3/download', async (req, res) => {
    try {
        const backupService = require('../../services/backupService');
        const path = require('path');

        const key = String(req.query.key || '').trim();
        if (!key) return res.status(400).json({ error: 'Key is required' });

        const settings = await Settings.get();
        if (!settings?.backup?.s3?.enabled) {
            return res.status(400).json({ error: 'S3 not configured' });
        }

        // Sanity check: key must live in the configured prefix to prevent
        // arbitrary object reads from the bucket via this endpoint.
        const prefix = (settings.backup.s3.prefix || 'backups').replace(/\/+$/, '');
        if (!key.startsWith(`${prefix}/hysteria-backup-`) || !key.endsWith('.tar.gz')) {
            return res.status(400).json({ error: 'Invalid backup key' });
        }

        const { stream, contentLength, contentType } = await backupService.getS3BackupStream(settings, key);

        const safeName = path.basename(key);
        res.setHeader('Content-Type', contentType || 'application/gzip');
        if (contentLength) res.setHeader('Content-Length', contentLength);
        res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
        res.setHeader('Cache-Control', 'no-store');

        stream.on('error', (err) => {
            logger.error(`[Backup] S3 download stream error: ${err.message}`);
            if (!res.headersSent) res.status(500).end();
            else res.destroy(err);
        });
        stream.pipe(res);

        logger.info(`[Panel] Backup download (S3): ${safeName} by ${req.session.adminUsername}`);
    } catch (error) {
        logger.error(`[Panel] S3 backup download error: ${error.message}`);
        if (!res.headersSent) res.status(500).json({ error: error.message });
    }
});

// POST /settings/restore-backup - Restore from backup (local or S3)
router.post('/settings/restore-backup', async (req, res) => {
    try {
        const backupService = require('../../services/backupService');
        const settings = await Settings.get();
        const { source, identifier } = req.body;
        
        if (!source || !identifier) {
            return res.status(400).json({ error: 'Source and identifier required' });
        }
        
        if (source !== 'local' && source !== 's3') {
            return res.status(400).json({ error: 'Invalid source' });
        }
        
        if (source === 's3' && !settings?.backup?.s3?.enabled) {
            return res.status(400).json({ error: 'S3 not configured' });
        }
        
        logger.info(`[Restore] Starting restore from ${source}: ${identifier}`);
        
        await backupService.restoreBackup(settings, source, identifier);
        
        logger.info(`[Restore] Completed successfully`);
        
        res.json({ success: true, message: 'Database restored successfully' });
    } catch (error) {
        logger.error(`[Restore] Error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

// ==================== API KEYS ====================

// POST /api-keys - Create a new API key (returns plaintext key once)
router.post('/api-keys', async (req, res) => {
    try {
        const { name, scopes, allowedIPs, rateLimit, expiresAt } = req.body;

        if (!name || !name.trim()) {
            return res.status(400).json({ error: 'Name is required' });
        }

        const scopesArr = scopes
            ? (Array.isArray(scopes) ? scopes : [scopes])
            : [];

        const invalidScopes = scopesArr.filter(s => !ApiKey.VALID_SCOPES.includes(s));
        if (invalidScopes.length > 0) {
            return res.status(400).json({ error: `Invalid scopes: ${invalidScopes.join(', ')}` });
        }

        const allowedIPsArr = allowedIPs
            ? allowedIPs.split('\n').map(s => s.trim()).filter(Boolean)
            : [];

        const { doc, plainKey } = await ApiKey.createKey({
            name: name.trim(),
            scopes: scopesArr,
            allowedIPs: allowedIPsArr,
            rateLimit: parseInt(rateLimit) || 60,
            expiresAt: expiresAt || null,
            createdBy: req.session.adminUsername,
        });

        logger.info(`[Panel] API key created: "${doc.name}" (${doc.keyPrefix}...) by ${req.session.adminUsername}`);

        res.json({ success: true, key: plainKey, doc });
    } catch (error) {
        logger.error(`[Panel] API key create error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

// POST /api-keys/:id/toggle - Enable/disable a key
router.post('/api-keys/:id/toggle', async (req, res) => {
    try {
        const key = await ApiKey.findById(req.params.id);
        if (!key) {
            return res.status(404).json({ error: 'API key not found' });
        }

        key.active = !key.active;
        await key.save();

        logger.info(`[Panel] API key ${key.keyPrefix}... ${key.active ? 'enabled' : 'disabled'} by ${req.session.adminUsername}`);
        res.json({ success: true, active: key.active });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST /api-keys/:id/delete - Delete a key
router.post('/api-keys/:id/delete', async (req, res) => {
    try {
        const key = await ApiKey.findByIdAndDelete(req.params.id);
        if (!key) {
            return res.status(404).json({ error: 'API key not found' });
        }

        logger.info(`[Panel] API key "${key.name}" (${key.keyPrefix}...) deleted by ${req.session.adminUsername}`);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST /settings/test-webhook - Send test webhook
router.post('/settings/test-webhook', async (req, res) => {
    try {
        const { url, secret, event } = req.body;

        if (!url || !url.trim()) {
            return res.status(400).json({ error: 'URL is required' });
        }

        // Whitelist event against EVENTS to prevent spoofing arbitrary headers.
        const knownEvents = Object.values(webhookService.EVENTS);
        const safeEvent = event && knownEvents.includes(event) ? event : undefined;

        const result = await webhookService.test(url.trim(), secret || '', safeEvent);

        if (result.success) {
            logger.info(`[Panel] Webhook test OK: ${url} (HTTP ${result.status})${safeEvent ? ` event=${safeEvent}` : ''}`);
            res.json({ success: true, status: result.status });
        } else {
            res.status(400).json({ success: false, error: result.error, status: result.status });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
