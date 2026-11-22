/**
 * Onboarding wizard routes.
 * Shown once after first admin login. Lets the user choose a deployment scenario
 * (self-host on this server vs. manage remote nodes) and optionally bootstrap
 * local Hysteria / Xray nodes via auto-setup.
 */

const crypto = require('crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const router = express.Router();

const HyNode = require('../../models/hyNodeModel');
const HyUser = require('../../models/hyUserModel');
const ServerGroup = require('../../models/serverGroupModel');
const Settings = require('../../models/settingsModel');
const cryptoService = require('../../services/cryptoService');
const sshKeyService = require('../../services/sshKeyService');
const nodeSetup = require('../../services/nodeSetup');
const { withNodeWriterFence, assertRelaySetupAllowed, describeRoleError } = require('../../services/rebuildRelayRoleGuard');
const { withNodes } = require('../../services/rebuildLocks');
const config = require('../../../config');
const logger = require('../../utils/logger');
const { invalidateOnboardingCache } = require('./helpers');
const { invalidateGroupsCache, invalidateNodesCache } = require('../../utils/helpers');

// In-memory map of active bootstrap tasks: taskId -> { logs, done, error }
const _bootstrapTasks = new Map();

// Rate limiter for wizard POST actions (SSH credentials + node creation)
const wizardLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.redirect('/panel/wizard?error=' + encodeURIComponent(res.locals.t?.('wizard.tooManyRequests') || 'Too many requests. Try again later.'));
    },
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Mark the onboarding wizard as completed and persist to DB.
 * Invalidates the in-memory cache in helpers.js so the middleware reflects it.
 */
async function completeOnboarding(profile) {
    await Settings.update({
        'deployment.completed': true,
        'deployment.profile': profile,
        'deployment.completedAt': new Date(),
    });
    invalidateOnboardingCache();
    logger.info(`[Wizard] Onboarding completed with profile: ${profile}`);
}

/**
 * Check if onboarding is already completed.
 * If so, redirect to dashboard — prevents re-running the wizard.
 * Returns true if redirected (caller should return early).
 */
async function redirectIfCompleted(req, res) {
    const settings = await Settings.get();
    if (settings.deployment?.completed) {
        res.redirect('/panel');
        return true;
    }
    return false;
}

async function ensureStarterAccessBundle(nodeIds) {
    if (!Array.isArray(nodeIds) || nodeIds.length === 0) {
        return null;
    }

    const group = await ServerGroup.findOneAndUpdate(
        { name: 'Celerity Primary Access' },
        {
            $setOnInsert: {
                name: 'Celerity Primary Access',
                description: 'Created automatically during onboarding.',
                color: '#6366f1',
                subscriptionTitle: 'C³ CELERITY',
            },
            $set: { active: true },
        },
        { new: true, upsert: true }
    );

    await HyNode.updateMany(
        { _id: { $in: nodeIds } },
        { $addToSet: { groups: group._id } }
    );

    let user = await HyUser.findOne({ userId: 'admin' });
    let generatedPassword = '';
    let createdUser = false;

    if (!user) {
        generatedPassword = cryptoService.generatePassword('admin');
        user = await HyUser.create({
            userId: 'admin',
            username: 'Administrator',
            password: generatedPassword,
            groups: [group._id],
            nodes: [],
            enabled: true,
            trafficLimit: 0,
            maxDevices: 0,
        });
        createdUser = true;
    } else {
        await HyUser.updateOne(
            { _id: user._id },
            {
                $set: {
                    enabled: true,
                    username: user.username || 'Administrator',
                },
                $addToSet: { groups: group._id },
            }
        );
        user = await HyUser.findById(user._id);
    }

    if (user && !user.subscriptionToken) {
        await user.save();
    }

    const subscriptionToken = user.subscriptionToken;

    await Promise.all([
        invalidateGroupsCache(),
        invalidateNodesCache(),
    ]);

    return {
        groupName: group.name,
        userId: user.userId,
        subscriptionToken,
        subscriptionUrl: `${config.BASE_URL}/api/files/${subscriptionToken}`,
    };
}

// ─── Step 1: Choose scenario ──────────────────────────────────────────────────

// GET /panel/wizard
router.get('/wizard', async (req, res) => {
    if (await redirectIfCompleted(req, res)) return;

    res.render('wizard', {
        step: 'scenario',
        error: req.query.error || null,
        panelDomain: config.PANEL_DOMAIN || '',
        defaults: null,
        taskId: null,
    });
});

// POST /panel/wizard/scenario
router.post('/wizard/scenario', wizardLimiter, async (req, res) => {
    if (await redirectIfCompleted(req, res)) return;

    const scenario = req.body.scenario;

    if (scenario !== 'self-host' && scenario !== 'remote') {
        return res.redirect('/panel/wizard?error=' + encodeURIComponent(res.locals.t?.('wizard.selectDeploymentOption') || 'Please select a deployment option'));
    }

    try {
        if (scenario === 'remote') {
            await completeOnboarding('remote');
            return res.redirect('/panel/nodes/add');
        }

        // Save profile choice but do not complete yet — Step 2 does that
        await Settings.update({ 'deployment.profile': 'self-host' });
        return res.redirect('/panel/wizard/self-host');
    } catch (err) {
        logger.error(`[Wizard] Scenario POST error: ${err.message}`);
        return res.redirect('/panel/wizard?error=' + encodeURIComponent(err.message));
    }
});

// ─── Step 2: Self-host configuration ─────────────────────────────────────────

// GET /panel/wizard/self-host
router.get('/wizard/self-host', async (req, res) => {
    if (await redirectIfCompleted(req, res)) return;

    res.render('wizard', {
        step: 'self-host',
        error: req.query.error || null,
        panelDomain: config.PANEL_DOMAIN || '',
        taskId: null,
        defaults: {
            hyPort:      443,
            hyPortRange: '20000-50000',
            hyDomain:    config.PANEL_DOMAIN || '',
            xrayPort:    8443,
        },
    });
});

// POST /panel/wizard/self-host
router.post('/wizard/self-host', wizardLimiter, async (req, res) => {
    if (await redirectIfCompleted(req, res)) return;

    try {
        const installHysteria = req.body.installHysteria === 'on';
        const installXray     = req.body.installXray     === 'on';

        if (!installHysteria && !installXray) {
            return res.redirect('/panel/wizard/self-host?error=' + encodeURIComponent(res.locals.t?.('wizard.noProtocolSelected') || 'Please select at least one protocol.'));
        }

        // SSH credentials
        const sshIp       = (req.body['ssh.ip']       || '').trim();
        const sshPort     = parseInt(req.body['ssh.port'])     || 22;
        const sshUsername = (req.body['ssh.username']  || 'root').trim();
        const sshPassword    = (req.body['ssh.password']    || '').trim();
        const sshPrivateKeyRaw = (req.body['ssh.privateKey'] || '').trim();

        if (!sshIp) {
            return res.redirect('/panel/wizard/self-host?error=' + encodeURIComponent(res.locals.t?.('wizard.serverAddressRequired') || 'Server IP or hostname is required'));
        }

        if (!sshPassword && !sshPrivateKeyRaw) {
            return res.redirect('/panel/wizard/self-host?error=' + encodeURIComponent(res.locals.t?.('wizard.sshAuthRequired') || 'SSH password or private key is required'));
        }

        let encryptedPrivateKey = '';
        if (sshPrivateKeyRaw) {
            if (!sshKeyService.isValidPrivateKey(sshPrivateKeyRaw)) {
                return res.redirect('/panel/wizard/self-host?error=' + encodeURIComponent(res.locals.t?.('wizard.invalidSshPrivateKey') || 'Invalid SSH private key format'));
            }
            encryptedPrivateKey = cryptoService.encrypt(sshPrivateKeyRaw);
        }

        const encryptedPassword = sshPassword ? cryptoService.encrypt(sshPassword) : '';

        const resolvedSsh = {
            port:       sshPort,
            username:   sshUsername,
            password:   encryptedPassword,
            privateKey: encryptedPrivateKey,
        };

        // Build list of nodes to create
        const nodesToCreate = [];

        if (installHysteria) {
            const hyPort      = parseInt(req.body['hy.port'])      || 443;
            const hyDomain    = (req.body['hy.domain']    || config.PANEL_DOMAIN || '').trim();

            nodesToCreate.push({
                type:              'hysteria',
                name:              'Local Hysteria',
                ip:                sshIp,
                domain:            hyDomain,
                port:              hyPort,
                portRange:         '',
                statsPort:         9999,
                statsSecret:       cryptoService.generateNodeSecret(),
                ssh:               resolvedSsh,
                active:            true,
                cascadeRole:       'standalone',
            });
        }

        if (installXray) {
            const xrayPort = parseInt(req.body['xray.port']) || 8443;
            const xrayTransport   = (req.body['xray.transport']   || 'tcp').trim();
            const xrayFingerprint = (req.body['xray.fingerprint'] || 'random').trim();
            const xrayFlow        = (req.body['xray.flow']        || '').trim();
            const xrayRealityDest = (req.body['xray.realityDest'] || 'www.google.com:443').trim();
            const xrayRealitySni  = (req.body['xray.realitySni']  || 'www.google.com')
                .split(',').map(s => s.trim()).filter(Boolean);
            const xrayShortIdsRaw = (req.body['xray.realityShortIds'] || '').trim();
            const xrayShortIds    = xrayShortIdsRaw
                ? xrayShortIdsRaw.split(',').map(s => s.trim())
                : [''];

            nodesToCreate.push({
                type:        'xray',
                name:        'Local Xray',
                ip:          sshIp,
                port:        xrayPort,
                ssh:         resolvedSsh,
                active:      true,
                cascadeRole: 'standalone',
                xray: {
                    transport:        xrayTransport,
                    security:         'reality',
                    fingerprint:      xrayFingerprint,
                    flow:             xrayTransport === 'tcp' ? (xrayFlow || 'xtls-rprx-vision') : '',
                    realityDest:      xrayRealityDest,
                    realitySni:       xrayRealitySni,
                    realityShortIds:  xrayShortIds,
                    apiPort:          61000,
                    agentPort:        62080,
                    agentToken:       nodeSetup.generateAgentToken(),
                    agentTls:         true,
                },
            });
        }

        // Preflight all existing cards before creating any new ones. The
        // background runner rechecks them under its own fence before effects.
        const createdNodeIds = await withNodeWriterFence(async (options, verify) => {
            const existingByIndex = [];
            if (options.writeConcern) {
                for (const { ip, type } of nodesToCreate) {
                    const existing = await HyNode.findOne({ ip, type }).read('primary').readConcern('majority').maxTimeMS(5000);
                    if (existing) await assertRelaySetupAllowed(existing);
                    existingByIndex.push(existing);
                }
            }
            const ids = [];
            for (const [i, nodeData] of nodesToCreate.entries()) {
                const existing = options.writeConcern ? existingByIndex[i]
                    : await HyNode.findOne({ ip: nodeData.ip, type: nodeData.type });
                if (existing) {
                    logger.info(`[Wizard] Node ${nodeData.type} on ${nodeData.ip} already exists, reusing`);
                    ids.push(existing._id.toString());
                } else {
                    await verify();
                    const created = options.writeConcern ? await new HyNode(nodeData).save(options) : await HyNode.create(nodeData);
                    logger.info(`[Wizard] Created ${nodeData.type} node on ${nodeData.ip}`);
                    ids.push(created._id.toString());
                }
            }
            return ids;
        });

        await invalidateNodesCache();

        // Create a task and redirect to progress page
        const taskId = crypto.randomUUID();
        _bootstrapTasks.set(taskId, {
            logs: [],
            done: false,
            success: false,
            error: null,
            starterSubscription: null,
        });

        // Run setup in background, do not await
        _runBootstrap(taskId, createdNodeIds).catch(err => {
            logger.error(`[Wizard] Bootstrap error: ${err.message}`);
        });

        return res.redirect(`/panel/wizard/progress/${taskId}`);
    } catch (err) {
        const conflict = describeRoleError(err, res.locals.t);
        if (conflict) return res.redirect('/panel/wizard/self-host?error=' + encodeURIComponent(conflict.message));
        logger.error(`[Wizard] Self-host POST error: ${err.message}`);
        return res.redirect('/panel/wizard/self-host?error=' + encodeURIComponent(err.message));
    }
});

// ─── Bootstrap runner ─────────────────────────────────────────────────────────

async function _runBootstrap(taskId, nodeIds) {
    const task = _bootstrapTasks.get(taskId);
    if (!task) return;

    const pushLog = (line) => { task.logs.push(line); };

    let allSuccess = true;
    let statusChanged = false;

    try {
        await withNodeWriterFence((options, verify) => {
            const run = async () => {
                const current = new Map();
                if (options.writeConcern) {
                    for (const nodeId of nodeIds) {
                        const node = await HyNode.findById(nodeId).read('primary').readConcern('majority').maxTimeMS(5000);
                        if (node) await assertRelaySetupAllowed(node);
                        current.set(nodeId, node);
                    }
                    await verify();
                }
                try {
                    const starterBundle = await ensureStarterAccessBundle(nodeIds);
                    if (starterBundle) {
                        pushLog(`[Info] Starter group ready: ${starterBundle.groupName}`);
                        pushLog(`[Info] Starter user ready: ${starterBundle.userId}`);
                        task.starterSubscription = {
                            userId: starterBundle.userId,
                            url: starterBundle.subscriptionUrl,
                            token: starterBundle.subscriptionToken,
                        };
                        pushLog('[Info] Starter subscription link is ready.');
                        pushLog('[Info] It will be shown separately after provisioning completes.');
                    }
                } catch (err) {
                    pushLog(`[Error] Could not prepare starter access: ${err.message}`);
                    allSuccess = false;
                }

                for (const nodeId of nodeIds) {
                    const node = options.writeConcern ? current.get(nodeId) : await HyNode.findById(nodeId);
                    if (!node) {
                        pushLog(`[Error] Node ${nodeId} not found, skipping`);
                        allSuccess = false;
                        continue;
                    }
                    if (node.type === 'virtual') {
                        pushLog(`[Skip] Virtual node ${node.name}: nothing to install`);
                        continue;
                    }

                    pushLog(`\n--- Setting up ${node.type.toUpperCase()} node: ${node.name} (${node.ip}) ---`);

                    let result;
                    await verify();
                    try {
                        if (node.type === 'xray') {
                            result = await nodeSetup.setupXrayNodeWithAgent(node, { restartService: true });
                        } else {
                            result = await nodeSetup.setupNode(node, {
                                installHysteria:  true,
                                setupPortHopping: false,
                                restartService:   true,
                            });
                        }
                    } catch (err) {
                        result = { success: false, error: err.message, logs: [] };
                    }

                    for (const line of (result.logs || [])) { pushLog(line); }

                    if (result.success) {
                        if (node.type === 'xray') {
                            const completion = await require('../../services/syncService').finishXraySetup(node, [], {
                                agentToken: result.agentToken, writeOptions: options, verify,
                            });
                            const { xray_status, xray_verification } = completion;
                            task.xrayHealth = { xray_status, xray_verification };
                            for (const line of completion.logs) pushLog(line);
                            statusChanged = true;
                            if (!completion.success) {
                                allSuccess = false;
                                task.starterSubscription = null;
                                break;
                            }
                            if (completion.warning) continue;
                        } else {
                            await verify();
                            await HyNode.findByIdAndUpdate(nodeId, { $set: {
                                status: 'online', lastSync: new Date(), lastError: '', healthFailures: 0, useTlsFiles: result.useTlsFiles,
                            } }, options);
                        }
                        statusChanged = true;
                        pushLog(`[OK] ${node.type.toUpperCase()} node setup completed`);
                    } else {
                        await verify();
                        await HyNode.findByIdAndUpdate(nodeId, { $set: { status: 'error', lastError: result.error } }, options);
                        statusChanged = true;
                        pushLog(`[FAIL] ${node.type.toUpperCase()} node setup failed: ${result.error}`);
                        allSuccess = false;
                    }
                }

            };
            return options.writeConcern ? withNodes(nodeIds, run) : run();
        });
    } catch (error) {
        const conflict = describeRoleError(error);
        if (!conflict) throw error;
        pushLog(`[Error] ${conflict.message}`);
        allSuccess = false;
    }

    if (statusChanged) {
        await invalidateNodesCache();
    }

    if (allSuccess) {
        await completeOnboarding('self-host');
        pushLog(task.xrayHealth?.xray_verification === 'unavailable'
            ? '[Warning] Onboarding finished without Xray runtime verification.'
            : '\n[Done] All nodes set up successfully. Onboarding complete.');
    } else {
        pushLog('\n[Done] Setup finished with errors. Onboarding remains open until provisioning completes successfully.');
    }

    task.done    = true;
    task.success = allSuccess;

    // Clean up task from memory after 10 minutes
    setTimeout(() => _bootstrapTasks.delete(taskId), 10 * 60 * 1000);
}

// ─── Step 3: Progress page ────────────────────────────────────────────────────

// GET /panel/wizard/progress/:taskId — renders the progress shell page
router.get('/wizard/progress/:taskId', (req, res) => {
    const taskId = req.params.taskId;
    if (!_bootstrapTasks.has(taskId)) {
        return res.redirect('/panel/wizard?error=' + encodeURIComponent(res.locals.t?.('wizard.bootstrapTaskNotFound') || 'Bootstrap task not found'));
    }

    res.render('wizard', {
        step:     'progress',
        taskId,
        error:    null,
        panelDomain: config.PANEL_DOMAIN || '',
        defaults: null,
    });
});

// GET /panel/wizard/progress/:taskId/stream — SSE log stream
router.get('/wizard/progress/:taskId/stream', (req, res) => {
    const taskId = req.params.taskId;
    const task = _bootstrapTasks.get(taskId);

    if (!task) {
        res.setHeader('Content-Type',      'text/event-stream; charset=utf-8');
        res.setHeader('Cache-Control',     'no-cache');
        res.setHeader('X-Accel-Buffering', 'no');
        res.flushHeaders();
        res.write(`data: ${JSON.stringify({ type: 'error', message: 'Task not found' })}\n\n`);
        res.end();
        return;
    }

    res.setHeader('Content-Type',      'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control',     'no-cache');
    res.setHeader('Connection',        'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    let sentIndex = 0;

    const send = (type, data) => {
        if (!res.writableEnded) {
            res.write(`data: ${JSON.stringify({ type, ...data })}\n\n`);
            if (typeof res.flush === 'function') res.flush();
        }
    };

    const flush = () => {
        const logs = task.logs;
        while (sentIndex < logs.length) {
            send('log', { message: logs[sentIndex] });
            sentIndex++;
        }

        if (task.done) {
            send('done', {
                success: task.success,
                ...task.xrayHealth,
                starterSubscription: task.starterSubscription,
            });
            clearInterval(intervalId);
            res.end();
        }
    };

    const intervalId = setInterval(flush, 300);

    req.on('close', () => clearInterval(intervalId));
});

// POST /panel/wizard/skip — skip the wizard entirely (no nodes created)
router.post('/wizard/skip', wizardLimiter, async (req, res) => {
    try {
        await completeOnboarding('');
        return res.redirect('/panel');
    } catch (err) {
        logger.error(`[Wizard] Skip error: ${err.message}`);
        return res.redirect('/panel/wizard?error=' + encodeURIComponent(err.message));
    }
});

module.exports = router;
