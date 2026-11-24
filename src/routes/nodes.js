/**
 * API для управления нодами Hysteria + Xray
 */

const express = require('express');
const { isDeepStrictEqual } = require('node:util');
const router = express.Router();
const HyNode = require('../models/hyNodeModel');
const { MODE_PATH, PROFILE_FIELDS, RealityGuardInputError, readXrayPolicy, rejectDottedGuard,
    RealityGuardConflictError, guardModeCAS, guardRoleOnUpdate, assertGuardModeAllowed,
    saveGuardMode, withNewRealityGuard } = require('../models/realityGuardPolicy');
const HyUser = require('../models/hyUserModel');
const ServerGroup = require('../models/serverGroupModel');
const cryptoService = require('../services/cryptoService');
const logger = require('../utils/logger');
const { requireScope } = require('../middleware/auth');
const { invalidateNodesCache } = require('../utils/helpers');
const nodeSetup = require('../services/nodeSetup');
const syncService = require('../services/syncService');
const vless = require('../utils/vlessEncryption');
const { assertRebuildVlessEditAllowed } = require('../services/rebuildClientConfigOwnership');
const { checkVlessEncryption, hasEncryptionState, sanitizeEncryptionInput, settleVlessEncryption,
    vlessEditCAS, vlessEditConflict } = require('./panel/helpers');
const { redactNode } = vless;
const { isXrayBridge, setupXrayForRole } = require('../services/xrayNodeAutoSetup');
const { withNodeWrite, assertNodeEditAllowed, describeRoleError } = require('../services/rebuildRelayRoleGuard');

function sendNodeWriteConflict(res, error) {
    const conflict = describeRoleError(error, res.locals.t);
    if (!conflict) return false;
    const { status, message, ...details } = conflict;
    res.status(status).json({ error: message, ...details });
    return true;
}

function hasSshCredentials(node) {
    return !!(node?.ssh?.password || node?.ssh?.privateKey);
}

function runtimeErrorMessage(result, fallback) {
    return result?.error || result?.reason || fallback;
}

async function disableNodeRuntime(node) {
    if (node.type === 'virtual') {
        return { success: true, attempted: false, reason: 'virtual node' };
    }

    if (!hasSshCredentials(node)) {
        return { success: false, attempted: false, reason: 'SSH credentials not configured' };
    }

    try {
        return await nodeSetup.stopNodeRuntime(node);
    } catch (error) {
        return { success: false, attempted: true, error: error.message };
    }
}

async function startNodeRuntime(node) {
    if (node.type === 'virtual') {
        return { success: true, attempted: false, reason: 'virtual node' };
    }

    if (node.type === 'xray' && node.xray?.agentToken) {
        const synced = await syncService.updateNodeConfig(node);
        return synced
            ? { success: true, attempted: true, service: 'xray', via: 'agent-sync' }
            : { success: false, attempted: true, service: 'xray', via: 'agent-sync', error: 'Node startup could not be confirmed' };
    }

    if (!hasSshCredentials(node)) {
        return { success: false, attempted: false, reason: 'SSH credentials not configured' };
    }

    return nodeSetup.startNodeRuntime(node);
}

async function setNodeActive(req, res, active) {
    try {
        const reply = (status, body) => ({ status, body });
        const result = await withNodeWrite(req.params.id, async (options, current, verify) => {
            const node = current ?? await HyNode.findById(req.params.id);
            if (!node) {
                return reply(404, { error: 'Node not found' });
            }

            if (!active) {
                const runtime = await disableNodeRuntime(node);
                await verify();
                const disabledNode = await HyNode.findByIdAndUpdate(
                    req.params.id,
                    { $set: { active: false, status: 'offline', onlineUsers: 0 } },
                    { new: true, ...options }
                );

                await invalidateNodesCache();

                const warning = runtime.success === false
                    ? runtimeErrorMessage(runtime, 'Runtime stop failed')
                    : undefined;

                if (warning) {
                    logger.warn(`[Nodes API] Disabled node ${node.name}, runtime stop warning: ${warning}`);
                } else {
                    logger.info(`[Nodes API] Disabled node ${node.name}`);
                }

                return reply(200, {
                    success: true,
                    node: redactNode(disabledNode),
                    runtime,
                    ...(warning ? { warning } : {}),
                });
            }

            const encryptionError = checkVlessEncryption(node, node.xrayVersion);
            if (encryptionError) return reply(400, { error: encryptionError });
            let runtime;
            try {
                runtime = await startNodeRuntime(node);
            } catch (error) {
                if (describeRoleError(error, res.locals.t)) throw error;
                runtime = { success: false, attempted: true, error: error.message };
            }

            if (!runtime.success) {
                const errorMessage = runtimeErrorMessage(runtime, 'Node startup could not be confirmed');
                await verify();
                const failedNode = await HyNode.findByIdAndUpdate(
                    req.params.id,
                    {
                        $set: {
                            active: false,
                            status: 'offline',
                            onlineUsers: 0,
                            lastError: errorMessage,
                        },
                    },
                    { new: true, ...options }
                );

                await invalidateNodesCache();

                logger.warn(`[Nodes API] Enable node ${node.name} failed: ${errorMessage}`);
                return reply(500, {
                    error: errorMessage,
                    node: redactNode(failedNode),
                    runtime,
                });
            }

            await verify();
            // Agent-backed Sync already persisted its proof. An SSH start of
            // an agent-less Xray is not proof of its live API.
            const fields = node.type !== 'xray'
                ? { active: true, status: node.type === 'virtual' ? node.status : 'online', lastError: '' }
                : node.xray?.agentToken ? { active: true } : {
                    active: true, status: 'unknown', onlineUsers: 0, agentStatus: 'unknown',
                    lastError: 'Xray health unknown: no agent token configured', healthFailures: 0,
                };
            const enabledNode = await HyNode.findByIdAndUpdate(
                req.params.id,
                { $set: fields },
                { new: true, ...options }
            );

            await invalidateNodesCache();

            logger.info(`[Nodes API] Enabled node ${node.name}`);

            return reply(200, { success: true, node: redactNode(enabledNode), runtime });
        }, { requireRemoval: true });
        return result ? res.status(result.status).json(result.body) : res.status(404).json({ error: 'Node not found' });
    } catch (error) {
        if (sendNodeWriteConflict(res, error)) return;
        logger.error(`[Nodes API] ${active ? 'Enable' : 'Disable'} node error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
}

/**
 * GET /nodes - Список всех нод
 */
router.get('/', requireScope('nodes:read'), async (req, res) => {
    try {
        const { active, group, status } = req.query;
        
        const filter = {};
        if (active !== undefined) filter.active = active === 'true';
        if (group) filter.groups = group;
        if (status) filter.status = status;
        
        const nodes = await HyNode.find(filter)
            .populate('groups', 'name color')
            .sort({ name: 1 });
        
        res.json(nodes.map(redactNode));
    } catch (error) {
        logger.error(`[Nodes API] List error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /nodes/check-ip - Check which protocol nodes exist for a given IP address.
 * Used by the UI to show a sibling-node hint when adding a node.
 * Returns { nodes: [{ type, name, _id }] } — only safe fields, no credentials.
 */
router.get('/check-ip', requireScope('nodes:read'), async (req, res) => {
    try {
        const ip = (req.query.ip || '').trim();
        if (!ip) return res.json({ nodes: [] });
        const nodes = await HyNode.find({ ip }).select('type name _id').lean();
        res.json({ nodes });
    } catch (error) {
        logger.error(`[Nodes API] check-ip error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /nodes/:id - Получить ноду
 */
router.get('/:id', requireScope('nodes:read'), async (req, res) => {
    try {
        const node = await HyNode.findById(req.params.id).populate('groups', 'name color');
        
        if (!node) {
            return res.status(404).json({ error: 'Node not found' });
        }
        
        // Считаем пользователей на этой ноде
        const userCount = await HyUser.countDocuments({
            nodes: node._id,
            enabled: true
        });
        
        res.json({
            ...redactNode(node),
            userCount,
        });
    } catch (error) {
        logger.error(`[Nodes API] Get node error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /nodes/:id/enable - Включить ноду в подписках
 */
router.post('/:id/enable', requireScope('nodes:write'), (req, res) => setNodeActive(req, res, true));

/**
 * POST /nodes/:id/disable - Отключить ноду из подписок без остановки сервиса
 */
router.post('/:id/disable', requireScope('nodes:write'), (req, res) => setNodeActive(req, res, false));

/**
 * POST /nodes - Создать ноду
 */
router.post('/', requireScope('nodes:write'), async (req, res) => {
    try {
        rejectDottedGuard(req.body, 'xray.realityGuard');
        const {
            name, ip, domain, sni, port, portRange, statsPort,
            groups, ssh, paths, settings, rankingCoefficient,
            type, xray, virtual, cascadeRole, country, comment,
            hopInterval, acme, masquerade, bandwidth,
            ignoreClientBandwidth, speedTest, disableUDP,
            udpIdleTimeout, sniff, quic, resolver, acl,
            aclRules, useTlsFiles,
        } = req.body;
        
        if (!name) {
            return res.status(400).json({ error: 'name is required' });
        }

        if (type && !['hysteria', 'xray', 'virtual'].includes(type)) {
            return res.status(400).json({ error: 'type must be hysteria, xray, or virtual' });
        }

        const nodeType = type || 'hysteria';

        if (nodeType !== 'virtual' && !ip) {
            return res.status(400).json({ error: 'ip is required for hysteria and xray nodes' });
        }

        // Validate virtual-specific fields up-front (pre('validate') hook is
        // skipped on findOneAndUpdate but still runs on .save(); keeping the
        // explicit check here gives callers a clear 400 instead of a generic
        // ValidationError 500).
        if (nodeType === 'virtual') {
            const v = virtual || {};
            const selectMode = v.selectMode === 'group' ? 'group' : 'manual';
            if (selectMode === 'group' && !v.sourceGroup) {
                return res.status(400).json({ error: 'Virtual node (group): sourceGroup required' });
            }
            if (selectMode === 'manual' && (!Array.isArray(v.sources) || v.sources.length === 0)) {
                return res.status(400).json({ error: 'Virtual node (manual): at least one source required' });
            }
        }

        // Ensure no duplicate node for the same IP + protocol type
        // (skipped for virtual: it has no IP and the partial unique index excludes it).
        if (nodeType !== 'virtual') {
            const existing = await HyNode.findOne({ ip, type: nodeType });
            if (existing) {
                return res.status(409).json({ error: `A ${nodeType} node with this IP already exists` });
            }
        }

        const statsSecret = cryptoService.generateNodeSecret();

        // Resolve SSH: use caller-provided credentials, or inherit from sibling node on the same IP.
        // Virtual nodes never need SSH — emit empty (still encrypted) shell.
        let resolvedSsh;
        const rawSsh = ssh || {};
        if (nodeType === 'virtual') {
            resolvedSsh = cryptoService.encryptSshCredentials({});
        } else if (rawSsh.password || rawSsh.privateKey) {
            resolvedSsh = cryptoService.encryptSshCredentials(rawSsh);
        } else {
            const sibling = await HyNode.findOne({ ip, type: { $ne: nodeType } }).select('ssh').lean();
            resolvedSsh = sibling?.ssh || cryptoService.encryptSshCredentials({});
        }

        const nodeData = {
            name,
            ip: nodeType === 'virtual' ? null : ip,
            type: nodeType,
            domain: domain || '',
            sni: sni || '',
            port: port || 443,
            portRange: portRange || '20000-50000',
            statsPort: statsPort || 9999,
            statsSecret,
            groups: groups || [],
            ssh: resolvedSsh,
            paths: paths || {},
            settings: settings || {},
            rankingCoefficient: rankingCoefficient || 1.0,
            cascadeRole: nodeType === 'virtual' ? 'standalone' : (cascadeRole || 'standalone'),
            country: country || '',
            comment: typeof comment === 'string' ? comment.trim().slice(0, 500) : '',
            initScript: req.body.initScript || '',
            active: true,
            status: 'offline',
        };

        if (nodeType === 'xray' && xray) {
            const invalid = sanitizeEncryptionInput(xray, res.locals.t);
            if (invalid) return res.status(400).json({ error: invalid });
            const encryptionError = await settleVlessEncryption(xray, null, nodeData, undefined,
                vless.takeRegenerateIds(xray), res.locals.t);
            if (encryptionError) return res.status(400).json({ error: encryptionError });
            nodeData.xray = xray;
        }

        if (nodeType === 'virtual') {
            const v = virtual || {};
            nodeData.virtual = {
                selectMode: v.selectMode === 'group' ? 'group' : 'manual',
                sources: Array.isArray(v.sources) ? v.sources : [],
                sourceGroup: v.sourceGroup || null,
                strategy: ['random', 'roundRobin', 'leastPing', 'leastLoad'].includes(v.strategy)
                    ? v.strategy
                    : 'leastLoad',
                fallbackToFirst: v.fallbackToFirst !== false,
                observatory: {
                    destination: (v.observatory?.destination || '').trim() || 'http://www.gstatic.com/generate_204',
                    connectivity: (v.observatory?.connectivity || '').trim(),
                    interval: (v.observatory?.interval || '').trim() || '1m',
                    timeout: (v.observatory?.timeout || '').trim() || '5s',
                    sampling: parseInt(v.observatory?.sampling, 10) || 3,
                },
            };
        }

        // Hysteria 2 advanced configuration fields
        const hy2Fields = { hopInterval, acme, masquerade, bandwidth, ignoreClientBandwidth, speedTest, disableUDP, udpIdleTimeout, sniff, quic, resolver, acl, aclRules, useTlsFiles };
        for (const [key, value] of Object.entries(hy2Fields)) {
            if (value !== undefined) nodeData[key] = value;
        }

        const node = new HyNode(withNewRealityGuard(nodeData, xray));
        await node.save();

        await invalidateNodesCache();

        logger.info(`[Nodes API] Created ${nodeType} node ${name} (${nodeType === 'virtual' ? 'virtual' : ip})`);

        res.status(201).json(redactNode(node));
    } catch (error) {
        if (error instanceof RealityGuardInputError) return res.status(400).json({ error: error.message });
        logger.error(`[Nodes API] Create node error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * PUT /nodes/:id - Обновить ноду
 */
router.put('/:id', requireScope('nodes:write'), async (req, res) => {
    try {
        rejectDottedGuard(req.body, 'xray.realityGuard');
        const allowedUpdates = [
            'name', 'domain', 'sni', 'port', 'portRange', 'statsPort',
            'groups', 'paths', 'settings', 'active', 'rankingCoefficient',
            'type', 'xray', 'virtual', 'cascadeRole', 'country', 'comment',
            'hopInterval', 'acme', 'masquerade', 'bandwidth',
            'ignoreClientBandwidth', 'speedTest', 'disableUDP',
            'udpIdleTimeout', 'sniff', 'quic', 'resolver', 'acl',
            'aclRules', 'useTlsFiles', 'initScript',
        ];

        const updates = {};
        for (const key of allowedUpdates) {
            if (req.body[key] !== undefined) {
                if (key === 'comment') {
                    updates[key] = typeof req.body[key] === 'string'
                        ? req.body[key].trim().slice(0, 500)
                        : '';
                } else {
                    updates[key] = req.body[key];
                }
            }
        }

        // A guard-only update is leaf-local. Other API Xray payloads retain
        // the existing replacement semantics, but cannot wipe guard state.
        let guardMode, encryptionOnly;
        const hasGuard = Object.hasOwn(updates.xray || {}, 'realityGuard');
        if (updates.xray !== undefined) {
            if (!updates.xray || typeof updates.xray !== 'object' || Array.isArray(updates.xray)) {
                return res.status(400).json({ error: 'xray must be an object' });
            }
            const { realityGuard, ...xray } = updates.xray;
            ({ mode: guardMode } = readXrayPolicy(updates.xray));
            const names = Object.keys(xray);
            encryptionOnly = names.length && names.every(key => key.split('.').some(part => part.startsWith('vlessEncryption')));
            const invalid = sanitizeEncryptionInput(xray, res.locals.t);
            if (invalid) return res.status(400).json({ error: invalid });
            if (realityGuard !== undefined && !Object.keys(xray).length) delete updates.xray;
            else updates.xray = xray;
        }

        // Patch individual fields on both nodes; a partial SSH object is not a replacement.
        const ssh = req.body.ssh;
        const sshUpdates = {};
        for (const key of ['port', 'username', 'password', 'privateKey']) {
            if (!ssh || !Object.hasOwn(ssh, key) || ssh[key] === undefined) continue;
            const value = ssh[key];
            const isSecret = key === 'password' || key === 'privateKey';
            sshUpdates[`ssh.${key}`] = isSecret && value ? cryptoService.encrypt(value) : value;
        }
        Object.assign(updates, sshUpdates);

        if (hasGuard && !Object.keys(updates).length) {
            const node = await saveGuardMode(req.params.id, guardMode);
            return node ? res.json(redactNode(node)) : res.status(404).json({ error: 'Node not found' });
        }
        // findByIdAndUpdate bypasses pre('validate') hooks, so enforce the
        // type-specific invariants against the resulting node explicitly.
        const result = await withNodeWrite(req.params.id, async (options, current, verify) => {
            const bindGuard = !!updates.xray || guardMode !== undefined;
            const profileEdit = updates.xray || ['type', 'cascadeRole', 'active'].some(key => Object.hasOwn(updates, key));
            const projection = profileEdit
                ? vless.EDIT_XRAY_SELECT
                : `type ip virtual${guardMode !== undefined ? ` ${PROFILE_FIELDS} ${MODE_PATH}` : ''}`;
            const existing = (bindGuard || profileEdit ? null : current) ?? await HyNode.findById(req.params.id).select(projection).lean();
            if (!existing) {
                return null;
            }
            const nextType = updates.type || existing.type;
            const nextVirtual = updates.virtual !== undefined ? updates.virtual : existing.virtual;
            const nextIp = updates.ip !== undefined ? updates.ip : existing.ip;

            if (nextType === 'virtual') {
                const v = nextVirtual || {};
                if (v.selectMode === 'group' && !v.sourceGroup) {
                    return { invalid: 'Virtual node (group): sourceGroup required' };
                }
                if (v.selectMode !== 'group' && (!Array.isArray(v.sources) || v.sources.length === 0)) {
                    return { invalid: 'Virtual node (manual): at least one source required' };
                }
                // Virtual nodes carry no IP — clear any leftover from a prior type.
                updates.ip = null;
            } else if (!nextIp) {
                return { invalid: `Node type ${nextType} requires ip` };
            }

            const profile = { ...existing, type: nextType, cascadeRole: updates.cascadeRole ?? existing.cascadeRole };
            const patch = updates.xray;
            const encryptionEdit = !!patch && (hasEncryptionState(patch) || hasEncryptionState(existing.xray));
            const bindEncryption = encryptionEdit || (profileEdit && hasEncryptionState(existing.xray));
            if (patch) {
                const ids = vless.takeRegenerateIds(patch);
                // Keep legacy replacement semantics. Encryption edits are partial
                // so adding/rotating a key does not reset the listener or TLS.
                const next = encryptionEdit ? { ...existing.xray, ...patch } : patch;
                if (Array.isArray(next.extraInbounds)) next.extraInbounds = next.extraInbounds.map(extra => ({ ...extra }));
                const encryptionError = await settleVlessEncryption(next, existing.xray, profile,
                    existing.type === 'xray' ? existing.xrayVersion : undefined, ids, res.locals.t);
                if (encryptionError) return { invalid: encryptionError };
                for (const key of ['manualKey', 'accessLogs']) {
                    if (!Object.hasOwn(next, key) && existing.xray?.[key] !== undefined) next[key] = existing.xray[key];
                }
                if (Object.hasOwn(next, 'accessLogs') && existing.xray?.accessLogs?.ingestTokenEncrypted) {
                    next.accessLogs = { ...next.accessLogs, ingestTokenEncrypted: existing.xray.accessLogs.ingestTokenEncrypted };
                }
                await assertRebuildVlessEditAllowed(current, existing.xray, next, profile);
                if ((encryptionOnly && !encryptionEdit) || (current && encryptionEdit && isDeepStrictEqual(existing.xray, next))) {
                    delete updates.xray;
                } else updates.xray = next;
            } else if (profileEdit && hasEncryptionState(existing.xray)) {
                await assertRebuildVlessEditAllowed(current, existing.xray, existing.xray, profile);
                const encryptionError = checkVlessEncryption(profile, existing.xrayVersion, res.locals.t);
                if (encryptionError && (updates.active !== false || nextType !== existing.type || updates.cascadeRole !== undefined)) {
                    return { invalid: encryptionError };
                }
            }
            if (existing.xrayVersion && nextType !== existing.type) updates.xrayVersion = '';
            if (guardMode !== undefined) {
                assertGuardModeAllowed(guardMode, { type: nextType, cascadeRole: guardRoleOnUpdate(existing.cascadeRole, updates.cascadeRole),
                    role: existing.role, useCustomConfig: existing.useCustomConfig, xray: updates.xray ?? existing.xray });
            }
            if (updates.xray) {
                const stored = existing.xray?.realityGuard;
                if (guardMode !== undefined) updates.xray.realityGuard = { ...stored, mode: guardMode };
                else if (stored !== undefined) updates.xray.realityGuard = stored;
            } else if (guardMode !== undefined) updates[MODE_PATH] = guardMode;

            await assertNodeEditAllowed(current, updates, sshUpdates);
            await verify();
            const predicates = { ...(bindGuard ? guardModeCAS(existing) : {}), ...(bindEncryption ? vlessEditCAS(existing) : {}) };
            if (!Object.keys(updates).length) {
                const node = await HyNode.findById(req.params.id).select('-ssh.password -ssh.privateKey').populate('groups', 'name color');
                return { node };
            }
            const write = bindGuard || bindEncryption
                ? HyNode.findOneAndUpdate({ _id: req.params.id, ...predicates }, { $set: updates }, { new: true, ...options })
                : HyNode.findByIdAndUpdate(req.params.id, { $set: updates }, { new: true, ...options });
            const node = await write.select('-ssh.password -ssh.privateKey').populate('groups', 'name color');
            if (bindEncryption && !node) return { staleEncryption: true };
            if (bindGuard && !node) return { stale: true };
            // SSH is host-local. Never propagate a move at either address.
            if (existing.ip && existing.ip === node?.ip && Object.keys(sshUpdates).length) {
                await verify();
                await HyNode.updateMany({ ip: existing.ip, _id: { $ne: node._id } }, { $set: sshUpdates }, options);
            }
            return { node };
        });
        if (result?.stale) throw new RealityGuardConflictError();
        if (result?.staleEncryption) return res.status(409).json({ error: vlessEditConflict(res.locals.t) });
        if (result?.invalid) return res.status(400).json({ error: result.invalid });
        const node = result?.node;
        if (!node) return res.status(404).json({ error: 'Node not found' });

        // Auto-push config to the node if any config-affecting field changed.
        const configUpdates = Object.fromEntries(Object.entries(updates).filter(([key]) => key !== MODE_PATH));
        if (Object.keys(configUpdates).length) {
            syncService.schedulePush(node._id, configUpdates);
        }

        // Инвалидируем кэш
        await invalidateNodesCache();
        
        logger.info(`[Nodes API] Updated node ${node.name}`);
        
        res.json(redactNode(node));
    } catch (error) {
        if (sendNodeWriteConflict(res, error)) return;
        // Casting and persistence errors can contain the submitted values.
        if (error instanceof RealityGuardConflictError) return res.status(409).json({ error: error.message });
        if (error instanceof RealityGuardInputError) return res.status(400).json({ error: error.message });
        logger.error('[Nodes API] Update node failed');
        res.status(500).json({ error: 'Failed to update node' });
    }
});

/**
 * DELETE /nodes/:id - Удалить ноду
 */
router.delete('/:id', requireScope('nodes:write'), async (req, res) => {
    try {
        const node = await withNodeWrite(req.params.id, async (options, _current, verify) => {
            const deleted = await HyNode.findByIdAndDelete(req.params.id, options);
            if (deleted) {
                await verify();
                await HyUser.updateMany({ nodes: deleted._id }, { $pull: { nodes: deleted._id } }, options);
            }
            return deleted;
        }, { bareDelete: true });
        if (!node) return res.status(404).json({ error: 'Node not found' });

        // Инвалидируем кэш
        await invalidateNodesCache();
        
        logger.info(`[Nodes API] Deleted node ${node.name}`);
        
        res.json({ success: true, message: 'Нода удалена' });
    } catch (error) {
        if (sendNodeWriteConflict(res, error)) return;
        logger.error(`[Nodes API] Delete error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /nodes/:id/status - Получить статус ноды
 */
router.get('/:id/status', requireScope('nodes:read'), async (req, res) => {
    try {
        const node = await HyNode.findById(req.params.id).select('name status lastError onlineUsers lastSync');
        
        if (!node) {
            return res.status(404).json({ error: 'Node not found' });
        }
        
        res.json({
            name: node.name,
            status: node.status,
            lastError: node.lastError,
            onlineUsers: node.onlineUsers,
            lastSync: node.lastSync,
        });
    } catch (error) {
        logger.error(`[Nodes API] Get status error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /nodes/:id/reset-status - Recheck Xray; legacy reset for other types
 */
router.post('/:id/reset-status', requireScope('nodes:write'), async (req, res) => {
    try {
        const current = await HyNode.findById(req.params.id);
        if (!current) return res.status(404).json({ error: 'Node not found' });
        if (current.type === 'xray') {
            if (!current.active) return res.status(409).json({ error: 'Xray node is disabled' });
            const health = await syncService.checkXrayAgentHealth(current, { requireProof: true });
            if (!health.online) return res.status(409).json({
                success: false, error: health.lastError || 'Xray health could not be saved', xray_status: health.xrayStatus,
                xray_verification: health.xrayStatus === 'unknown' ? 'unavailable' : 'available',
            });
            const node = await HyNode.findById(current._id).select('name status lastError healthFailures');
            return res.json({ success: true, message: 'Статус сброшен', node });
        }
        const node = await HyNode.findByIdAndUpdate(
            req.params.id,
            { $set: { status: 'online', lastError: '', healthFailures: 0 } },
            { new: true }
        );
        
        if (!node) {
            return res.status(404).json({ error: 'Node not found' });
        }
        
        await invalidateNodesCache();
        
        logger.info(`[Nodes API] Node ${node.name} status reset to online`);
        
        res.json({ success: true, message: 'Статус сброшен', node });
    } catch (error) {
        logger.error(`[Nodes API] Status reset error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /nodes/:id/agent-info - Fetch live info from CC Agent (version, users, uptime)
 */
router.get('/:id/agent-info', requireScope('nodes:read'), async (req, res) => {
    try {
        const node = await HyNode.findById(req.params.id);
        if (!node) return res.status(404).json({ error: 'Node not found' });
        if (node.type !== 'xray') return res.status(400).json({ error: 'Not an Xray node' });

        const health = await syncService.probeXrayHealth(node);
        res.set('Cache-Control', 'no-store');
        res.status(health.agentStatus === 'online' ? 200 : 502).json({
            ...health.info,
            agent_status: health.agentStatus,
            xray_status: health.xrayStatus,
            ...(health.lastError ? { xray_health_reason: health.lastError } : {}),
        });
    } catch (_) {
        res.status(502).json({ error: 'Agent info unavailable' });
    }
});

/**
 * POST /nodes/:id/sync - Force sync a single node
 */
router.post('/:id/sync', requireScope('nodes:write'), async (req, res) => {
    try {
        const node = await HyNode.findByIdAndUpdate(
            req.params.id,
            { $set: { status: 'syncing' } },
            { new: true }
        );
        
        if (!node) {
            return res.status(404).json({ error: 'Node not found' });
        }
        
        await invalidateNodesCache();
        
        const syncService = require('../services/syncService');
        syncService.updateNodeConfig(node).catch(err => {
            logger.error(`[Nodes API] Sync error for ${node.name}: ${err.message}`);
        });
        
        logger.info(`[Nodes API] Started sync for node ${node.name}`);
        
        res.json({ success: true, message: 'Синхронизация запущена' });
    } catch (error) {
        logger.error(`[Nodes API] Start sync error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /nodes/:id/users - Пользователи на ноде
 */
router.get('/:id/users', requireScope('nodes:read'), async (req, res) => {
    try {
        const node = await HyNode.findById(req.params.id);
        
        if (!node) {
            return res.status(404).json({ error: 'Node not found' });
        }
        
        const users = await HyUser.find({
            nodes: node._id,
            enabled: true
        }).select('userId username traffic');
        
        res.json(users);
    } catch (error) {
        logger.error(`[Nodes API] Get users error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /nodes/:id/groups - Добавить ноду в группы
 */
router.post('/:id/groups', requireScope('nodes:write'), async (req, res) => {
    try {
        const { groups } = req.body;
        
        if (!Array.isArray(groups)) {
            return res.status(400).json({ error: 'groups должен быть массивом' });
        }
        
        const node = await HyNode.findByIdAndUpdate(
            req.params.id,
            { $addToSet: { groups: { $each: groups } } },
            { new: true }
        ).populate('groups', 'name color');
        
        if (!node) {
            return res.status(404).json({ error: 'Node not found' });
        }
        
        // Инвалидируем кэш
        await invalidateNodesCache();
        
        logger.info(`[Nodes API] Added groups for node ${node.name}`);
        res.json(redactNode(node));
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * DELETE /nodes/:id/groups/:groupId - Удалить ноду из группы
 */
router.delete('/:id/groups/:groupId', requireScope('nodes:write'), async (req, res) => {
    try {
        const node = await HyNode.findByIdAndUpdate(
            req.params.id,
            { $pull: { groups: req.params.groupId } },
            { new: true }
        ).populate('groups', 'name color');
        
        if (!node) {
            return res.status(404).json({ error: 'Node not found' });
        }
        
        // Инвалидируем кэш
        await invalidateNodesCache();
        
        logger.info(`[Nodes API] Removed group ${req.params.groupId} from node ${node.name}`);
        res.json(redactNode(node));
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /nodes/:id/config - Получить текущий конфиг ноды
 */
router.get('/:id/config', requireScope('nodes:read'), async (req, res) => {
    try {
        const node = await HyNode.findById(req.params.id);
        
        if (!node) {
            return res.status(404).json({ error: 'Node not found' });
        }
        
        // Генерируем конфиг с HTTP авторизацией
        const configGenerator = require('../services/configGenerator');
        const config = require('../../config');
        
        const baseUrl = process.env.BASE_URL || `http://localhost:${config.PORT}`;
        const authUrl = `${baseUrl}/api/auth`;
        
        const configContent = configGenerator.generateNodeConfig(node, authUrl);
        
        res.type('text/yaml').send(configContent);
    } catch (error) {
        logger.error(`[Nodes API] Config generation error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /nodes/:id/setup-port-hopping - Настройка port hopping на ноде
 */
router.post('/:id/setup-port-hopping', requireScope('nodes:write'), async (req, res) => {
    try {
        const node = await HyNode.findById(req.params.id);
        
        if (!node) {
            return res.status(404).json({ error: 'Node not found' });
        }
        
        const syncService = require('../services/syncService');
        const success = await syncService.setupPortHopping(node);
        
        if (success) {
            res.json({ success: true, message: 'Port hopping настроен' });
        } else {
            res.status(500).json({ error: 'Не удалось настроить port hopping' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /nodes/:id/update-config - Обновить конфиг на ноде через SSH
 */
router.post('/:id/update-config', requireScope('nodes:write'), async (req, res) => {
    try {
        const node = await HyNode.findById(req.params.id);
        
        if (!node) {
            return res.status(404).json({ error: 'Node not found' });
        }
        
        const syncService = require('../services/syncService');
        const success = await syncService.updateNodeConfig(node);
        
        if (success) {
            res.json({ success: true, message: 'Конфиг обновлён' });
        } else {
            res.status(500).json({ error: 'Не удалось обновить конфиг' });
        }
    } catch (error) {
        if (sendNodeWriteConflict(res, error)) return;
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /nodes/:id/setup - Auto-setup node via SSH
 *
 * Installs Hysteria, generates certs, configures port hopping, opens firewall ports
 * and starts the service — same as the one-click setup in the web panel.
 *
 * This is a long-running operation (30s–2min). The response is returned only after
 * all steps complete. Set your HTTP client timeout accordingly (e.g. 3–5 minutes).
 *
 * Body (all optional, all default to true):
 *   installHysteria  {boolean}  Install/update Hysteria binary
 *   setupPortHopping {boolean}  Configure iptables NAT rules for port range
 *   restartService   {boolean}  Enable and restart hysteria-server systemd unit
 *
 * Returns:
 *   200 { success: true,  logs: string[] }
 *   500/502 { success: false, error: string, logs: string[] }
 */
router.post('/:id/setup', requireScope('nodes:write'), async (req, res) => {
    try {
        const reply = (status, body) => ({ status, body });
        const result = await withNodeWrite(req.params.id, async (options, current, verify) => {
            const node = current ?? await HyNode.findById(req.params.id);

            if (!node) {
                return reply(404, { error: 'Node not found' });
            }

            if (!node.ssh?.password && !node.ssh?.privateKey) {
                return reply(400, { error: 'SSH credentials not configured for this node' });
            }

            const {
                installHysteria  = true,
                setupPortHopping = true,
                restartService   = true,
            } = req.body || {};

            if (node.type === 'virtual') {
                return reply(400, { success: false, error: 'Virtual nodes have no remote server to set up' });
            }

            logger.info(`[Nodes API] Auto-setup started for ${node.name} (${node.ip}) via API`);

            const nodeSetup = require('../services/nodeSetup');

            let result;
            if (node.type === 'xray') {
                result = await setupXrayForRole(node, { restartService });
            } else {
                result = await nodeSetup.setupNode(node, {
                    installHysteria,
                    setupPortHopping,
                    restartService,
                });
            }

            if (result.success) {
                if (node.type === 'xray' && !isXrayBridge(node)) {
                    const completion = await syncService.finishXraySetup(node, result.logs, {
                        restartService, agentToken: result.agentToken, writeOptions: options, verify,
                    });
                    await invalidateNodesCache();
                    return reply(completion.success ? 200 : 502, completion);
                } else {
                    await verify();
                    await HyNode.findByIdAndUpdate(req.params.id, { $set: {
                        status: isXrayBridge(node) ? 'offline' : 'online',
                        lastSync: new Date(), lastError: '', healthFailures: 0,
                        ...(node.type !== 'xray' && { useTlsFiles: result.useTlsFiles }),
                    } }, options);
                }
                await invalidateNodesCache();
                logger.info(`[Nodes API] Auto-setup completed for ${node.name} (${node.type})`);
                return reply(200, { success: true, logs: result.logs });
            } else {
                await verify();
                await HyNode.findByIdAndUpdate(req.params.id, {
                    $set: { status: 'error', lastError: result.error, healthFailures: 0 },
                }, options);
                logger.warn(`[Nodes API] Auto-setup failed for ${node.name}: ${result.error}`);
                return reply(500, { success: false, error: result.error, logs: result.logs });
            }
        }, { fullSetup: true });
        return result ? res.status(result.status).json(result.body) : res.status(404).json({ error: 'Node not found' });
    } catch (error) {
        if (sendNodeWriteConflict(res, error)) return;
        logger.error(`[Nodes API] Setup error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
