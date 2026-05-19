/**
 * API для управления пользователями Hysteria + Xray
 */

const express = require('express');
const router = express.Router();
const HyUser = require('../models/hyUserModel');
const HyNode = require('../models/hyNodeModel');
const UserDevice = require('../models/userDeviceModel');
const ServerGroup = require('../models/serverGroupModel');
const cryptoService = require('../services/cryptoService');
const hwidDeviceService = require('../services/hwidDeviceService');
const logger = require('../utils/logger');
const { getNodesByGroups, invalidateUserCache, invalidateUsersBulkCache } = require('../utils/helpers');
const { requireScope } = require('../middleware/auth');
const webhook = require('../services/webhookService');

/**
 * Lazy-load syncService to avoid circular dependency
 */
function getSyncService() {
    return require('../services/syncService');
}

/**
 * Add user to all Xray nodes they belong to (fire-and-forget, non-blocking)
 */
function xrayAddUser(user) {
    getSyncService().addUserToAllXrayNodes(user).catch(err => {
        logger.error(`[Users API] Xray addUser error for ${user.userId}: ${err.message}`);
    });
}

/**
 * Remove user from all Xray nodes (fire-and-forget, non-blocking)
 */
function xrayRemoveUser(user) {
    getSyncService().removeUserFromAllXrayNodes(user).catch(err => {
        logger.error(`[Users API] Xray removeUser error for ${user.userId}: ${err.message}`);
    });
}

/**
 * GET /users - Список всех пользователей
 */
router.get('/', requireScope('users:read'), async (req, res) => {
    try {
        const { enabled, group, page = 1, limit = 50, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;
        
        const filter = {};
        if (enabled !== undefined) filter.enabled = enabled === 'true';
        if (group) filter.groups = group;
        
        // Определяем поле для сортировки
        let sortField = {};
        const order = sortOrder === 'asc' ? 1 : -1;
        
        switch (sortBy) {
            case 'traffic':
                // Для сортировки по трафику нужно использовать aggregation
                // так как трафик - это сумма tx + rx
                const pipeline = [
                    { $match: filter },
                    {
                        $addFields: {
                            totalTraffic: { $add: ['$traffic.tx', '$traffic.rx'] }
                        }
                    },
                    { $sort: { totalTraffic: order } },
                    { $skip: (page - 1) * limit },
                    { $limit: parseInt(limit) }
                ];
                
                const usersAggregated = await HyUser.aggregate(pipeline);
                
                // Populate вручную после aggregation
                const users = await HyUser.populate(usersAggregated, [
                    { path: 'nodes', select: 'name ip' },
                    { path: 'groups', select: 'name color' }
                ]);
                
                const total = await HyUser.countDocuments(filter);
                
                return res.json({
                    users,
                    pagination: {
                        page: parseInt(page),
                        limit: parseInt(limit),
                        total,
                        pages: Math.ceil(total / limit),
                    }
                });
            
            case 'userId':
                sortField = { userId: order };
                break;
            
            case 'username':
                sortField = { username: order };
                break;
            
            case 'enabled':
                sortField = { enabled: order };
                break;
            
            case 'createdAt':
            default:
                sortField = { createdAt: order };
                break;
        }
        
        const users = await HyUser.find(filter)
            .sort(sortField)
            .skip((page - 1) * limit)
            .limit(parseInt(limit))
            .populate('nodes', 'name ip')
            .populate('groups', 'name color maxDevices');
        
        const total = await HyUser.countDocuments(filter);
        
        res.json({
            users,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit),
            }
        });
    } catch (error) {
        logger.error(`[Users API] List error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /users/:userId/devices — HWID devices registered via subscription
 */
router.get('/:userId/devices', requireScope('users:read'), async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await HyUser.findOne({ userId }).select('userId').lean();
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        const devices = await hwidDeviceService.listDevices(userId);
        const full = await HyUser.findOne({ userId }).populate('groups', 'maxDevices').lean();
        const limit = hwidDeviceService.effectiveDeviceLimit(full);
        res.json({
            userId,
            count: devices.length,
            limit,
            devices,
        });
    } catch (error) {
        logger.error(`[Users API] List HWID devices: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * DELETE /users/:userId/devices/:hwid — remove one HWID device
 */
router.delete('/:userId/devices/:hwid', requireScope('users:write'), async (req, res) => {
    try {
        const { userId, hwid: hwidParam } = req.params;
        let hwid = hwidParam;
        try {
            hwid = decodeURIComponent(hwidParam);
        } catch (_e) { /* use raw */ }

        const user = await HyUser.findOne({ userId }).select('userId subscriptionToken').lean();
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        const result = await UserDevice.deleteOne({ userId, hwid });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Устройство не найдено' });
        }
        await hwidDeviceService.invalidateCountCache(userId);
        await invalidateUserCache(userId, user.subscriptionToken);
        webhook.clearDeviceLimitNotified(userId);
        res.json({ success: true });
    } catch (error) {
        logger.error(`[Users API] Delete HWID device: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * DELETE /users/:userId/devices — remove all HWID devices for user
 */
router.delete('/:userId/devices', requireScope('users:write'), async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await HyUser.findOne({ userId }).select('userId subscriptionToken').lean();
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        await UserDevice.deleteMany({ userId });
        await hwidDeviceService.invalidateCountCache(userId);
        await invalidateUserCache(userId, user.subscriptionToken);
        webhook.clearDeviceLimitNotified(userId);
        res.json({ success: true });
    } catch (error) {
        logger.error(`[Users API] Delete all HWID devices: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /users/:userId - Получить пользователя
 */
router.get('/:userId', requireScope('users:read'), async (req, res) => {
    try {
        const user = await HyUser.findOne({ userId: req.params.userId })
            .populate('nodes', 'name ip domain port portRange')
            .populate('groups', 'name color maxDevices');
        
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        res.json(user);
    } catch (error) {
        logger.error(`[Users API] Get user error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /users - Создать пользователя
 * Body: { userId, username?, groups?, enabled?, trafficLimit?, expireAt? }
 */
router.post('/', requireScope('users:write'), async (req, res) => {
    try {
        const { userId, username, groups, enabled, trafficLimit, expireAt } = req.body;
        
        if (!userId) {
            return res.status(400).json({ error: 'userId обязателен' });
        }
        
        // Проверяем существование
        const existing = await HyUser.findOne({ userId });
        if (existing) {
            return res.status(409).json({ error: 'Пользователь уже существует', user: existing });
        }
        
        // Генерируем пароль
        const password = cryptoService.generatePassword(userId);
        
        // Группы (массив ObjectId)
        const userGroups = groups || [];
        
        const user = new HyUser({
            userId,
            username: username || '',
            password,
            groups: userGroups,
            enabled: enabled !== undefined ? enabled : false,
            trafficLimit: trafficLimit || 0,
            expireAt: expireAt || null,
            nodes: [], // Ноды автоматически по группам
        });
        
        await user.save();

        await invalidateUserCache(userId, user.subscriptionToken);

        logger.info(`[Users API] Created user ${userId}, groups: ${userGroups.length}`);
        webhook.emit(webhook.EVENTS.USER_CREATED, { userId, username: username || '', groups: userGroups });

        // Add to Xray nodes if user is enabled
        if (user.enabled) xrayAddUser(user.toObject());

        res.status(201).json(user);
    } catch (error) {
        logger.error(`[Users API] Create user error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * PUT /users/:userId - Обновить пользователя
 */
router.put('/:userId', requireScope('users:write'), async (req, res) => {
    try {
        const { enabled, groups, trafficLimit, username, expireAt, maxDevices } = req.body;
        
        const user = await HyUser.findOne({ userId: req.params.userId });
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        const updates = {};
        
        if (enabled !== undefined) {
            updates.enabled = enabled;
        }
        
        if (username !== undefined) {
            updates.username = username;
        }
        
        if (trafficLimit !== undefined) {
            updates.trafficLimit = trafficLimit;
        }
        
        if (expireAt !== undefined) {
            updates.expireAt = expireAt;
        }
        
        if (groups !== undefined) {
            updates.groups = groups;
        }

        if (maxDevices !== undefined) {
            updates.maxDevices = maxDevices;
        }

        if (req.body.hwidMode !== undefined) {
            const hm = String(req.body.hwidMode);
            if (['inherit', 'off', 'strict'].includes(hm)) {
                updates.hwidMode = hm;
            }
        }
        if (req.body.hwidEnforceFrom !== undefined) {
            const raw = req.body.hwidEnforceFrom;
            if (raw === null || raw === '') {
                updates.hwidEnforceFrom = null;
            } else {
                const d = new Date(raw);
                updates.hwidEnforceFrom = Number.isNaN(d.getTime()) ? null : d;
            }
        }
        
        const updatedUser = await HyUser.findOneAndUpdate(
            { userId: req.params.userId },
            { $set: updates },
            { new: true }
        )
        .populate('nodes', 'name ip')
        .populate('groups', 'name color maxDevices');
        
        // Инвалидируем кэш
        await invalidateUserCache(req.params.userId, user.subscriptionToken);

        const limitTouched = updates.maxDevices !== undefined
            && updates.maxDevices !== user.maxDevices;
        const modeRelaxed = updates.hwidMode !== undefined
            && updates.hwidMode !== user.hwidMode
            && (updates.hwidMode === 'off' || updates.hwidMode === 'inherit');
        const enforceDelayed = Object.prototype.hasOwnProperty.call(updates, 'hwidEnforceFrom');
        if (limitTouched || modeRelaxed || enforceDelayed) {
            webhook.clearDeviceLimitNotified(req.params.userId);
        }

        logger.info(`[Users API] Updated user ${req.params.userId}`);

        webhook.emit(webhook.EVENTS.USER_UPDATED, { userId: req.params.userId, updates });
        
        res.json(updatedUser);
    } catch (error) {
        logger.error(`[Users API] Update error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * DELETE /users/:userId - Удалить пользователя
 */
router.delete('/:userId', requireScope('users:write'), async (req, res) => {
    try {
        const user = await HyUser.findOneAndDelete({ userId: req.params.userId });
        
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        await UserDevice.deleteMany({ userId: req.params.userId });

        // Remove from Xray nodes
        xrayRemoveUser(user.toObject());

        // Инвалидируем кэш
        await invalidateUserCache(req.params.userId, user.subscriptionToken);
        webhook.clearDeviceLimitNotified(req.params.userId);

        logger.info(`[Users API] Deleted user ${req.params.userId}`);
        webhook.emit(webhook.EVENTS.USER_DELETED, { userId: req.params.userId });
        
        res.json({ success: true, message: 'Пользователь удалён' });
    } catch (error) {
        logger.error(`[Users API] Delete error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /users/:userId/enable - Включить пользователя
 */
router.post('/:userId/enable', requireScope('users:write'), async (req, res) => {
    try {
        const user = await HyUser.findOneAndUpdate(
            { userId: req.params.userId },
            { $set: { enabled: true } },
            { new: true }
        );
        
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        // Add to Xray nodes (user just got enabled)
        xrayAddUser(user.toObject());

        // Инвалидируем кэш
        await invalidateUserCache(req.params.userId, user.subscriptionToken);
        
        logger.info(`[Users API] Enabled user ${req.params.userId}`);
        webhook.emit(webhook.EVENTS.USER_ENABLED, { userId: req.params.userId });
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /users/:userId/disable - Отключить пользователя
 */
router.post('/:userId/disable', requireScope('users:write'), async (req, res) => {
    try {
        const user = await HyUser.findOneAndUpdate(
            { userId: req.params.userId },
            { $set: { enabled: false } },
            { new: true }
        );
        
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        // Remove from Xray nodes (user is disabled)
        xrayRemoveUser(user.toObject());

        // Инвалидируем кэш
        await invalidateUserCache(req.params.userId, user.subscriptionToken);
        
        logger.info(`[Users API] Disabled user ${req.params.userId}`);
        webhook.emit(webhook.EVENTS.USER_DISABLED, { userId: req.params.userId });
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /users/:userId/groups - Добавить пользователя в группы
 * Body: { groups: ['groupId1', 'groupId2'] }
 */
router.post('/:userId/groups', requireScope('users:write'), async (req, res) => {
    try {
        const { groups } = req.body;
        
        if (!Array.isArray(groups)) {
            return res.status(400).json({ error: 'groups должен быть массивом' });
        }
        
        const user = await HyUser.findOneAndUpdate(
            { userId: req.params.userId },
            { $addToSet: { groups: { $each: groups } } },
            { new: true }
        ).populate('groups', 'name color');
        
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        // Инвалидируем кэш
        await invalidateUserCache(req.params.userId, user.subscriptionToken);
        
        logger.info(`[Users API] Added groups to user ${req.params.userId}`);
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * DELETE /users/:userId/groups/:groupId - Удалить пользователя из группы
 */
router.delete('/:userId/groups/:groupId', requireScope('users:write'), async (req, res) => {
    try {
        const user = await HyUser.findOneAndUpdate(
            { userId: req.params.userId },
            { $pull: { groups: req.params.groupId } },
            { new: true }
        ).populate('groups', 'name color');
        
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        // Инвалидируем кэш
        await invalidateUserCache(req.params.userId, user.subscriptionToken);
        
        logger.info(`[Users API] Removed group ${req.params.groupId} from user ${req.params.userId}`);
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /users/sync-from-main - Синхронизация с основной БД
 * Body: { users: [{ userId, username, enabled, groups }] }
 */
router.post('/sync-from-main', requireScope('users:write'), async (req, res) => {
    try {
        const { users } = req.body;
        
        if (!Array.isArray(users)) {
            return res.status(400).json({ error: 'users должен быть массивом' });
        }
        
        let created = 0, updated = 0, errors = 0;
        const changed = [];
        
        for (const userData of users) {
            try {
                const { userId, username, enabled, groups } = userData;
                
                if (!userId) continue;
                
                const existing = await HyUser.findOne({ userId });
                
                if (existing) {
                    // Обновляем
                    const updates = {};
                    if (enabled !== undefined && enabled !== existing.enabled) {
                        updates.enabled = enabled;
                    }
                    if (username) updates.username = username;
                    if (groups !== undefined) {
                        updates.groups = groups;
                    }
                    
                    if (Object.keys(updates).length > 0) {
                        await HyUser.updateOne({ userId }, { $set: updates });
                        changed.push({ userId, subscriptionToken: existing.subscriptionToken });
                        updated++;
                    }
                } else {
                    // Создаём нового
                    const password = cryptoService.generatePassword(userId);
                    
                    const createdUser = await HyUser.create({
                        userId,
                        username: username || '',
                        password,
                        groups: groups || [],
                        enabled: enabled || false,
                        nodes: [],
                    });
                    changed.push({ userId, subscriptionToken: createdUser.subscriptionToken });
                    created++;
                }
            } catch (err) {
                logger.error(`[Sync] Error for userId ${userData.userId}: ${err.message}`);
                errors++;
            }
        }
        
        if (changed.length > 0) {
            await invalidateUsersBulkCache(changed);
        }
        
        logger.info(`[Sync] Sync: created ${created}, updated ${updated}, errors ${errors}`);
        
        res.json({ created, updated, errors });
    } catch (error) {
        logger.error(`[Sync] Sync error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;