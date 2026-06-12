/**
 * HTTP Auth endpoint for Hysteria 2 nodes
 * Nodes send requests here on each client connection
 */

const express = require('express');
const router = express.Router();
const HyUser = require('../models/hyUserModel');
const cryptoService = require('../services/cryptoService');
const cache = require('../services/cacheService');
const { getSettings } = require('../utils/helpers');
const logger = require('../utils/logger');

/**
 * Extract IP from addr (IPv4 and IPv6 support)
 */
function extractIP(addr) {
    if (!addr) return '';
    
    // IPv6 with brackets: [2001:db8::1]:55239
    if (addr.startsWith('[')) {
        const endBracket = addr.indexOf(']');
        if (endBracket > 0) {
            return addr.substring(1, endBracket);
        }
    }
    
    // Find last colon
    const lastColon = addr.lastIndexOf(':');
    if (lastColon > 0) {
        // Check if part after : is port (digits only)
        const afterColon = addr.substring(lastColon + 1);
        if (/^\d+$/.test(afterColon)) {
            return addr.substring(0, lastColon);
        }
    }
    
    return addr;
}

/**
 * Check device limit by unique IPs
 */
async function checkDeviceLimit(userId, clientIP, maxDevices) {
    try {
        const settings = await getSettings();
        const gracePeriodMinutes = settings?.deviceGracePeriod ?? 15;
        const gracePeriodMs = gracePeriodMinutes * 60 * 1000;
        
        const deviceIPs = await cache.getDeviceIPs(userId);
        const now = Date.now();
        
        const activeIPs = new Set();
        for (const [ip, timestamp] of Object.entries(deviceIPs)) {
            if (now - parseInt(timestamp) < gracePeriodMs) {
                activeIPs.add(ip);
            }
        }
        
        activeIPs.add(clientIP);
        const activeCount = activeIPs.size;
        
        if (activeCount > maxDevices) {
            return { allowed: false, activeCount };
        }
        
        await cache.updateDeviceIP(userId, clientIP);
        
        // Periodically clean old IPs (not on every request)
        if (Math.random() < 0.1) {
            await cache.cleanupOldDeviceIPs(userId, gracePeriodMs);
        }
        
        return { allowed: true, activeCount };
    } catch (err) {
        logger.error(`[Auth] Device check error: ${err.message}`);
        // On error - allow (fail open)
        return { allowed: true, activeCount: 0 };
    }
}

/**
 * Get user with caching
 */
async function getUserWithCache(userId) {
    const cached = await cache.getUser(userId);
    if (cached) {
        return cached;
    }
    
    const user = await HyUser.findOne({ userId }).populate('groups', 'maxDevices').lean();
    
    if (user) {
        await cache.setUser(userId, user);
    }
    
    return user;
}

function parseHysteriaAuthPayload(auth) {
    if (typeof auth !== 'string') return null;

    const colonIdx = auth.indexOf(':');
    if (colonIdx === -1) return null;

    const userId = auth.substring(0, colonIdx);
    const password = auth.substring(colonIdx + 1);
    if (!userId || !password) return null;

    return { userId, password };
}

/**
 * POST /auth - User authorization check
 * 
 * Hysteria sends: { "addr": "IP:port", "auth": "userId:password", "tx": bandwidth }
 * Response: { "ok": true, "id": "userId" } or { "ok": false }
 */
router.post('/', async (req, res) => {
    try {
        const { addr, auth, tx } = req.body;

        const parsedAuth = parseHysteriaAuthPayload(auth);
        if (!parsedAuth) {
            logger.warn(`[Auth] Invalid auth payload from ${addr}`);
            return res.json({ ok: false });
        }

        const { userId, password } = parsedAuth;
        
        const user = await getUserWithCache(userId);
        
        if (!user) {
            logger.warn(`[Auth] User not found: ${userId} (${addr})`);
            return res.json({ ok: false });
        }
        
        if (!user.enabled) {
            logger.warn(`[Auth] Subscription inactive: ${userId} (${addr})`);
            return res.json({ ok: false });
        }
        
        const expectedPassword = cryptoService.generatePassword(userId);
        if (password !== expectedPassword) {
            // Cached user may not have password field (stripped for security).
            // Fall back to DB lookup before rejecting.
            let dbPassword = user.password;
            if (dbPassword === undefined || dbPassword === null) {
                const dbUser = await HyUser.findOne({ userId }, 'password').lean();
                dbPassword = dbUser?.password;
            }
            if (password !== dbPassword) {
                logger.warn(`[Auth] Invalid password: ${userId} (${addr})`);
                return res.json({ ok: false });
            }
        }
        
        if (user.trafficLimit > 0) {
            const usedTraffic = (user.traffic?.tx || 0) + (user.traffic?.rx || 0);
            if (usedTraffic >= user.trafficLimit) {
                logger.warn(`[Auth] Traffic limit exceeded: ${userId} (${addr})`);
                return res.json({ ok: false });
            }
        }
        
        if (user.expireAt && new Date(user.expireAt) < new Date()) {
            logger.warn(`[Auth] Subscription expired: ${userId} (${addr})`);
            return res.json({ ok: false });
        }
        
        let maxDevices = user.maxDevices;
        
        // If user has 0 - use minimum from groups
        if (maxDevices === 0 && user.groups?.length > 0) {
            const groupLimits = user.groups
                .filter(g => g.maxDevices > 0)
                .map(g => g.maxDevices);
            
            if (groupLimits.length > 0) {
                maxDevices = Math.min(...groupLimits);
            }
        }
        
        // -1 = unlimited, 0 = no limit (no settings)
        if (maxDevices > 0) {
            const clientIP = extractIP(addr);
            
            const { allowed, activeCount } = await checkDeviceLimit(userId, clientIP, maxDevices);
            
            if (!allowed) {
                logger.warn(`[Auth] Device limit exceeded (${activeCount}/${maxDevices} IP): ${userId} (${addr})`);
                return res.json({ ok: false });
            }
        }
        
        logger.debug(`[Auth] Authorized: ${userId} (${addr})`);
        
        return res.json({ ok: true, id: userId });
        
    } catch (error) {
        logger.error(`[Auth] Error: ${error.message}`);
        return res.json({ ok: false });
    }
});

module.exports = router;
