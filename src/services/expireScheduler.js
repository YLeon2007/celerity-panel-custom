/**
 * Expire scheduler — reliable next-fire-time scheduler for subscription expiry.
 *
 * Three layers of reliability:
 *   1. In-process setTimeout on the nearest upcoming expireAt (hot path, 0 ms latency).
 *   2. Boot catchup in init() — flips any users who expired while the panel was down.
 *      Also performs a one-shot traffic-limit sweep to absorb dirty state from
 *      before this fix shipped.
 *   3. Watchdog: processExpired() is also called from the existing 5-min cron
 *      as a safety net in case a timer was dropped by an unexpected fault.
 *
 * Source of truth: user.expireAt in Mongo. The scheduler holds no critical
 * state — losing the timer only delays a flip until the next watchdog tick.
 *
 * Atomicity is enforced inside syncService.disableUser via a compare-and-set
 * updateOne, so concurrent ticks/catchups/instances cannot double-fire.
 */

const HyUser = require('../models/hyUserModel');
const logger = require('../utils/logger');

// Node setTimeout uses int32 internally (~24.8 days). For expireAt further out
// we set a max-length timer that simply re-runs scheduleNext on fire.
const MAX_TIMEOUT_MS = 2147483647;

let _timer = null;
let _nextAt = null;
let _initialized = false;

// Single-flight guard for scheduleNext / processExpired. Module-level mutable
// state (_timer, _nextAt) is touched only from inside these guards, so the
// chain "concurrent notify + watchdog + timer-fire" can never leave orphan
// timers or stale _nextAt.
let _scheduling = null;
let _processing = null;

// Lazy require to avoid circular dependency with syncService at module load.
function getSync() {
    return require('./syncService');
}

/**
 * Find every user whose subscription has expired and they are still enabled,
 * then atomically disable each. Returns the number actually processed.
 * Concurrent callers share the same in-flight run.
 */
function processExpired() {
    if (_processing) return _processing;
    _processing = (async () => {
        try {
            const overdue = await HyUser.find(
                { enabled: true, expireAt: { $ne: null, $lte: new Date() } },
                { userId: 1, subscriptionToken: 1, xrayUuid: 1, expireAt: 1 }
            ).lean();

            if (overdue.length === 0) return 0;

            const sync = getSync();
            const results = await Promise.allSettled(overdue.map(u => sync.disableUser(u, 'expired')));
            const disabled = results.filter(r => r.status === 'fulfilled' && r.value === true).length;
            const failed = results.filter(r => r.status === 'rejected').length;
            if (failed) logger.warn(`[ExpireScheduler] Failed to process ${failed} expired user(s)`);
            logger.info(`[ExpireScheduler] Disabled ${disabled} expired user(s) in DB`);
            return disabled;
        } finally {
            _processing = null;
        }
    })();
    return _processing;
}

/**
 * Cancel the current timer and arm a new one on the nearest upcoming expireAt.
 * No-op if no future expiry exists. Serialized: concurrent callers await the
 * same run, guaranteeing exactly one active timer.
 */
function scheduleNext() {
    if (_scheduling) return _scheduling;
    _scheduling = (async () => {
        try {
            if (_timer) {
                clearTimeout(_timer);
                _timer = null;
                _nextAt = null;
            }

            const next = await HyUser.findOne(
                { enabled: true, expireAt: { $ne: null, $gt: new Date() } },
                { expireAt: 1 }
            ).sort({ expireAt: 1 }).lean();

            if (!next) {
                logger.debug('[ExpireScheduler] No upcoming expiry — idle');
                return;
            }

            _nextAt = new Date(next.expireAt);
            const delay = Math.max(0, Math.min(_nextAt.getTime() - Date.now(), MAX_TIMEOUT_MS));

            _timer = setTimeout(async () => {
                try {
                    await processExpired();
                } catch (err) {
                    logger.error(`[ExpireScheduler] Timer fire error: ${err.message}`);
                }
                scheduleNext().catch(err =>
                    logger.error(`[ExpireScheduler] Reschedule error: ${err.message}`)
                );
            }, delay);

            // Don't keep the process alive for this timer alone.
            if (typeof _timer.unref === 'function') _timer.unref();

            logger.debug(`[ExpireScheduler] Next fire at ${_nextAt.toISOString()} (in ${Math.round(delay / 1000)}s)`);
        } finally {
            _scheduling = null;
        }
    })();
    return _scheduling;
}

/**
 * Notify the scheduler that a user's expireAt was set/changed.
 * Triggers a reschedule only when the new time is earlier than the current
 * target (or no target exists). If the time is already in the past, fires
 * processExpired immediately. Cheap and safe to call from any save hook.
 */
function notify(expireAt) {
    if (!_initialized) return;
    if (!expireAt) return;

    const t = expireAt instanceof Date ? expireAt : new Date(expireAt);
    if (Number.isNaN(t.getTime())) return;

    if (t.getTime() <= Date.now()) {
        // Already past — sweep now, then re-arm. Serialized via processExpired
        // and scheduleNext mutexes, so racing notifies coalesce.
        (async () => {
            try {
                await processExpired();
            } catch (err) {
                logger.error(`[ExpireScheduler] notify processExpired error: ${err.message}`);
            }
            try {
                await scheduleNext();
            } catch (err) {
                logger.error(`[ExpireScheduler] notify reschedule error: ${err.message}`);
            }
        })();
        return;
    }

    if (!_nextAt || t.getTime() < _nextAt.getTime()) {
        scheduleNext().catch(err =>
            logger.error(`[ExpireScheduler] notify reschedule error: ${err.message}`)
        );
    }
}

/**
 * Boot catchup + initial schedule. Idempotent.
 *
 * Expiry catchup and the next-fire scheduling are awaited because they
 * directly affect correctness of the first HTTP responses. DB disablement
 * does not attest Xray runtime removal (the classic agent may be unavailable).
 *
 * The traffic-limit migration sweep is dispatched in the background — it can
 * be large on existing installs and would otherwise delay server startup by
 * minutes. The regular stats cron picks up the same set within ~5 min anyway,
 * so the worst case is a single late-by-five-minutes flip on first boot.
 */
async function init() {
    if (_initialized) return;
    _initialized = true;

    try {
        const expiredCount = await processExpired();
        await scheduleNext();
        logger.info(`[ExpireScheduler] Initialized (expired catchup: ${expiredCount})`);
    } catch (err) {
        logger.error(`[ExpireScheduler] init error: ${err.message}`);
    }

    // Background traffic migration sweep — non-blocking.
    (async () => {
        try {
            const candidates = await HyUser.find(
                { enabled: true, trafficLimit: { $gt: 0 } },
                { userId: 1 }
            ).lean();
            if (candidates.length === 0) return;
            await getSync().enforceTrafficLimit(candidates.map(u => u.userId));
            logger.info(`[ExpireScheduler] Boot traffic sweep done (${candidates.length} checked)`);
        } catch (err) {
            logger.error(`[ExpireScheduler] Boot traffic sweep error: ${err.message}`);
        }
    })();
}

module.exports = {
    init,
    scheduleNext,
    processExpired,
    notify,
};
