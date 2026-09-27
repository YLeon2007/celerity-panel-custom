'use strict';

const { createHash } = require('node:crypto');

const DEFAULT_MAX_SYNC_ATTEMPTS = 3;
const DEFAULT_MIN_RETRY_INTERVAL_MS = 30000;

const REASONS = Object.freeze({
    L2TP_PPP_NOT_INSTALLED: 'L2TP на релее не установлен; PPP-пользователи не готовы',
    L2TP_PPP_USER_REVISION_DRIFT: 'Желаемая и применённая ревизии PPP-пользователей расходятся; запущена синхронизация',
    L2TP_PPP_SYNC_RETRY_EXHAUSTED: 'Исчерпаны автоматические попытки синхронизации PPP-пользователей; требуется проверка релея',
    L2TP_PPP_SYNC_QUEUE_FAILED: 'Не удалось поставить синхронизацию PPP-пользователей в очередь',
    L2TP_PPP_CHAP_SECRETS_DRIFT: 'Фактические PPP-учётные записи на релее не совпадают с желаемыми; запущена синхронизация',
    L2TP_PPP_READBACK_FAILED: 'Не удалось проверить фактические PPP-учётные записи на релее',
    L2TP_PPP_READBACK_UNAVAILABLE: 'Проверка фактических PPP-учётных записей на релее недоступна; готовность не подтверждена',
    L2TP_PPP_READINESS_CHECK_FAILED: 'Не удалось проверить готовность PPP-пользователей',
});

function validateRelayNode(relayNode) {
    if (typeof relayNode !== 'string' || relayNode.length === 0 || /[\r\n\0]/.test(relayNode)) {
        throw new TypeError('L2TP PPP readiness requires a valid relay node id');
    }
    return relayNode;
}

function desiredUserSnapshot(users) {
    return users
        .map(user => ({
            login: user?.login,
            ip: user?.ip,
            enabled: user?.enabled === true,
            desiredRevision: user?.desiredRevision,
        }))
        .sort((left, right) => String(left.login).localeCompare(String(right.login)));
}

function desiredHashOf(users) {
    return createHash('sha256')
        .update(JSON.stringify(desiredUserSnapshot(users)))
        .digest('hex');
}

class L2tpPppUserReadinessService {
    constructor({
        loadRelayState,
        loadUsers,
        queueSync,
        readback,
        clock,
        maxSyncAttempts = DEFAULT_MAX_SYNC_ATTEMPTS,
        minRetryIntervalMs = DEFAULT_MIN_RETRY_INTERVAL_MS,
    } = {}) {
        if (typeof loadRelayState !== 'function') {
            throw new TypeError('L2TP PPP readiness requires loadRelayState');
        }
        if (typeof loadUsers !== 'function') {
            throw new TypeError('L2TP PPP readiness requires loadUsers');
        }
        if (typeof queueSync !== 'function') {
            throw new TypeError('L2TP PPP readiness requires queueSync');
        }
        if (readback !== undefined && typeof readback !== 'function') {
            throw new TypeError('L2TP PPP readiness readback must be a function');
        }
        if (!clock || typeof clock.now !== 'function') {
            throw new TypeError('L2TP PPP readiness requires a clock');
        }
        if (!Number.isSafeInteger(maxSyncAttempts) || maxSyncAttempts < 1) {
            throw new TypeError('L2TP PPP readiness requires a positive maxSyncAttempts');
        }
        if (!Number.isSafeInteger(minRetryIntervalMs) || minRetryIntervalMs < 0) {
            throw new TypeError('L2TP PPP readiness requires a non-negative minRetryIntervalMs');
        }
        this.loadRelayState = loadRelayState;
        this.loadUsers = loadUsers;
        this.queueSync = queueSync;
        this.readback = readback ?? null;
        this.clock = clock;
        this.maxSyncAttempts = maxSyncAttempts;
        this.minRetryIntervalMs = minRetryIntervalMs;
        // In-memory retry budget per drift episode (keyed by relay). Durable
        // retry is provided by the queued sync_users operations themselves;
        // this bound only prevents unbounded re-queueing while drift persists.
        this.episodes = new Map();
    }

    #episodeFor(relay, desiredHash) {
        const episode = this.episodes.get(relay);
        if (episode && episode.desiredHash === desiredHash) return episode;
        const fresh = { desiredHash, attempts: 0, lastAttemptAt: null };
        this.episodes.set(relay, fresh);
        return fresh;
    }

    #clearEpisode(relay) {
        this.episodes.delete(relay);
    }

    async #handleDrift({ relay, checkedAt, base, reasonCode, episode }) {
        const lastAttemptAt = episode.lastAttemptAt;
        const cooledDown = lastAttemptAt === null
            || checkedAt.getTime() - lastAttemptAt.getTime() >= this.minRetryIntervalMs;

        if (episode.attempts >= this.maxSyncAttempts) {
            return {
                ...base,
                ready: false,
                status: 'blocked',
                reason: {
                    code: 'L2TP_PPP_SYNC_RETRY_EXHAUSTED',
                    message: REASONS.L2TP_PPP_SYNC_RETRY_EXHAUSTED,
                },
                syncAttempts: episode.attempts,
            };
        }

        if (!cooledDown) {
            return {
                ...base,
                ready: false,
                status: 'reconciling',
                reason: { code: reasonCode, message: REASONS[reasonCode] },
                syncAttempts: episode.attempts,
            };
        }

        episode.attempts += 1;
        episode.lastAttemptAt = checkedAt;
        try {
            await this.queueSync({ relayNode: relay, reasonCode });
        } catch {
            return {
                ...base,
                ready: false,
                status: 'blocked',
                reason: {
                    code: 'L2TP_PPP_SYNC_QUEUE_FAILED',
                    message: REASONS.L2TP_PPP_SYNC_QUEUE_FAILED,
                },
                syncAttempts: episode.attempts,
            };
        }

        return {
            ...base,
            ready: false,
            status: 'reconciling',
            reason: { code: reasonCode, message: REASONS[reasonCode] },
            syncQueued: true,
            syncAttempts: episode.attempts,
        };
    }

    async assess({ relayNode } = {}) {
        const relay = validateRelayNode(relayNode);
        const checkedAt = this.clock.now();
        const base = {
            relayNode: relay,
            checkedAt,
            syncQueued: false,
        };
        const blocked = (code, extra = {}) => ({
            ...base,
            ready: false,
            status: 'blocked',
            reason: { code, message: REASONS[code] },
            ...extra,
        });

        let state;
        let users;
        try {
            state = await this.loadRelayState(relay);
            if (state && state.status === 'installed' && state.desiredState === 'installed') {
                users = await this.loadUsers(relay);
            }
        } catch {
            return blocked('L2TP_PPP_READINESS_CHECK_FAILED');
        }
        if (!state || state.status !== 'installed' || state.desiredState !== 'installed') {
            return blocked('L2TP_PPP_NOT_INSTALLED');
        }

        const userRows = Array.isArray(users) ? users : [];
        const desiredHash = desiredHashOf(userRows);
        const enabledUserCount = userRows.filter(user => user?.enabled === true).length;
        const expectedCredentialRevision = userRows.reduce(
            (max, user) => (Number.isSafeInteger(user?.desiredRevision)
                ? Math.max(max, user.desiredRevision)
                : max),
            0,
        );
        const snapshot = {
            ...base,
            desiredHash,
            userCount: userRows.length,
            enabledUserCount,
            credentialRevision: expectedCredentialRevision,
        };

        const revisionDrift = userRows.some(user => (
            user?.syncStatus !== 'synced'
            || !Number.isSafeInteger(user?.desiredRevision)
            || user.desiredRevision < 1
            || user.appliedRevision !== user.desiredRevision
        ));
        if (revisionDrift) {
            return this.#handleDrift({
                relay,
                checkedAt,
                base: snapshot,
                reasonCode: 'L2TP_PPP_USER_REVISION_DRIFT',
                episode: this.#episodeFor(relay, desiredHash),
            });
        }

        if (!this.readback) {
            return blocked('L2TP_PPP_READBACK_UNAVAILABLE', { ...snapshot, nodeVerified: false });
        }
        let actual;
        try {
            actual = await this.readback({ relayNode: relay });
        } catch {
            return blocked('L2TP_PPP_READBACK_FAILED', { ...snapshot, nodeVerified: false });
        }
        const readbackMatches = actual
            && actual.ok === true
            && actual.code === 'USERS_VERIFIED'
            && actual.credentialRevision === expectedCredentialRevision
            && actual.enabledUserCount === enabledUserCount
            && actual.managedUserCount === enabledUserCount;
        if (!readbackMatches) {
            return this.#handleDrift({
                relay,
                checkedAt,
                base: { ...snapshot, nodeVerified: false },
                reasonCode: 'L2TP_PPP_CHAP_SECRETS_DRIFT',
                episode: this.#episodeFor(relay, desiredHash),
            });
        }
        const nodeVerified = true;

        this.#clearEpisode(relay);
        return {
            ...snapshot,
            ready: true,
            status: 'ready',
            reason: null,
            syncAttempts: 0,
            nodeVerified,
        };
    }
}

module.exports = {
    DEFAULT_MAX_SYNC_ATTEMPTS,
    DEFAULT_MIN_RETRY_INTERVAL_MS,
    L2tpPppUserReadinessService,
    desiredHashOf,
};
