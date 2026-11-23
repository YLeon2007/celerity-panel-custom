'use strict';

const ranges = Object.freeze({ preflight: [0, 0], reserve: [10, 10], preparePackages: [20, 49],
    prepare: [50, 50], install: [65, 65], restart: [80, 80], verify: [92, 92], unknown: [10, 92],
    installed: [100, 100] });
const validPercent = (stage, percent) => typeof stage === 'string' && Object.hasOwn(ranges, stage) && Number.isInteger(percent)
    && percent >= ranges[stage][0] && percent <= ranges[stage][1];
function publicProgress(row) {
    const p = row?.installProgress;
    if (!p || Object.getPrototypeOf(p) !== Object.prototype || Object.keys(p).length !== 3
        || !['stage', 'percent', 'at'].every(k => Object.hasOwn(p, k)) || typeof p.stage !== 'string'
        || !validPercent(p.stage, p.percent) || !(p.at instanceof Date) || !Number.isFinite(p.at.getTime())) return null;
    // A stale/forged presentation field cannot announce completion.
    if ((p.stage === 'installed' ? row.status !== 'installed' : row.status !== 'installing') || p.stage === 'preflight') return null;
    return { stage: p.stage, percent: p.percent, at: p.at.toISOString() };
}

module.exports = { stages: Object.freeze(Object.keys(ranges).filter(stage => stage !== 'preflight')), validPercent, publicProgress };
