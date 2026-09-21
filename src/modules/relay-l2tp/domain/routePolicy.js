'use strict';

function selectActivePath(paths = [], healthByPathKey = {}) {
    const eligiblePaths = paths.filter(path =>
        path
        && path.enabled === true
        && path.complete === true
        && healthByPathKey[path.key] === true
        && typeof path.priority === 'number'
        && Number.isFinite(path.priority)
    );

    if (eligiblePaths.length === 0) {
        return {
            decision: 'block',
            error: { code: 'NO_HEALTHY_PATH' },
        };
    }

    const pathsByPriority = new Map();
    for (const path of eligiblePaths) {
        const pathsAtPriority = pathsByPriority.get(path.priority) || [];
        pathsAtPriority.push(path);
        pathsByPriority.set(path.priority, pathsAtPriority);
    }

    const duplicate = [...pathsByPriority.entries()]
        .filter(([, pathsAtPriority]) => pathsAtPriority.length > 1)
        .sort(([leftPriority], [rightPriority]) => leftPriority - rightPriority)[0];

    if (duplicate) {
        const [priority, pathsAtPriority] = duplicate;
        return {
            decision: 'block',
            error: {
                code: 'DUPLICATE_PRIORITY',
                priority,
                pathKeys: pathsAtPriority.map(path => path.key).sort(),
            },
        };
    }

    const selectedPath = eligiblePaths.reduce((best, candidate) =>
        candidate.priority < best.priority ? candidate : best
    );

    return {
        decision: 'select',
        pathKey: selectedPath.key,
    };
}

module.exports = { selectActivePath };
