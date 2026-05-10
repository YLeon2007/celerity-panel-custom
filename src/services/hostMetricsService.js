// Single source of truth for host/process metrics. Owns the only CPU sampler.

const os = require('os');
const rpsCounter = require('../middleware/rpsCounter');

let _cpuPercent = 0;
let _prevCpuTimes = sampleCpuTimes();

// Accumulator for cron snapshot — avoids capturing the cron's own CPU spike.
let _cpuSum = 0;
let _cpuCount = 0;
let _cpuMax = 0;

function sampleCpuTimes() {
    const cpus = os.cpus();
    let idle = 0, total = 0;
    for (const cpu of cpus) {
        const t = cpu.times;
        idle += t.idle;
        total += t.user + t.nice + t.sys + t.idle + t.irq;
    }
    return { idle, total };
}

function updateCpuPercent() {
    const cur = sampleCpuTimes();
    if (_prevCpuTimes) {
        const dIdle = cur.idle - _prevCpuTimes.idle;
        const dTotal = cur.total - _prevCpuTimes.total;
        _cpuPercent = dTotal > 0 ? Math.min(Math.round((1 - dIdle / dTotal) * 100), 100) : 0;
        _cpuSum += _cpuPercent;
        _cpuCount++;
        if (_cpuPercent > _cpuMax) _cpuMax = _cpuPercent;
    }
    _prevCpuTimes = cur;
}

setInterval(updateCpuPercent, 2000).unref();

function buildBase() {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const pm = process.memoryUsage();
    const load = os.loadavg();
    const r = rpsCounter.getStats();

    return {
        load1: Number((load[0] || 0).toFixed(2)),
        memPct: totalMem > 0 ? Math.round((usedMem / totalMem) * 100) : 0,
        memUsed: usedMem,
        rss: pm.rss,
        heapUsed: pm.heapUsed,
        rps: r.rps,
        rpm: r.rpm,
    };
}

// Realtime snapshot (dashboard). Does not affect the accumulator.
function getSnapshot() {
    return { cpuPct: _cpuPercent, ...buildBase() };
}

// Snapshot for persistence — uses CPU averaged over the window since the last
// call, then resets the accumulator. Falls back to the instant value on cold
// start when no samples have been collected yet.
function consumeSnapshot() {
    const cpuAvg = _cpuCount > 0 ? Math.round(_cpuSum / _cpuCount) : _cpuPercent;
    _cpuSum = 0;
    _cpuCount = 0;
    _cpuMax = 0;
    return { cpuPct: cpuAvg, ...buildBase() };
}

function getCpuPercent() {
    return _cpuPercent;
}

module.exports = {
    getSnapshot,
    consumeSnapshot,
    getCpuPercent,
};
