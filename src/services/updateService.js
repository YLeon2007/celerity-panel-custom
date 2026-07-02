const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { execFile, spawn } = require('child_process');
const { promisify } = require('util');

const logger = require('../utils/logger');
const { version: packageVersion } = require('../../package.json');

const execFileAsync = promisify(execFile);

const DEFAULT_HOST_REPO_PATH = '/opt/hysteria-panel-host';
const DEFAULT_REMOTE = 'origin';
const DEFAULT_BRANCH = 'main';
const CHECK_CACHE_TTL_MS = 5 * 60 * 1000;

let lastStatus = null;
let lastStatusAt = 0;
let applyState = {
    running: false,
    startedAt: null,
    finishedAt: null,
    success: null,
    error: null,
    log: '',
    backupDir: null,
    rollbackPath: null,
};

function hostRepoPath() {
    return process.env.SELF_UPDATE_REPO_PATH || DEFAULT_HOST_REPO_PATH;
}

function remoteName() {
    return process.env.SELF_UPDATE_REMOTE || DEFAULT_REMOTE;
}

function branchName() {
    return process.env.SELF_UPDATE_BRANCH || process.env.GIT_BRANCH || DEFAULT_BRANCH;
}

function scriptPath() {
    return process.env.SELF_UPDATE_SCRIPT || path.join(hostRepoPath(), 'scripts', 'self-update.sh');
}

function trimOutput(value) {
    return String(value || '').trim();
}

function publicApplyState() {
    return {
        running: applyState.running,
        startedAt: applyState.startedAt,
        finishedAt: applyState.finishedAt,
        success: applyState.success,
        error: applyState.error,
        backupDir: applyState.backupDir,
        rollbackPath: applyState.rollbackPath,
        log: applyState.log.slice(-12000),
    };
}

async function pathExists(p) {
    try {
        await fsp.access(p);
        return true;
    } catch {
        return false;
    }
}

async function execGit(args, options = {}) {
    const { stdout } = await execFileAsync('git', args, {
        cwd: hostRepoPath(),
        timeout: options.timeout || 30000,
        maxBuffer: options.maxBuffer || 1024 * 1024,
        env: process.env,
    });
    return trimOutput(stdout);
}

async function getLocalInfo() {
    const repo = hostRepoPath();
    const available = await pathExists(path.join(repo, '.git'));
    if (!available) {
        return {
            repoPath: repo,
            available: false,
            currentVersion: packageVersion,
            currentSha: null,
            currentBranch: null,
            error: `Host git checkout is not mounted at ${repo}`,
        };
    }

    const [currentSha, currentBranch] = await Promise.all([
        execGit(['rev-parse', '--short=12', 'HEAD']).catch(() => null),
        execGit(['rev-parse', '--abbrev-ref', 'HEAD']).catch(() => null),
    ]);

    return {
        repoPath: repo,
        available: true,
        currentVersion: packageVersion,
        currentSha,
        currentBranch,
    };
}

async function readRemoteVersion(remoteRef) {
    try {
        const content = await execGit(['show', `${remoteRef}:package.json`], { timeout: 30000, maxBuffer: 512 * 1024 });
        return JSON.parse(content).version || null;
    } catch {
        return null;
    }
}

async function readChangelog(remoteRef) {
    const args = ['log', '--no-merges', '--date=short', '--pretty=format:%h|%ad|%s', `HEAD..${remoteRef}`];
    const raw = await execGit(args, { timeout: 30000, maxBuffer: 1024 * 1024 }).catch(() => '');
    return raw.split('\n').filter(Boolean).slice(0, 40).map((line) => {
        const [sha, date, ...subjectParts] = line.split('|');
        return { sha, date, subject: subjectParts.join('|') };
    });
}

async function computeStatus({ force = false } = {}) {
    if (!force && lastStatus && Date.now() - lastStatusAt < CHECK_CACHE_TTL_MS) {
        return { ...lastStatus, cached: true, apply: publicApplyState() };
    }

    const local = await getLocalInfo();
    if (!local.available) {
        lastStatus = {
            success: false,
            updateAvailable: false,
            ...local,
            remote: remoteName(),
            branch: branchName(),
            latestSha: null,
            latestVersion: null,
            behindBy: 0,
            changelog: [],
        };
        lastStatusAt = Date.now();
        return { ...lastStatus, cached: false, apply: publicApplyState() };
    }

    const remote = remoteName();
    const branch = branchName();
    const remoteRef = `${remote}/${branch}`;

    await execGit(['fetch', '--prune', remote, branch], { timeout: 60000, maxBuffer: 1024 * 1024 });

    const [latestSha, behindRaw, latestVersion, changelog] = await Promise.all([
        execGit(['rev-parse', '--short=12', remoteRef]).catch(() => null),
        execGit(['rev-list', '--count', `HEAD..${remoteRef}`]).catch(() => '0'),
        readRemoteVersion(remoteRef),
        readChangelog(remoteRef),
    ]);

    const behindBy = Number.parseInt(behindRaw, 10) || 0;
    lastStatus = {
        success: true,
        updateAvailable: behindBy > 0,
        ...local,
        remote,
        branch,
        latestSha,
        latestVersion,
        behindBy,
        changelog,
        checkedAt: new Date().toISOString(),
    };
    lastStatusAt = Date.now();
    return { ...lastStatus, cached: false, apply: publicApplyState() };
}

async function getStatus() {
    try {
        return await computeStatus({ force: false });
    } catch (error) {
        logger.warn(`[SelfUpdate] Status error: ${error.message}`);
        return {
            success: false,
            updateAvailable: false,
            currentVersion: packageVersion,
            repoPath: hostRepoPath(),
            remote: remoteName(),
            branch: branchName(),
            error: error.message,
            apply: publicApplyState(),
        };
    }
}

async function checkNow() {
    const status = await computeStatus({ force: true });
    return status;
}

function appendApplyLog(chunk) {
    applyState.log += chunk;
    if (applyState.log.length > 60000) {
        applyState.log = applyState.log.slice(-60000);
    }
}

async function applyUpdate() {
    if (applyState.running) {
        const err = new Error('Self-update is already running');
        err.code = 'UPDATE_RUNNING';
        throw err;
    }

    const status = await checkNow();
    if (!status.success) {
        throw new Error(status.error || 'Update status check failed');
    }
    if (!status.updateAvailable) {
        return { success: true, message: 'Already up to date', status, apply: publicApplyState() };
    }

    const updateScript = scriptPath();
    if (!await pathExists(updateScript)) {
        throw new Error(`Self-update script not found: ${updateScript}`);
    }

    applyState = {
        running: true,
        startedAt: new Date().toISOString(),
        finishedAt: null,
        success: null,
        error: null,
        log: '',
        backupDir: null,
        rollbackPath: null,
    };

    logger.warn(`[SelfUpdate] Starting apply via ${updateScript}`);

    const child = spawn('bash', [updateScript], {
        cwd: hostRepoPath(),
        env: {
            ...process.env,
            SELF_UPDATE_REPO_PATH: hostRepoPath(),
            SELF_UPDATE_REMOTE: remoteName(),
            SELF_UPDATE_BRANCH: branchName(),
        },
        stdio: ['ignore', 'pipe', 'pipe'],
    });

    child.stdout.on('data', (data) => appendApplyLog(data.toString()));
    child.stderr.on('data', (data) => appendApplyLog(data.toString()));

    child.on('close', (code) => {
        applyState.running = false;
        applyState.finishedAt = new Date().toISOString();
        applyState.success = code === 0;
        if (code !== 0) {
            applyState.error = `Self-update script exited with code ${code}`;
            logger.error(`[SelfUpdate] Apply failed: ${applyState.error}`);
        } else {
            lastStatus = null;
            lastStatusAt = 0;
            const backupMatch = applyState.log.match(/BACKUP_DIR=(.+)/);
            const rollbackMatch = applyState.log.match(/ROLLBACK_PATH=(.+)/);
            applyState.backupDir = backupMatch ? backupMatch[1].trim() : null;
            applyState.rollbackPath = rollbackMatch ? rollbackMatch[1].trim() : null;
            logger.warn('[SelfUpdate] Apply completed successfully');
        }
    });

    child.on('error', (error) => {
        applyState.running = false;
        applyState.finishedAt = new Date().toISOString();
        applyState.success = false;
        applyState.error = error.message;
        appendApplyLog(`\n[spawn-error] ${error.message}\n`);
        logger.error(`[SelfUpdate] Spawn error: ${error.message}`);
    });

    return { success: true, started: true, status, apply: publicApplyState() };
}

module.exports = {
    getStatus,
    checkNow,
    applyUpdate,
};
