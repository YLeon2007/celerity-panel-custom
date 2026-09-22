#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const MODULE_ID = 'relay-l2tp';
const MODULE_PATH = 'src/modules/relay-l2tp';
const STATE_PATH = 'data/modules/relay-l2tp/installer-state.json';
const ROLLBACK_PATH = 'data/modules/relay-l2tp/rollback-module';
const ACTIONS = new Set(['install', 'upgrade', 'remove', 'rollback']);

function fail(message) {
    throw new Error(message);
}

function readJson(filePath, label) {
    let value;
    try {
        value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (error) {
        fail(`Unable to read ${label}: ${error.message}`);
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        fail(`${label} must be a JSON object`);
    }
    return value;
}

function validateModuleManifest(manifest, label = 'module manifest') {
    if (manifest.id !== MODULE_ID) fail(`${label} has unexpected module id`);
    if (typeof manifest.version !== 'string' || manifest.version.trim() === '') {
        fail(`${label}.version must be a non-empty string`);
    }
    if (!Number.isInteger(manifest.moduleApiVersion) || manifest.moduleApiVersion < 1) {
        fail(`${label}.moduleApiVersion must be a positive integer`);
    }
    if (!Array.isArray(manifest.requiredCapabilities)
        || manifest.requiredCapabilities.some(value => typeof value !== 'string' || value.trim() === '')) {
        fail(`${label}.requiredCapabilities must be an array of non-empty strings`);
    }
    return manifest;
}

function validateArtifact(artifactRoot) {
    const releaseManifest = readJson(path.join(artifactRoot, 'release-manifest.json'), 'release manifest');
    if (releaseManifest.schemaVersion !== 2) fail('Unsupported release manifest schemaVersion');
    const releaseModule = validateModuleManifest(releaseManifest.module, 'release manifest module');
    const moduleManifest = validateModuleManifest(
        readJson(path.join(artifactRoot, 'module', 'manifest.json'), 'module manifest'),
    );

    for (const field of ['id', 'version', 'moduleApiVersion']) {
        if (releaseModule[field] !== moduleManifest[field]) {
            fail(`Release and module manifests disagree on ${field}`);
        }
    }
    const releaseCapabilities = [...releaseModule.requiredCapabilities].sort();
    const moduleCapabilities = [...moduleManifest.requiredCapabilities].sort();
    if (JSON.stringify(releaseCapabilities) !== JSON.stringify(moduleCapabilities)) {
        fail('Release and module manifests disagree on requiredCapabilities');
    }
    return moduleManifest;
}

function validateHostManifest(hostManifest, moduleManifest) {
    if (!Number.isInteger(hostManifest.moduleApiVersion) || hostManifest.moduleApiVersion < 1) {
        fail('Host manifest.moduleApiVersion must be a positive integer');
    }
    if (!Array.isArray(hostManifest.capabilities)
        || hostManifest.capabilities.some(value => typeof value !== 'string' || value.trim() === '')) {
        fail('Host manifest.capabilities must be an array of non-empty strings');
    }
    if (hostManifest.moduleApiVersion !== moduleManifest.moduleApiVersion) {
        fail(
            `Host module API version ${hostManifest.moduleApiVersion} does not support module API version ${moduleManifest.moduleApiVersion}`,
        );
    }

    const capabilities = new Set(hostManifest.capabilities);
    const missing = moduleManifest.requiredCapabilities.filter(value => !capabilities.has(value));
    if (missing.length > 0) fail(`Missing required capabilities: ${missing.join(', ')}`);
}

function assertSafeManagedPath(hostRoot, relativePath, expectedType) {
    let current = hostRoot;
    const segments = relativePath.split('/');
    for (let index = 0; index < segments.length; index += 1) {
        current = path.join(current, segments[index]);
        if (!fs.existsSync(current)) continue;
        const stat = fs.lstatSync(current);
        if (stat.isSymbolicLink()) fail(`Managed path must not contain symlinks: ${relativePath}`);
        if (index < segments.length - 1 && !stat.isDirectory()) {
            fail(`Managed path parent is not a directory: ${relativePath}`);
        }
        if (index === segments.length - 1 && expectedType === 'directory' && !stat.isDirectory()) {
            fail(`Managed path is not a directory: ${relativePath}`);
        }
        if (index === segments.length - 1 && expectedType === 'file' && !stat.isFile()) {
            fail(`Managed path is not a regular file: ${relativePath}`);
        }
    }
}

function copyTree(sourcePath, destinationPath) {
    const stat = fs.lstatSync(sourcePath);
    if (stat.isSymbolicLink()) fail(`Refusing to copy symlink: ${sourcePath}`);
    if (stat.isDirectory()) {
        fs.mkdirSync(destinationPath, { recursive: true, mode: stat.mode & 0o777 });
        for (const name of fs.readdirSync(sourcePath).sort()) {
            copyTree(path.join(sourcePath, name), path.join(destinationPath, name));
        }
        return;
    }
    if (!stat.isFile()) fail(`Refusing to copy non-regular file: ${sourcePath}`);
    fs.mkdirSync(path.dirname(destinationPath), { recursive: true });
    fs.copyFileSync(sourcePath, destinationPath);
    fs.chmodSync(destinationPath, stat.mode & 0o777);
}

function removePath(targetPath) {
    fs.rmSync(targetPath, { recursive: true, force: true });
}

function removeEmptyParents(startPath, stopPath) {
    let current = path.dirname(startPath);
    while (current !== stopPath && current.startsWith(`${stopPath}${path.sep}`)) {
        try {
            fs.rmdirSync(current);
        } catch (error) {
            if (error.code === 'ENOENT') {
                current = path.dirname(current);
                continue;
            }
            if (error.code === 'ENOTEMPTY') break;
            throw error;
        }
        current = path.dirname(current);
    }
}

function replacePath({ destination, prepared, snapshot, hostRoot }) {
    const existed = fs.existsSync(destination);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    if (existed) fs.renameSync(destination, snapshot);
    try {
        if (prepared) fs.renameSync(prepared, destination);
    } catch (error) {
        if (existed && fs.existsSync(snapshot)) fs.renameSync(snapshot, destination);
        removeEmptyParents(destination, hostRoot);
        throw error;
    }
    return { destination, snapshot, existed, hostRoot };
}

function undoReplacement(entry) {
    removePath(entry.destination);
    if (entry.existed && fs.existsSync(entry.snapshot)) {
        fs.mkdirSync(path.dirname(entry.destination), { recursive: true });
        fs.renameSync(entry.snapshot, entry.destination);
    }
    removeEmptyParents(entry.destination, entry.hostRoot);
}

function actionPlan(action) {
    const operations = [];
    if (action !== 'remove') operations.push({ type: 'replace', path: MODULE_PATH });
    else operations.push({ type: 'remove', path: MODULE_PATH });
    if (action !== 'install') operations.push({ type: 'replace', path: ROLLBACK_PATH });
    operations.push({ type: 'write', path: STATE_PATH });
    return operations;
}

function runInstaller({
    action,
    artifactRoot = __dirname,
    hostRoot,
    hostManifestPath,
    dryRun = false,
    faultInjector = () => {},
}) {
    if (!ACTIONS.has(action)) fail(`Unsupported installer action: ${action}`);
    if (typeof hostRoot !== 'string' || hostRoot.length === 0) fail('hostRoot is required');
    if (typeof hostManifestPath !== 'string' || hostManifestPath.length === 0) {
        fail('hostManifestPath is required');
    }

    const absoluteArtifactRoot = path.resolve(artifactRoot);
    const absoluteHostRoot = fs.realpathSync(path.resolve(hostRoot));
    if (!fs.statSync(absoluteHostRoot).isDirectory()) fail('Host root must be a directory');
    const moduleManifest = validateArtifact(absoluteArtifactRoot);
    const hostManifest = readJson(path.resolve(hostManifestPath), 'host manifest');
    validateHostManifest(hostManifest, moduleManifest);

    assertSafeManagedPath(absoluteHostRoot, MODULE_PATH, 'directory');
    assertSafeManagedPath(absoluteHostRoot, ROLLBACK_PATH, 'directory');
    assertSafeManagedPath(absoluteHostRoot, STATE_PATH, 'file');

    const moduleTarget = path.join(absoluteHostRoot, ...MODULE_PATH.split('/'));
    const rollbackTarget = path.join(absoluteHostRoot, ...ROLLBACK_PATH.split('/'));
    const stateTarget = path.join(absoluteHostRoot, ...STATE_PATH.split('/'));
    const moduleExists = fs.existsSync(moduleTarget);
    const rollbackExists = fs.existsSync(rollbackTarget);

    if (action === 'install' && moduleExists) fail('Module is already installed; use upgrade');
    if (action === 'upgrade' && !moduleExists) fail('Module is not installed; use install');
    if (action === 'remove' && !moduleExists) fail('Module is not installed');
    if (action === 'rollback' && !rollbackExists) fail('No rollback module is available');

    const currentManifest = moduleExists
        ? validateModuleManifest(readJson(path.join(moduleTarget, 'manifest.json'), 'installed module manifest'))
        : null;
    const rollbackManifest = rollbackExists
        ? validateModuleManifest(readJson(path.join(rollbackTarget, 'manifest.json'), 'rollback module manifest'))
        : null;
    const plannedManifest = action === 'remove'
        ? currentManifest
        : (action === 'rollback' ? rollbackManifest : moduleManifest);
    const summaryModule = { id: plannedManifest.id, version: plannedManifest.version };
    if (dryRun) {
        return {
            action,
            dryRun: true,
            module: summaryModule,
            operations: actionPlan(action),
        };
    }

    const transactionRoot = fs.mkdtempSync(path.join(absoluteHostRoot, '.relay-l2tp-txn-'));
    const applied = [];
    try {
        let preparedModule = null;
        let preparedRollback = null;
        if (action === 'install' || action === 'upgrade') {
            preparedModule = path.join(transactionRoot, 'next-module');
            copyTree(path.join(absoluteArtifactRoot, 'module'), preparedModule);
        } else if (action === 'rollback') {
            preparedModule = path.join(transactionRoot, 'next-module');
            copyTree(rollbackTarget, preparedModule);
        }
        if ((action === 'upgrade' || action === 'remove' || action === 'rollback') && moduleExists) {
            preparedRollback = path.join(transactionRoot, 'next-rollback');
            copyTree(moduleTarget, preparedRollback);
        }

        const activeManifest = preparedModule
            ? validateModuleManifest(readJson(path.join(preparedModule, 'manifest.json'), 'prepared module manifest'))
            : plannedManifest;
        const preparedState = path.join(transactionRoot, 'next-state.json');
        fs.writeFileSync(preparedState, `${JSON.stringify({
            schemaVersion: 1,
            module: { id: activeManifest.id, version: activeManifest.version },
            lastAction: action,
            rollbackAvailable: preparedRollback !== null,
        }, null, 2)}\n`, { mode: 0o600 });

        applied.push(replacePath({
            destination: moduleTarget,
            prepared: preparedModule,
            snapshot: path.join(transactionRoot, 'before-module'),
            hostRoot: absoluteHostRoot,
        }));
        faultInjector('module-applied');

        if (preparedRollback || rollbackExists) {
            applied.push(replacePath({
                destination: rollbackTarget,
                prepared: preparedRollback,
                snapshot: path.join(transactionRoot, 'before-rollback'),
                hostRoot: absoluteHostRoot,
            }));
        }
        faultInjector('rollback-applied');

        applied.push(replacePath({
            destination: stateTarget,
            prepared: preparedState,
            snapshot: path.join(transactionRoot, 'before-state'),
            hostRoot: absoluteHostRoot,
        }));
        faultInjector('state-applied');

        return {
            action,
            dryRun: false,
            changed: true,
            module: { id: activeManifest.id, version: activeManifest.version },
            rollbackAvailable: preparedRollback !== null,
        };
    } catch (error) {
        let rollbackError = null;
        for (const entry of applied.reverse()) {
            try {
                undoReplacement(entry);
            } catch (candidate) {
                rollbackError ||= candidate;
            }
        }
        if (rollbackError) {
            throw new Error(`Installer transaction failed (${error.message}); rollback failed (${rollbackError.message})`);
        }
        throw error;
    } finally {
        removePath(transactionRoot);
    }
}

function parseArguments(argv) {
    const [action, ...args] = argv;
    if (!ACTIONS.has(action)) {
        fail('Usage: install.js <install|upgrade|remove|rollback> --host-root PATH --host-manifest FILE [--dry-run]');
    }
    const values = { action, dryRun: false };
    for (let index = 0; index < args.length; index += 1) {
        const name = args[index];
        if (name === '--dry-run') {
            values.dryRun = true;
            continue;
        }
        if (!['--host-root', '--host-manifest'].includes(name) || args[index + 1] === undefined) {
            fail(`Invalid argument: ${name || ''}`);
        }
        values[name === '--host-root' ? 'hostRoot' : 'hostManifestPath'] = args[index + 1];
        index += 1;
    }
    if (!values.hostRoot || !values.hostManifestPath) {
        fail('Both --host-root and --host-manifest are required');
    }
    return values;
}

if (require.main === module) {
    try {
        process.stdout.write(`${JSON.stringify(runInstaller(parseArguments(process.argv.slice(2))))}\n`);
    } catch (error) {
        process.stderr.write(`Installer failed: ${error.message}\n`);
        process.exitCode = 1;
    }
}

module.exports = {
    runInstaller,
    validateHostManifest,
};
