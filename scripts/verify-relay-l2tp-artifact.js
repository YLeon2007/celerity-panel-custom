#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const NODE_ARTIFACT_ROOT = 'module/node-artifacts/l2tp';
const REQUIRED_NODE_EXECUTABLE_PATHS = Object.freeze([
    'activate-xray.sh',
    'apply-firewall-policy.sh',
    'apply.sh',
    'backup.sh',
    'commit.sh',
    'compose-xray-fragment.sh',
    'install-runtime.sh',
    'install.sh',
    'preflight.sh',
    'receive-artifact.py',
    'rollback.sh',
    'runner.sh',
    'start-l2tp.sh',
    'sync-users.sh',
    'validate-nft.sh',
    'validate-xray.sh',
    'verify.sh',
].map(name => `${NODE_ARTIFACT_ROOT}/${name}`).sort((left, right) => left.localeCompare(right, 'en')));
const REQUIRED_CONTENTS = Object.freeze({
    migrationRegistry: 'module/migrations/index.js',
    panel: Object.freeze({
        views: Object.freeze(['module/views/l2tp.ejs']),
        routes: Object.freeze(['module/routes/panel.js', 'module/routes/panelOverview.js']),
    }),
    tools: Object.freeze({
        installer: 'install.js',
        nodeInstaller: `${NODE_ARTIFACT_ROOT}/install.sh`,
        rollback: `${NODE_ARTIFACT_ROOT}/rollback.sh`,
        topologySchema: 'topology.schema.json',
        topologyTransfer: 'topology-transfer.js',
    }),
});

function fail(message) {
    throw new Error(message);
}

function runTar(args) {
    const result = spawnSync('tar', args, {
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
    });
    if (result.status !== 0) fail(`tar failed: ${result.stderr.trim()}`);
    return result.stdout;
}

function sha256File(filePath) {
    return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function validateArchiveMemberPath(memberPath) {
    if (typeof memberPath !== 'string' || memberPath.length === 0) {
        fail('Archive member path must be a non-empty string');
    }
    if (memberPath.includes('\0')
        || memberPath.includes('\\')
        || path.posix.isAbsolute(memberPath)
        || /^[A-Za-z]:/.test(memberPath)) {
        fail(`Unsafe archive member path: ${JSON.stringify(memberPath)}`);
    }

    const normalized = memberPath.endsWith('/') ? memberPath.slice(0, -1) : memberPath;
    const segments = normalized.split('/');
    if (segments.some(segment => segment === '' || segment === '.' || segment === '..')) {
        fail(`Unsafe archive member path: ${JSON.stringify(memberPath)}`);
    }
    if (path.posix.normalize(normalized) !== normalized) {
        fail(`Unsafe archive member path: ${JSON.stringify(memberPath)}`);
    }
    return normalized;
}

function parseChecksum(checksumPath, archivePath) {
    const checksumText = fs.readFileSync(checksumPath, 'utf8');
    const match = /^([a-f0-9]{64})  ([^\r\n]+)\n?$/.exec(checksumText);
    if (!match) fail('Invalid SHA-256 checksum manifest format');
    if (match[2] !== path.basename(archivePath)) fail('Checksum manifest names a different archive');
    return match[1];
}

function assertManifestShape(manifest) {
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
        fail('Release manifest must be an object');
    }
    if (manifest.schemaVersion !== 2) fail('Unsupported release manifest schemaVersion');
    if (manifest.module?.id !== 'relay-l2tp') fail('Unexpected module id');
    if (typeof manifest.module.version !== 'string' || manifest.module.version.length === 0) {
        fail('Invalid module version');
    }
    if (manifest.module.moduleApiVersion !== 1) fail('Unsupported module API version');
    if (!Array.isArray(manifest.module.requiredCapabilities)
        || manifest.module.requiredCapabilities.some(value => typeof value !== 'string' || !value)) {
        fail('Invalid required capabilities');
    }
    if (!manifest.source || typeof manifest.source !== 'object' || Array.isArray(manifest.source)) {
        fail('Source identity is required');
    }
    if (!/^[a-f0-9]{40}$/.test(manifest.source.commit)) fail('Invalid source commit hash');
    if (!/^[a-f0-9]{40}$/.test(manifest.source.tree)) fail('Invalid source tree hash');
    if (JSON.stringify(manifest.contents) !== JSON.stringify(REQUIRED_CONTENTS)) {
        fail('Release content contract does not match the relay-l2tp package');
    }
    if (manifest.nodeArtifacts?.root !== NODE_ARTIFACT_ROOT
        || !Array.isArray(manifest.nodeArtifacts.executables)
        || manifest.nodeArtifacts.executables.length === 0) {
        fail('Executable node artifact digest pins are required');
    }
    if (!Array.isArray(manifest.files) || manifest.files.length === 0) fail('File hash list is required');
}

function verifyArtifact({ archivePath, checksumPath }) {
    const absoluteArchivePath = path.resolve(archivePath);
    const absoluteChecksumPath = path.resolve(checksumPath);
    const actualArchiveHash = sha256File(absoluteArchivePath);
    const expectedArchiveHash = parseChecksum(absoluteChecksumPath, absoluteArchivePath);
    if (actualArchiveHash !== expectedArchiveHash) fail('Archive SHA-256 does not match checksum manifest');

    const rawMembers = runTar(['-tzf', absoluteArchivePath]).trim().split('\n').filter(Boolean);
    if (rawMembers.length === 0) fail('Archive is empty');
    for (const member of rawMembers) validateArchiveMemberPath(member);
    if (new Set(rawMembers).size !== rawMembers.length) fail('Archive contains duplicate member paths');
    if (rawMembers.join('\n') !== [...rawMembers].sort().join('\n')) {
        fail('Archive member paths are not sorted');
    }

    const verboseMembers = runTar(['--numeric-owner', '-tvzf', absoluteArchivePath])
        .trim().split('\n').filter(Boolean);
    if (verboseMembers.length !== rawMembers.length) fail('Unable to inspect every archive member');
    if (verboseMembers.some(line => !['-', 'd'].includes(line[0]))) {
        fail('Archive contains a non-regular, non-directory member');
    }

    const rootNames = new Set(rawMembers.map(member => member.split('/')[0]));
    if (rootNames.size !== 1) fail('Archive must have exactly one top-level directory');
    const [rootName] = rootNames;
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-l2tp-verify-'));

    try {
        runTar(['-xzf', absoluteArchivePath, '-C', tempRoot]);
        const releaseRoot = path.join(tempRoot, rootName);
        const manifestPath = path.join(releaseRoot, 'release-manifest.json');
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
        assertManifestShape(manifest);
        if (rootName !== `${manifest.module.id}-${manifest.module.version}`) {
            fail('Top-level directory does not match module id and version');
        }

        const relativeFiles = manifest.files.map(file => {
            if (!file || typeof file.path !== 'string' || !/^[a-f0-9]{64}$/.test(file.sha256)) {
                fail('Invalid file hash entry');
            }
            const validatedPath = validateArchiveMemberPath(file.path);
            if (validatedPath !== file.path || file.path === 'release-manifest.json') {
                fail(`Invalid payload path: ${JSON.stringify(file.path)}`);
            }
            return file.path;
        });
        if (new Set(relativeFiles).size !== relativeFiles.length) fail('Duplicate file hash entry');
        if (relativeFiles.join('\n') !== [...relativeFiles].sort().join('\n')) {
            fail('File hash entries are not sorted');
        }
        const requiredContentPaths = [
            manifest.contents.migrationRegistry,
            ...manifest.contents.panel.views,
            ...manifest.contents.panel.routes,
            ...Object.values(manifest.contents.tools),
        ];
        for (const requiredPath of requiredContentPaths) {
            if (relativeFiles.filter(filePath => filePath === requiredPath).length !== 1) {
                fail(`Required release content must appear exactly once: ${requiredPath}`);
            }
        }

        const pinnedNodeExecutables = manifest.nodeArtifacts.executables.map(file => {
            if (!file || typeof file.path !== 'string' || !/^[a-f0-9]{64}$/.test(file.sha256)) {
                fail('Invalid executable node artifact digest pin');
            }
            if (validateArchiveMemberPath(file.path) !== file.path
                || !file.path.startsWith(`${NODE_ARTIFACT_ROOT}/`)) {
                fail(`Invalid executable node artifact path: ${JSON.stringify(file.path)}`);
            }
            return file.path;
        });
        if (new Set(pinnedNodeExecutables).size !== pinnedNodeExecutables.length) {
            fail('Duplicate executable node artifact digest pin');
        }
        if (JSON.stringify(pinnedNodeExecutables) !== JSON.stringify(REQUIRED_NODE_EXECUTABLE_PATHS)) {
            fail('Executable node artifact digest pin set is incomplete or unexpected');
        }

        const archiveFiles = rawMembers
            .filter(member => !member.endsWith('/'))
            .map(member => member.slice(rootName.length + 1))
            .sort();
        const expectedFiles = ['release-manifest.json', ...relativeFiles].sort();
        if (JSON.stringify(archiveFiles) !== JSON.stringify(expectedFiles)) {
            fail('Archive file set does not match release manifest');
        }

        for (const file of manifest.files) {
            const filePath = path.join(releaseRoot, ...file.path.split('/'));
            if (sha256File(filePath) !== file.sha256) fail(`Payload hash mismatch: ${file.path}`);
        }

        const nodePayloadPaths = relativeFiles.filter(filePath => filePath.startsWith(`${NODE_ARTIFACT_ROOT}/`));
        if (JSON.stringify(nodePayloadPaths) !== JSON.stringify(REQUIRED_NODE_EXECUTABLE_PATHS)) {
            fail('Node artifact payload set is incomplete or unexpected');
        }
        for (const pin of manifest.nodeArtifacts.executables) {
            const payloadHash = manifest.files.find(file => file.path === pin.path)?.sha256;
            if (payloadHash !== pin.sha256) fail(`Node artifact digest pin mismatch: ${pin.path}`);
            const filePath = path.join(releaseRoot, ...pin.path.split('/'));
            if (!fs.statSync(filePath).isFile() || (fs.statSync(filePath).mode & 0o111) === 0) {
                fail(`Node artifact is not executable: ${pin.path}`);
            }
        }

        const moduleManifest = JSON.parse(
            fs.readFileSync(path.join(releaseRoot, 'module', 'manifest.json'), 'utf8'),
        );
        for (const field of ['id', 'version', 'moduleApiVersion']) {
            if (moduleManifest[field] !== manifest.module[field]) {
                fail(`Module manifest mismatch: ${field}`);
            }
        }
        if (JSON.stringify([...moduleManifest.requiredCapabilities].sort())
            !== JSON.stringify([...manifest.module.requiredCapabilities].sort())) {
            fail('Module manifest mismatch: requiredCapabilities');
        }

        return {
            valid: true,
            module: manifest.module,
            source: manifest.source,
            sha256: actualArchiveHash,
            size: fs.statSync(absoluteArchivePath).size,
            files: manifest.files.length,
        };
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
}

function parseArguments(argv) {
    const values = {};
    for (let index = 0; index < argv.length; index += 2) {
        const name = argv[index];
        const value = argv[index + 1];
        if (!name?.startsWith('--') || value === undefined) fail(`Invalid argument: ${name || ''}`);
        values[name.slice(2)] = value;
    }
    if (!values.archive || !values.checksum) {
        fail('Usage: verify-relay-l2tp-artifact.js --archive FILE --checksum FILE');
    }
    return { archivePath: values.archive, checksumPath: values.checksum };
}

if (require.main === module) {
    try {
        const options = parseArguments(process.argv.slice(2));
        const verified = verifyArtifact(options);
        process.stdout.write(`${JSON.stringify({
            artifactPath: path.resolve(options.archivePath),
            sha256: verified.sha256,
            size: verified.size,
            source: verified.source,
        })}\n`);
    } catch (error) {
        process.stderr.write(`Artifact verification failed: ${error.message}\n`);
        process.exitCode = 1;
    }
}

module.exports = {
    validateArchiveMemberPath,
    verifyArtifact,
};
