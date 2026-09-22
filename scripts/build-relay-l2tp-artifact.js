#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const zlib = require('node:zlib');

const MODULE_PATH = 'src/modules/relay-l2tp';
const METADATA_PATH = 'scripts/relay-l2tp-artifact';
const METADATA_FILES = [
    { name: 'install.js', executable: true },
    { name: 'topology.schema.json', executable: false },
    { name: 'topology-transfer.js', executable: true },
];
const FIXED_MODE = 0o644;
const FIXED_EXECUTABLE_MODE = 0o755;

function fail(message) {
    throw new Error(message);
}

function run(command, args, options = {}) {
    const spawnOptions = {
        cwd: options.cwd,
        maxBuffer: 64 * 1024 * 1024,
    };
    if (Object.hasOwn(options, 'encoding')) spawnOptions.encoding = options.encoding;
    else spawnOptions.encoding = 'utf8';
    const result = spawnSync(command, args, spawnOptions);
    if (result.status !== 0) {
        fail(`${command} failed: ${String(result.stderr || result.stdout).trim()}`);
    }
    return result.stdout;
}

function sha256Buffer(content) {
    return crypto.createHash('sha256').update(content).digest('hex');
}

function sha256File(filePath) {
    return sha256Buffer(fs.readFileSync(filePath));
}

const SECRET_PATTERNS = [
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?):\/\/[^\s/:@]+:[^\s/@]+@/i,
    /\bAKIA[0-9A-Z]{16}\b/,
    /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
    /\bBearer\s+eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/,
    /\b(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret|psk)\s*[:=]\s*['"][^'"\r\n]{8,}['"]/i,
];

function assertNoSecretMaterial(entries) {
    for (const entry of entries) {
        const content = Buffer.isBuffer(entry.content) ? entry.content.toString('utf8') : String(entry.content);
        if (SECRET_PATTERNS.some(pattern => pattern.test(content))) {
            fail(`Secret-like material detected in ${entry.path}`);
        }
    }
}

function git(repoRoot, args) {
    return run('git', ['-C', repoRoot, ...args]).trim();
}

function listModuleSourceFiles(repoRoot) {
    const output = git(repoRoot, ['ls-files', '-z', '--', MODULE_PATH]);
    return output.split('\0')
        .filter(Boolean)
        .filter(relativePath => !relativePath.startsWith(`${MODULE_PATH}/tests/`))
        .sort((left, right) => left.localeCompare(right, 'en'));
}

function copyFile(sourcePath, destinationPath, executable = false) {
    fs.mkdirSync(path.dirname(destinationPath), { recursive: true });
    fs.copyFileSync(sourcePath, destinationPath);
    fs.chmodSync(destinationPath, executable ? FIXED_EXECUTABLE_MODE : FIXED_MODE);
    fs.utimesSync(destinationPath, 0, 0);
}

function buildArtifact({ repoRoot, outputDir }) {
    const absoluteRepoRoot = path.resolve(repoRoot);
    const absoluteOutputDir = path.resolve(outputDir);
    const moduleManifest = JSON.parse(
        fs.readFileSync(path.join(absoluteRepoRoot, MODULE_PATH, 'manifest.json'), 'utf8'),
    );
    const sourceCommit = git(absoluteRepoRoot, ['rev-parse', 'HEAD']);
    const archiveBaseName = `${moduleManifest.id}-${moduleManifest.version}`;
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-l2tp-build-'));
    const stageRoot = path.join(tempRoot, archiveBaseName);

    try {
        const sourceFiles = listModuleSourceFiles(absoluteRepoRoot);
        if (sourceFiles.length === 0) fail('No relay-l2tp source files found');

        const fileHashes = [];
        const payloadEntries = [];
        for (const relativeSourcePath of sourceFiles) {
            const sourcePath = path.join(absoluteRepoRoot, relativeSourcePath);
            const relativeModulePath = path.relative(MODULE_PATH, relativeSourcePath);
            const artifactPath = path.posix.join('module', relativeModulePath.split(path.sep).join('/'));
            const destinationPath = path.join(stageRoot, ...artifactPath.split('/'));
            const sourceMode = fs.statSync(sourcePath).mode;
            copyFile(sourcePath, destinationPath, (sourceMode & 0o111) !== 0);
            fileHashes.push({ path: artifactPath, sha256: sha256File(destinationPath) });
            payloadEntries.push({ path: artifactPath, content: fs.readFileSync(destinationPath) });
        }

        for (const metadataFile of METADATA_FILES) {
            const sourcePath = path.join(absoluteRepoRoot, METADATA_PATH, metadataFile.name);
            const destinationPath = path.join(stageRoot, metadataFile.name);
            copyFile(sourcePath, destinationPath, metadataFile.executable);
            fileHashes.push({ path: metadataFile.name, sha256: sha256File(destinationPath) });
            payloadEntries.push({ path: metadataFile.name, content: fs.readFileSync(destinationPath) });
        }
        assertNoSecretMaterial(payloadEntries);

        const releaseManifest = {
            schemaVersion: 1,
            module: {
                id: moduleManifest.id,
                version: moduleManifest.version,
                moduleApiVersion: moduleManifest.moduleApiVersion,
                requiredCapabilities: [...moduleManifest.requiredCapabilities].sort(),
            },
            sourceCommit,
            installer: {
                stateDirectory: 'data/modules/relay-l2tp',
                moduleDirectory: 'src/modules/relay-l2tp',
                hostFilePolicy: 'Uses the host module loader/registry; never patches host index or configuration files.',
                commands: {
                    install: 'node install.js install --host-root <path> --host-manifest <path> [--dry-run]',
                    upgrade: 'node install.js upgrade --host-root <path> --host-manifest <path> [--dry-run]',
                    remove: 'node install.js remove --host-root <path> --host-manifest <path> [--dry-run]',
                    rollback: 'node install.js rollback --host-root <path> --host-manifest <path> [--dry-run]',
                },
            },
            topologyTransfer: {
                schema: 'topology.schema.json',
                policy: 'Topology is transferred separately and is never changed by install, upgrade, remove, or rollback.',
                commands: {
                    export: 'node topology-transfer.js export --input <file> --output <file>',
                    validate: 'node topology-transfer.js validate --input <file>',
                    import: 'node topology-transfer.js import --input <file> --output <file>',
                },
            },
            files: fileHashes.sort((left, right) => left.path.localeCompare(right.path, 'en')),
        };
        const releaseManifestPath = path.join(stageRoot, 'release-manifest.json');
        fs.mkdirSync(stageRoot, { recursive: true });
        fs.writeFileSync(releaseManifestPath, `${JSON.stringify(releaseManifest, null, 2)}\n`, { mode: FIXED_MODE });
        fs.utimesSync(releaseManifestPath, 0, 0);

        const tarBuffer = run('tar', [
            '--sort=name',
            '--format=ustar',
            '--mtime=@0',
            '--owner=0',
            '--group=0',
            '--numeric-owner',
            '--mode=u+rwX,go+rX,go-w',
            '-C', tempRoot,
            '-cf', '-',
            archiveBaseName,
        ], { encoding: null });
        const archiveBuffer = zlib.gzipSync(tarBuffer, { level: 9, mtime: 0 });

        fs.mkdirSync(absoluteOutputDir, { recursive: true });
        const archivePath = path.join(absoluteOutputDir, `${archiveBaseName}.tar.gz`);
        const checksumPath = `${archivePath}.sha256`;
        fs.writeFileSync(archivePath, archiveBuffer);
        fs.writeFileSync(
            checksumPath,
            `${sha256Buffer(archiveBuffer)}  ${path.basename(archivePath)}\n`,
            { mode: FIXED_MODE },
        );

        return { archivePath, checksumPath, releaseManifest };
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
    if (!values['repo-root'] || !values['output-dir']) {
        fail('Usage: build-relay-l2tp-artifact.js --repo-root PATH --output-dir PATH');
    }
    return { repoRoot: values['repo-root'], outputDir: values['output-dir'] };
}

if (require.main === module) {
    try {
        process.stdout.write(`${JSON.stringify(buildArtifact(parseArguments(process.argv.slice(2))))}\n`);
    } catch (error) {
        process.stderr.write(`Artifact build failed: ${error.message}\n`);
        process.exitCode = 1;
    }
}

module.exports = {
    assertNoSecretMaterial,
    buildArtifact,
    listModuleSourceFiles,
    sha256File,
};
