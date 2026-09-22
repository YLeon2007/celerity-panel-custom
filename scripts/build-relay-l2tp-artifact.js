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
const EXTRA_MODULE_FILES = [
    { source: 'views/l2tp.ejs', artifact: 'module/views/l2tp.ejs', executable: false },
];
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
    'materialize-nft-candidate.sh',
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
const RELEASE_CONTENTS = Object.freeze({
    migrationRegistry: 'module/migrations/index.js',
    migrations: Object.freeze([
        'module/migrations/index.js',
        'module/migrations/migrationRunner.js',
        'module/migrations/migrationStateRepository.js',
    ]),
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
const HOST_INTEGRATION = Object.freeze({
    artifactScope: 'module-only',
    fullPanelSourceBundleRequired: true,
    policy: 'Root lifecycle, migration bootstrap, and panel mounting are host integrations outside this module archive; deploy with the full panel source bundle matching source.commit and source.tree.',
    entryPoints: Object.freeze([
        'index.js',
        'src/modules/createL2tpPanelHost.js',
        'src/modules/createL2tpStartupLifecycle.js',
        'src/modules/l2tpActiveHostProvider.js',
        'src/modules/l2tpMigrationBootstrap.js',
        'src/modules/l2tpRuntimeLifecycleHook.js',
        'src/routes/panel/index.js',
        'views/l2tp.ejs',
    ]),
});
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

function gitBuffer(repoRoot, args) {
    return run('git', ['-C', repoRoot, ...args], { encoding: null });
}

function resolveSource(repoRoot, sourceRef) {
    if (typeof sourceRef !== 'string' || sourceRef.length === 0 || sourceRef.startsWith('-')) {
        fail('sourceRef must be a non-empty Git revision without a leading dash');
    }
    const commit = git(repoRoot, ['rev-parse', '--verify', `${sourceRef}^{commit}`]);
    const tree = git(repoRoot, ['rev-parse', '--verify', `${commit}^{tree}`]);
    return { commit, tree };
}

function listGitFiles(repoRoot, sourceCommit, pathspec) {
    const output = gitBuffer(repoRoot, ['ls-tree', '-r', '-z', sourceCommit, '--', pathspec]);
    return output.toString('utf8').split('\0').filter(Boolean).map(line => {
        const match = /^(\d{6}) (\S+) ([a-f0-9]+)\t(.+)$/.exec(line);
        if (!match || match[2] !== 'blob' || !['100644', '100755'].includes(match[1])) {
            fail(`Unsupported Git tree entry under ${pathspec}`);
        }
        return { mode: match[1], path: match[4] };
    });
}

function listModuleSourceEntries(repoRoot, sourceCommit) {
    return listGitFiles(repoRoot, sourceCommit, MODULE_PATH)
        .filter(entry => !entry.path.startsWith(`${MODULE_PATH}/tests/`))
        .sort((left, right) => left.path.localeCompare(right.path, 'en'));
}

function listModuleSourceFiles(repoRoot, sourceRef = 'HEAD') {
    const source = resolveSource(repoRoot, sourceRef);
    return listModuleSourceEntries(repoRoot, source.commit).map(entry => entry.path);
}

function readSourceFile(repoRoot, sourceCommit, relativePath) {
    const entries = listGitFiles(repoRoot, sourceCommit, relativePath);
    if (entries.length !== 1 || entries[0].path !== relativePath) {
        fail(`Required source file is missing from build target: ${relativePath}`);
    }
    return {
        content: gitBuffer(repoRoot, ['show', `${sourceCommit}:${relativePath}`]),
        executable: entries[0].mode === '100755',
    };
}

function writePayload(content, destinationPath, executable = false) {
    fs.mkdirSync(path.dirname(destinationPath), { recursive: true });
    fs.writeFileSync(destinationPath, content);
    fs.chmodSync(destinationPath, executable ? FIXED_EXECUTABLE_MODE : FIXED_MODE);
    fs.utimesSync(destinationPath, 0, 0);
}

function buildArtifact({ repoRoot, outputDir, sourceRef = 'HEAD' }) {
    const absoluteRepoRoot = path.resolve(repoRoot);
    const absoluteOutputDir = path.resolve(outputDir);
    const source = resolveSource(absoluteRepoRoot, sourceRef);
    const moduleManifestSource = readSourceFile(
        absoluteRepoRoot,
        source.commit,
        `${MODULE_PATH}/manifest.json`,
    );
    const moduleManifest = JSON.parse(moduleManifestSource.content.toString('utf8'));
    const archiveBaseName = `${moduleManifest.id}-${moduleManifest.version}`;
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-l2tp-build-'));
    const stageRoot = path.join(tempRoot, archiveBaseName);

    try {
        for (const entryPoint of HOST_INTEGRATION.entryPoints) {
            readSourceFile(absoluteRepoRoot, source.commit, entryPoint);
        }
        const sourceEntries = listModuleSourceEntries(absoluteRepoRoot, source.commit);
        if (sourceEntries.length === 0) fail('No relay-l2tp source files found in build target');

        const fileHashes = [];
        const payloadEntries = [];
        const executablePaths = new Set();
        for (const sourceEntry of sourceEntries) {
            const relativeModulePath = path.posix.relative(MODULE_PATH, sourceEntry.path);
            const artifactPath = path.posix.join('module', relativeModulePath);
            const destinationPath = path.join(stageRoot, ...artifactPath.split('/'));
            const content = gitBuffer(absoluteRepoRoot, ['show', `${source.commit}:${sourceEntry.path}`]);
            const executable = sourceEntry.mode === '100755';
            writePayload(content, destinationPath, executable);
            fileHashes.push({ path: artifactPath, sha256: sha256File(destinationPath) });
            payloadEntries.push({ path: artifactPath, content });
            if (executable) executablePaths.add(artifactPath);
        }

        for (const extraFile of EXTRA_MODULE_FILES) {
            const sourceFile = readSourceFile(absoluteRepoRoot, source.commit, extraFile.source);
            if (sourceFile.executable !== extraFile.executable) {
                fail(`Unexpected executable mode in build target: ${extraFile.source}`);
            }
            const destinationPath = path.join(stageRoot, ...extraFile.artifact.split('/'));
            writePayload(sourceFile.content, destinationPath, extraFile.executable);
            fileHashes.push({ path: extraFile.artifact, sha256: sha256File(destinationPath) });
            payloadEntries.push({ path: extraFile.artifact, content: sourceFile.content });
            if (extraFile.executable) executablePaths.add(extraFile.artifact);
        }

        for (const metadataFile of METADATA_FILES) {
            const relativeSourcePath = `${METADATA_PATH}/${metadataFile.name}`;
            const sourceFile = readSourceFile(absoluteRepoRoot, source.commit, relativeSourcePath);
            const destinationPath = path.join(stageRoot, metadataFile.name);
            writePayload(sourceFile.content, destinationPath, metadataFile.executable);
            fileHashes.push({ path: metadataFile.name, sha256: sha256File(destinationPath) });
            payloadEntries.push({ path: metadataFile.name, content: sourceFile.content });
            if (metadataFile.executable) executablePaths.add(metadataFile.name);
        }
        assertNoSecretMaterial(payloadEntries);

        const sortedFileHashes = fileHashes
            .sort((left, right) => left.path.localeCompare(right.path, 'en'));
        const nodeExecutables = sortedFileHashes
            .filter(file => file.path.startsWith(`${NODE_ARTIFACT_ROOT}/`) && executablePaths.has(file.path));
        if (JSON.stringify(nodeExecutables.map(file => file.path))
            !== JSON.stringify(REQUIRED_NODE_EXECUTABLE_PATHS)) {
            fail('Executable node artifact set is incomplete or unexpected');
        }
        const releaseManifest = {
            schemaVersion: 2,
            module: {
                id: moduleManifest.id,
                version: moduleManifest.version,
                moduleApiVersion: moduleManifest.moduleApiVersion,
                requiredCapabilities: [...moduleManifest.requiredCapabilities].sort(),
            },
            source,
            contents: RELEASE_CONTENTS,
            hostIntegration: HOST_INTEGRATION,
            nodeArtifacts: {
                root: NODE_ARTIFACT_ROOT,
                executables: nodeExecutables,
            },
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
            files: sortedFileHashes,
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
        fail('Usage: build-relay-l2tp-artifact.js --repo-root PATH --output-dir PATH [--source-ref REV]');
    }
    return {
        repoRoot: values['repo-root'],
        outputDir: values['output-dir'],
        sourceRef: values['source-ref'] || 'HEAD',
    };
}

if (require.main === module) {
    try {
        const built = buildArtifact(parseArguments(process.argv.slice(2)));
        process.stdout.write(`${JSON.stringify({
            artifactPath: built.archivePath,
            sha256: sha256File(built.archivePath),
            size: fs.statSync(built.archivePath).size,
            source: built.releaseManifest.source,
        })}\n`);
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
