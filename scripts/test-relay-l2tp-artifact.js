'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const repoRoot = path.resolve(__dirname, '..');
const buildScript = path.join(repoRoot, 'scripts', 'build-relay-l2tp-artifact.js');
const verifyScript = path.join(repoRoot, 'scripts', 'verify-relay-l2tp-artifact.js');
const { assertNoSecretMaterial } = require('./build-relay-l2tp-artifact');
const { validateArchiveMemberPath } = require('./verify-relay-l2tp-artifact');

function runBuild(outputDir) {
    const result = spawnSync(process.execPath, [
        buildScript,
        '--repo-root', repoRoot,
        '--output-dir', outputDir,
    ], { encoding: 'utf8' });

    assert.equal(result.status, 0, result.stderr || result.stdout);
    const built = JSON.parse(result.stdout);
    if (built.artifactPath && !built.archivePath) built.archivePath = built.artifactPath;
    if (!built.checksumPath && built.archivePath) built.checksumPath = `${built.archivePath}.sha256`;
    return built;
}

function runVerify(archivePath, checksumPath) {
    const result = runVerifyResult(archivePath, checksumPath);

    assert.equal(result.status, 0, result.stderr || result.stdout);
    return JSON.parse(result.stdout);
}

function runVerifyResult(archivePath, checksumPath) {
    return spawnSync(process.execPath, [
        verifyScript,
        '--archive', archivePath,
        '--checksum', checksumPath,
    ], { encoding: 'utf8' });
}

function sha256(filePath) {
    return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function archiveFiles(archivePath) {
    const result = spawnSync('tar', ['-tzf', archivePath], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim().split('\n').filter(member => member && !member.endsWith('/'));
}

function extractArchive(archivePath, outputDir) {
    fs.mkdirSync(outputDir, { recursive: true });
    const result = spawnSync('tar', ['-xzf', archivePath, '-C', outputDir], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
}

function createDeterministicArchive(sourceDir, rootName, archivePath) {
    const result = spawnSync('tar', [
        '--sort=name',
        '--format=ustar',
        '--mtime=@0',
        '--owner=0',
        '--group=0',
        '--numeric-owner',
        '--mode=u+rwX,go+rX,go-w',
        '-C', sourceDir,
        '-czf', archivePath,
        rootName,
    ], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr || result.stdout);
}

function trackedModuleFiles() {
    const result = spawnSync('git', [
        '-C', repoRoot, 'ls-files', '-z', '--', 'src/modules/relay-l2tp',
    ], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.split('\0')
        .filter(Boolean)
        .filter(file => !file.startsWith('src/modules/relay-l2tp/tests/'))
        .map(file => file.replace('src/modules/relay-l2tp/', 'module/'));
}

function writeJson(filePath, value) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function runCli(scriptPath, args) {
    return spawnSync(process.execPath, [scriptPath, ...args], { encoding: 'utf8' });
}

function runGit(repoPath, args) {
    const result = spawnSync('git', ['-C', repoPath, ...args], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    return result.stdout.trim();
}

function createBuildTargetFixture(prefix) {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    const fixtureRepo = path.join(tempRoot, 'repo');
    for (const relativePath of [
        'index.js',
        'src/modules/relay-l2tp',
        'src/modules/createL2tpPanelHost.js',
        'src/modules/createL2tpStartupLifecycle.js',
        'src/modules/l2tpActiveHostProvider.js',
        'src/modules/l2tpMigrationBootstrap.js',
        'src/modules/l2tpRuntimeLifecycleHook.js',
        'src/routes/panel/index.js',
        'scripts/relay-l2tp-artifact',
        'views/l2tp.ejs',
    ]) {
        fs.cpSync(
            path.join(repoRoot, ...relativePath.split('/')),
            path.join(fixtureRepo, ...relativePath.split('/')),
            { recursive: true },
        );
    }
    runGit(fixtureRepo, ['init', '--quiet']);
    runGit(fixtureRepo, ['add', '.']);
    runGit(fixtureRepo, [
        '-c', 'user.name=Release Test',
        '-c', 'user.email=release-test@example.invalid',
        'commit', '--quiet', '-m', 'target',
    ]);
    const targetCommit = runGit(fixtureRepo, ['rev-parse', 'HEAD^{commit}']);
    const targetTree = runGit(fixtureRepo, ['rev-parse', 'HEAD^{tree}']);

    const manifestPath = path.join(fixtureRepo, 'src/modules/relay-l2tp/manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    manifest.version = '9.9.9';
    writeJson(manifestPath, manifest);
    runGit(fixtureRepo, ['add', manifestPath]);
    runGit(fixtureRepo, [
        '-c', 'user.name=Release Test',
        '-c', 'user.email=release-test@example.invalid',
        'commit', '--quiet', '-m', 'newer-head',
    ]);

    return { tempRoot, fixtureRepo, targetCommit, targetTree };
}

function createArtifactFixture(prefix) {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    const built = runBuild(path.join(tempRoot, 'dist'));
    const extracted = path.join(tempRoot, 'extracted');
    extractArchive(built.archivePath, extracted);
    return {
        tempRoot,
        releaseRoot: path.join(extracted, 'relay-l2tp-0.1.0'),
        cleanup() {
            fs.rmSync(tempRoot, { recursive: true, force: true });
        },
    };
}

function snapshotTree(rootPath) {
    const entries = [];

    function visit(currentPath, relativePath = '') {
        for (const name of fs.readdirSync(currentPath).sort()) {
            const absolutePath = path.join(currentPath, name);
            const childPath = relativePath ? `${relativePath}/${name}` : name;
            const stat = fs.lstatSync(absolutePath);
            if (stat.isDirectory()) {
                entries.push(`${childPath}/`);
                visit(absolutePath, childPath);
            } else {
                entries.push(`${childPath}:${sha256(absolutePath)}`);
            }
        }
    }

    visit(rootPath);
    return entries;
}

test('builds byte-identical archives and checksum manifests in separate temporary directories', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-l2tp-artifact-'));
    try {
        const first = runBuild(path.join(tempRoot, 'first'));
        const second = runBuild(path.join(tempRoot, 'second'));

        assert.equal(sha256(first.archivePath), sha256(second.archivePath));
        assert.equal(
            fs.readFileSync(first.checksumPath, 'utf8'),
            fs.readFileSync(second.checksumPath, 'utf8'),
        );
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
});

test('builds the exact requested source ref instead of a newer checked-out branch', () => {
    const fixture = createBuildTargetFixture('relay-l2tp-source-ref-');
    try {
        const result = runCli(buildScript, [
            '--repo-root', fixture.fixtureRepo,
            '--output-dir', path.join(fixture.tempRoot, 'dist'),
            '--source-ref', fixture.targetCommit,
        ]);
        assert.equal(result.status, 0, result.stderr || result.stdout);
        const built = JSON.parse(result.stdout);
        assert.equal(path.basename(built.artifactPath), 'relay-l2tp-0.1.0.tar.gz');
        assert.deepEqual(built.source, {
            commit: fixture.targetCommit,
            tree: fixture.targetTree,
        });
    } finally {
        fs.rmSync(fixture.tempRoot, { recursive: true, force: true });
    }
});

test('builder CLI prints only artifact identity fields', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-l2tp-build-output-'));
    try {
        const result = runCli(buildScript, [
            '--repo-root', repoRoot,
            '--output-dir', path.join(tempRoot, 'dist'),
        ]);
        assert.equal(result.status, 0, result.stderr || result.stdout);
        const output = JSON.parse(result.stdout);
        assert.deepEqual(Object.keys(output).sort(), ['artifactPath', 'sha256', 'size', 'source']);
        assert.match(output.artifactPath, /relay-l2tp-0\.1\.0\.tar\.gz$/);
        assert.match(output.sha256, /^[a-f0-9]{64}$/);
        assert.equal(output.size, fs.statSync(output.artifactPath).size);
        assert.match(output.source.commit, /^[a-f0-9]{40}$/);
        assert.match(output.source.tree, /^[a-f0-9]{40}$/);
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
});

test('archive contains exactly module source and explicit release metadata in sorted paths', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-l2tp-members-'));
    try {
        const built = runBuild(tempRoot);
        const root = 'relay-l2tp-0.1.0/';
        const actual = archiveFiles(built.archivePath);
        const expected = [
            ...trackedModuleFiles().map(file => `${root}${file}`),
            `${root}install.js`,
            `${root}module/views/l2tp.ejs`,
            `${root}release-manifest.json`,
            `${root}topology.schema.json`,
            `${root}topology-transfer.js`,
        ].sort();

        assert.deepEqual(actual, [...actual].sort(), 'archive member paths must be sorted');
        assert.deepEqual(actual, expected);
        assert.equal(actual.some(member => /(^|\/)(?:node_modules|\.git|tests?|cache|tmp|credentials?)(?:\/|$)/i.test(member)), false);
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
});

test('release manifest binds source, package contents, host integration requirement, node executables, and payload hashes', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-l2tp-manifest-'));
    try {
        const built = runBuild(path.join(tempRoot, 'out'));
        const extracted = path.join(tempRoot, 'extracted');
        extractArchive(built.archivePath, extracted);
        const releaseRoot = path.join(extracted, 'relay-l2tp-0.1.0');
        const manifest = JSON.parse(fs.readFileSync(path.join(releaseRoot, 'release-manifest.json'), 'utf8'));
        const commit = spawnSync('git', ['-C', repoRoot, 'rev-parse', 'HEAD^{commit}'], { encoding: 'utf8' }).stdout.trim();
        const tree = spawnSync('git', ['-C', repoRoot, 'rev-parse', 'HEAD^{tree}'], { encoding: 'utf8' }).stdout.trim();

        assert.equal(manifest.schemaVersion, 2);
        assert.deepEqual(manifest.module, {
            id: 'relay-l2tp',
            version: '0.1.0',
            moduleApiVersion: 1,
            requiredCapabilities: ['ssh'],
        });
        assert.deepEqual(manifest.source, { commit, tree });
        assert.deepEqual(Object.keys(manifest.installer.commands).sort(), ['install', 'remove', 'rollback', 'upgrade']);
        assert.equal(manifest.installer.stateDirectory, 'data/modules/relay-l2tp');
        assert.match(manifest.installer.hostFilePolicy, /never patches host index or configuration files/i);
        assert.deepEqual(Object.keys(manifest.topologyTransfer.commands).sort(), ['export', 'import', 'validate']);
        assert.equal(manifest.topologyTransfer.schema, 'topology.schema.json');
        assert.deepEqual(manifest.contents, {
            migrationRegistry: 'module/migrations/index.js',
            migrations: [
                'module/migrations/index.js',
                'module/migrations/migrationRunner.js',
                'module/migrations/migrationStateRepository.js',
            ],
            panel: {
                views: ['module/views/l2tp.ejs'],
                routes: ['module/routes/panel.js', 'module/routes/panelOverview.js'],
            },
            tools: {
                installer: 'install.js',
                nodeInstaller: 'module/node-artifacts/l2tp/install.sh',
                rollback: 'module/node-artifacts/l2tp/rollback.sh',
                topologySchema: 'topology.schema.json',
                topologyTransfer: 'topology-transfer.js',
            },
        });
        assert.deepEqual(manifest.hostIntegration, {
            artifactScope: 'module-only',
            fullPanelSourceBundleRequired: true,
            policy: 'Root lifecycle, migration bootstrap, and panel mounting are host integrations outside this module archive; deploy with the full panel source bundle matching source.commit and source.tree.',
            entryPoints: [
                'index.js',
                'src/modules/createL2tpPanelHost.js',
                'src/modules/createL2tpStartupLifecycle.js',
                'src/modules/l2tpActiveHostProvider.js',
                'src/modules/l2tpMigrationBootstrap.js',
                'src/modules/l2tpRuntimeLifecycleHook.js',
                'src/routes/panel/index.js',
                'views/l2tp.ejs',
            ],
        });

        const payloadFiles = archiveFiles(built.archivePath)
            .map(member => member.replace('relay-l2tp-0.1.0/', ''))
            .filter(member => member !== 'release-manifest.json')
            .sort();
        assert.deepEqual(manifest.files.map(file => file.path), payloadFiles);
        for (const file of manifest.files) {
            assert.equal(file.sha256, sha256(path.join(releaseRoot, ...file.path.split('/'))));
        }

        const executableNodeArtifacts = manifest.files
            .filter(file => file.path.startsWith('module/node-artifacts/l2tp/'))
            .filter(file => (fs.statSync(path.join(releaseRoot, ...file.path.split('/'))).mode & 0o111) !== 0);
        assert.deepEqual(manifest.nodeArtifacts, {
            root: 'module/node-artifacts/l2tp',
            executables: executableNodeArtifacts,
        });
        assert.equal(manifest.nodeArtifacts.executables.length, 19);
        assert.equal(new Set(manifest.nodeArtifacts.executables.map(file => file.path)).size, 19);
        assert.equal(
            manifest.nodeArtifacts.executables.some(file => (
                file.path === 'module/node-artifacts/l2tp/materialize-nft-candidate.sh'
            )),
            true,
        );
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
});

test('verifier authenticates the checksum, member set, manifest, and file hashes', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-l2tp-verify-'));
    try {
        const built = runBuild(tempRoot);
        const verified = runVerify(built.archivePath, built.checksumPath);

        assert.deepEqual(Object.keys(verified).sort(), ['artifactPath', 'sha256', 'size', 'source']);
        assert.equal(verified.artifactPath, path.resolve(built.archivePath));
        assert.equal(verified.sha256, sha256(built.archivePath));
        assert.equal(verified.size, fs.statSync(built.archivePath).size);
        assert.match(verified.source.commit, /^[a-f0-9]{40}$/);
        assert.match(verified.source.tree, /^[a-f0-9]{40}$/);
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
});

test('changing a node payload invalidates verification even when its generic file hash and archive checksum are refreshed', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-l2tp-node-tamper-'));
    try {
        const built = runBuild(path.join(tempRoot, 'original'));
        const extracted = path.join(tempRoot, 'extracted');
        const rootName = 'relay-l2tp-0.1.0';
        const releaseRoot = path.join(extracted, rootName);
        const payloadPath = 'module/node-artifacts/l2tp/verify-users.sh';
        extractArchive(built.archivePath, extracted);

        const absolutePayloadPath = path.join(releaseRoot, ...payloadPath.split('/'));
        fs.appendFileSync(absolutePayloadPath, '\n# release-verifier-tamper-probe\n');
        const manifestPath = path.join(releaseRoot, 'release-manifest.json');
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
        manifest.files.find(file => file.path === payloadPath).sha256 = sha256(absolutePayloadPath);
        writeJson(manifestPath, manifest);

        const tamperedArchive = path.join(tempRoot, `${rootName}-tampered.tar.gz`);
        const tamperedChecksum = `${tamperedArchive}.sha256`;
        createDeterministicArchive(extracted, rootName, tamperedArchive);
        fs.writeFileSync(
            tamperedChecksum,
            `${sha256(tamperedArchive)}  ${path.basename(tamperedArchive)}\n`,
        );

        const result = runVerifyResult(tamperedArchive, tamperedChecksum);
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /node artifact digest pin mismatch: module\/node-artifacts\/l2tp\/verify-users\.sh/i);
        assert.equal(result.stderr.includes('release-verifier-tamper-probe'), false);
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
});

test('verifier rejects traversal and platform-absolute archive member paths', () => {
    for (const unsafePath of ['../escape', 'root/../../escape', '/absolute', 'C:/absolute', 'root\\escape']) {
        assert.throws(() => validateArchiveMemberPath(unsafePath), /Unsafe archive member path/);
    }
});

test('builder rejects a secret-like fixture without echoing secret material', () => {
    const fixture = 'mongodb://artifact-user:fixture-password@db.invalid/celerity';
    assert.throws(
        () => assertNoSecretMaterial([{ path: 'fixture.json', content: fixture }]),
        error => {
            assert.match(error.message, /secret-like material.*fixture\.json/i);
            assert.equal(error.message.includes(fixture), false);
            assert.equal(error.message.includes('fixture-password'), false);
            return true;
        },
    );
});

test('installer dry-run validates and plans without writing to the host root', () => {
    const fixture = createArtifactFixture('relay-l2tp-dry-run-');
    try {
        const hostRoot = path.join(fixture.tempRoot, 'host');
        const hostManifestPath = path.join(fixture.tempRoot, 'host-manifest.json');
        fs.mkdirSync(hostRoot);
        fs.writeFileSync(path.join(hostRoot, 'keep.txt'), 'unchanged\n');
        writeJson(hostManifestPath, { moduleApiVersion: 1, capabilities: ['ssh'] });
        const before = snapshotTree(hostRoot);
        const result = runCli(path.join(fixture.releaseRoot, 'install.js'), [
            'install', '--host-root', hostRoot, '--host-manifest', hostManifestPath, '--dry-run',
        ]);

        assert.equal(result.status, 0, result.stderr || result.stdout);
        assert.deepEqual(snapshotTree(hostRoot), before);
        assert.deepEqual(JSON.parse(result.stdout), {
            action: 'install',
            dryRun: true,
            module: { id: 'relay-l2tp', version: '0.1.0' },
            operations: [
                { type: 'replace', path: 'src/modules/relay-l2tp' },
                { type: 'write', path: 'data/modules/relay-l2tp/installer-state.json' },
            ],
        });
    } finally {
        fixture.cleanup();
    }
});

test('installer installs the module and records local installer state', () => {
    const fixture = createArtifactFixture('relay-l2tp-install-');
    try {
        const hostRoot = path.join(fixture.tempRoot, 'host');
        const hostManifestPath = path.join(fixture.tempRoot, 'host-manifest.json');
        fs.mkdirSync(hostRoot);
        writeJson(hostManifestPath, { moduleApiVersion: 1, capabilities: ['ssh'] });
        const result = runCli(path.join(fixture.releaseRoot, 'install.js'), [
            'install', '--host-root', hostRoot, '--host-manifest', hostManifestPath,
        ]);

        assert.equal(result.status, 0, result.stderr || result.stdout);
        const installedManifest = JSON.parse(fs.readFileSync(
            path.join(hostRoot, 'src/modules/relay-l2tp/manifest.json'),
            'utf8',
        ));
        const installerState = JSON.parse(fs.readFileSync(
            path.join(hostRoot, 'data/modules/relay-l2tp/installer-state.json'),
            'utf8',
        ));
        assert.equal(installedManifest.version, '0.1.0');
        assert.deepEqual(installerState, {
            schemaVersion: 1,
            module: { id: 'relay-l2tp', version: '0.1.0' },
            lastAction: 'install',
            rollbackAvailable: false,
        });
        assert.equal(JSON.parse(result.stdout).changed, true);
    } finally {
        fixture.cleanup();
    }
});

test('installer restores the previous module and metadata after an induced transaction failure', () => {
    const fixture = createArtifactFixture('relay-l2tp-rollback-');
    try {
        const hostRoot = path.join(fixture.tempRoot, 'host');
        const hostManifestPath = path.join(fixture.tempRoot, 'host-manifest.json');
        const targetRoot = path.join(hostRoot, 'src/modules/relay-l2tp');
        fs.mkdirSync(targetRoot, { recursive: true });
        fs.writeFileSync(path.join(targetRoot, 'previous.txt'), 'previous module\n');
        writeJson(path.join(targetRoot, 'manifest.json'), {
            id: 'relay-l2tp',
            version: '0.0.9',
            moduleApiVersion: 1,
            requiredCapabilities: ['ssh'],
        });
        writeJson(hostManifestPath, { moduleApiVersion: 1, capabilities: ['ssh'] });
        const before = snapshotTree(hostRoot);
        const { runInstaller } = require(path.join(fixture.releaseRoot, 'install.js'));

        assert.throws(
            () => runInstaller({
                action: 'upgrade',
                artifactRoot: fixture.releaseRoot,
                hostRoot,
                hostManifestPath,
                faultInjector(step) {
                    if (step === 'module-applied') throw new Error('induced failure');
                },
            }),
            /induced failure/,
        );
        assert.deepEqual(snapshotTree(hostRoot), before);
    } finally {
        fixture.cleanup();
    }
});

test('installer rejects host API and capability mismatches before writing', () => {
    const fixture = createArtifactFixture('relay-l2tp-host-check-');
    try {
        const installScript = path.join(fixture.releaseRoot, 'install.js');
        for (const [hostManifest, expectedError] of [
            [{ moduleApiVersion: 2, capabilities: ['ssh'] }, /module api version/i],
            [{ moduleApiVersion: 1, capabilities: [] }, /missing required capabilities: ssh/i],
        ]) {
            const caseRoot = fs.mkdtempSync(path.join(fixture.tempRoot, 'host-'));
            const hostManifestPath = path.join(fixture.tempRoot, `${path.basename(caseRoot)}.json`);
            writeJson(hostManifestPath, hostManifest);
            const before = snapshotTree(caseRoot);
            const result = runCli(installScript, [
                'install', '--host-root', caseRoot, '--host-manifest', hostManifestPath, '--dry-run',
            ]);

            assert.notEqual(result.status, 0);
            assert.match(result.stderr, expectedError);
            assert.deepEqual(snapshotTree(caseRoot), before);
        }
    } finally {
        fixture.cleanup();
    }
});

test('topology export and import produce secret-free drafts without database ObjectIds', () => {
    const fixture = createArtifactFixture('relay-l2tp-topology-transfer-');
    try {
        const ids = {
            relay: '64a1b2c3d4e5f6a7b8c9d001',
            bridge: '64a1b2c3d4e5f6a7b8c9d002',
            link: '64a1b2c3d4e5f6a7b8c9d003',
            group: '64a1b2c3d4e5f6a7b8c9d004',
        };
        const secrets = ['ssh-password-value', 'encrypted-psk-value', 'encrypted-user-password'];
        const rawPath = path.join(fixture.tempRoot, 'raw.json');
        const transferPath = path.join(fixture.tempRoot, 'transfer.json');
        const taintedPath = path.join(fixture.tempRoot, 'tainted-transfer.json');
        const importPath = path.join(fixture.tempRoot, 'import-draft.json');
        const transferScript = path.join(fixture.releaseRoot, 'topology-transfer.js');
        writeJson(rawPath, {
            nodes: [
                {
                    _id: ids.relay,
                    name: 'Relay west',
                    cascadeRole: 'relay',
                    ssh: { password: secrets[0], privateKey: 'private-key-material' },
                },
                { _id: ids.bridge, name: 'Bridge east', cascadeRole: 'bridge' },
            ],
            links: [{
                _id: ids.link,
                name: 'Relay to bridge',
                portalNode: ids.relay,
                bridgeNode: ids.bridge,
                mode: 'reverse',
                active: true,
                tunnelSecret: 'link-secret-value',
            }],
            routeGroups: [{
                _id: ids.group,
                name: 'Primary route',
                mode: 'reverse',
                strategy: 'priority-failover',
                paths: [{ pathKey: 'primary', linkIds: [ids.link], priority: 1 }],
            }],
            relayStates: [{
                node: ids.relay,
                desiredState: 'installed',
                clientCidr: '10.66.0.0/24',
                localAddress: '10.66.0.1',
                dnsServers: ['9.9.9.9'],
                routingMode: 'route-group',
                routeGroup: ids.group,
                pskEncrypted: secrets[1],
            }],
            l2tpUsers: [{ relayNode: ids.relay, login: 'alice', passwordEncrypted: secrets[2] }],
        });

        const exported = runCli(transferScript, [
            'export', '--input', rawPath, '--output', transferPath,
        ]);
        assert.equal(exported.status, 0, exported.stderr || exported.stdout);
        const validated = runCli(transferScript, ['validate', '--input', transferPath]);
        assert.equal(validated.status, 0, validated.stderr || validated.stdout);
        const transfer = JSON.parse(fs.readFileSync(transferPath, 'utf8'));
        const transferText = JSON.stringify(transfer);
        assert.equal(transfer.kind, 'relay-l2tp-topology-transfer');
        assert.deepEqual(transfer.topology.links[0], {
            key: 'link-001',
            name: 'Relay to bridge',
            source: 'node-001',
            target: 'node-002',
            mode: 'reverse',
            active: true,
        });
        assert.deepEqual(transfer.topology.routeGroups[0].paths[0].links, ['link-001']);
        for (const value of [...Object.values(ids), ...secrets, 'link-secret-value', 'private-key-material']) {
            assert.equal(transferText.includes(value), false, `draft leaked ${value}`);
        }
        assert.doesNotMatch(transferText, /\b[a-f0-9]{24}\b/i);
        assert.doesNotMatch(transferText, /password|privateKey|psk|secret/i);

        transfer.topology.nodes[0]._id = ids.relay;
        transfer.topology.nodes[0].password = 'import-password-value';
        transfer.credentials = { token: 'import-token-value' };
        writeJson(taintedPath, transfer);
        const imported = runCli(transferScript, [
            'import', '--input', taintedPath, '--output', importPath,
        ]);
        assert.equal(imported.status, 0, imported.stderr || imported.stdout);
        const importDraft = JSON.parse(fs.readFileSync(importPath, 'utf8'));
        const importText = JSON.stringify(importDraft);
        assert.equal(importDraft.kind, 'relay-l2tp-topology-import-draft');
        assert.doesNotMatch(importText, /\b[a-f0-9]{24}\b/i);
        assert.doesNotMatch(importText, /password|credential|token|psk|secret/i);
    } finally {
        fixture.cleanup();
    }
});
