'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const repoRoot = path.resolve(__dirname, '../..');
const buildArtifactScript = path.join(repoRoot, 'scripts', 'build-relay-l2tp-artifact.js');
const buildBundleScript = path.join(repoRoot, 'scripts', 'staging', 'build-source-bundle.sh');
const deployScript = path.join(repoRoot, 'scripts', 'staging', 'deploy.sh');
const precheckScript = path.join(repoRoot, 'scripts', 'staging', 'precheck.sh');
const rollbackScript = path.join(repoRoot, 'scripts', 'staging', 'rollback.sh');
const validateInputsScript = path.join(repoRoot, 'scripts', 'staging', 'validate-staging-inputs.py');
const sourceCommit = 'a'.repeat(40);
const sourceTree = 'b'.repeat(40);

function run(script, args, options = {}) {
    return spawnSync('bash', [script, ...args], {
        cwd: repoRoot,
        encoding: 'utf8',
        env: { ...process.env, ...options.env },
    });
}

function runChecked(command, args, options = {}) {
    const result = spawnSync(command, args, {
        cwd: options.cwd ?? repoRoot,
        encoding: 'utf8',
        env: { ...process.env, ...options.env },
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    return result.stdout.trim();
}

function sha256(filePath) {
    return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function createMinimalPrecheckFixture() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'celerity-staging-controls-'));
    const bundleStage = path.join(root, 'bundle-stage');
    const sourceRoot = path.join(bundleStage, 'source');
    const artifactStage = path.join(root, 'artifact-stage', 'relay-l2tp-0.1.0');
    const bundle = path.join(root, 'source.tar.gz');
    const artifact = path.join(root, 'relay-l2tp.tar.gz');
    const configEnv = path.join(root, 'test.env');
    const configRef = path.join(root, 'worker.conf');
    const mockBin = path.join(root, 'mock-bin');
    const dockerLog = path.join(root, 'docker.log');

    fs.mkdirSync(sourceRoot, { recursive: true });
    fs.mkdirSync(artifactStage, { recursive: true });
    fs.mkdirSync(mockBin, { recursive: true });
    fs.writeFileSync(path.join(bundleStage, 'manifest.env'), [
        'schema_version=1',
        `source_commit=${sourceCommit}`,
        `source_tree=${sourceTree}`,
        'worktree_clean=true',
        'archive_root=source',
        'compose_file=docker-compose.yml',
        'app_service=backend',
        '',
    ].join('\n'));
    fs.writeFileSync(path.join(sourceRoot, 'docker-compose.yml'), [
        'services:',
        '  backend:',
        '    build: .',
        '    env_file:',
        '      - .env',
        '  caddy:',
        '    image: caddy:2-alpine',
        '  mongo:',
        '    image: mongo:7',
        '  redis:',
        '    image: redis:7-alpine',
        '  updater:',
        '    image: updater:test',
        '',
    ].join('\n'));
    fs.writeFileSync(path.join(sourceRoot, 'index.js'), "'use strict';\n");
    fs.writeFileSync(path.join(artifactStage, 'release-manifest.json'), `${JSON.stringify({
        schemaVersion: 2,
        module: { id: 'relay-l2tp', version: '0.1.0' },
        source: { commit: sourceCommit, tree: sourceTree },
        files: [],
    }, null, 2)}\n`);
    let packed = spawnSync('tar', ['-czf', bundle, '-C', bundleStage, 'manifest.env', 'source'], { encoding: 'utf8' });
    assert.equal(packed.status, 0, packed.stderr);
    packed = spawnSync('tar', ['-czf', artifact, '-C', path.dirname(artifactStage), path.basename(artifactStage)], { encoding: 'utf8' });
    assert.equal(packed.status, 0, packed.stderr);

    fs.writeFileSync(configEnv, [
        'PANEL_DOMAIN=test.infograd.online',
        'L2TP_EXECUTION_ENABLED=true',
        'L2TP_MIGRATIONS_ENABLED=true',
        'FIXTURE_SECRET=must-not-appear',
        '',
    ].join('\n'), { mode: 0o600 });
    fs.writeFileSync(configRef, 'token=must-not-appear\n', { mode: 0o600 });
    const dockerMock = path.join(mockBin, 'docker');
    fs.writeFileSync(dockerMock, [
        '#!/bin/sh',
        'printf "%s\\n" "$*" >> "$MOCK_DOCKER_LOG"',
        'case " $* " in',
        '  *" config --services "*) printf "backend\\ncaddy\\nmongo\\nredis\\nupdater\\n" ;;',
        '  *" config --quiet "*) : ;;',
        '  *" build backend "*) : ;;',
        '  *" up -d --no-deps backend "*) : ;;',
        '  *" ps --status running --services backend "*) printf "backend\\n" ;;',
        '  *) exit 97 ;;',
        'esac',
        '',
    ].join('\n'), { mode: 0o755 });

    return {
        root,
        bundle,
        artifact,
        artifactStage,
        configEnv,
        configRef,
        dockerLog,
        env: {
            PATH: `${mockBin}:${process.env.PATH}`,
            MOCK_DOCKER_LOG: dockerLog,
        },
        args: [
            '--target', 'test',
            '--host-identity', 'test.infograd.online',
            '--install-root', '/opt/hysteria-panel',
            '--backup-root', '/opt/hysteria-panel-test-backups',
            '--source-bundle', bundle,
            '--source-bundle-sha256', sha256(bundle),
            '--expected-source-commit', sourceCommit,
            '--expected-source-tree', sourceTree,
            '--module-artifact', artifact,
            '--module-artifact-sha256', sha256(artifact),
            '--config-env-file', configEnv,
            '--config-file-ref', `config/test/worker.conf=${configRef}`,
        ],
        cleanup() {
            fs.rmSync(root, { recursive: true, force: true });
        },
    };
}

function rewriteModuleArtifact(fixture, mutateManifest) {
    const manifestPath = path.join(fixture.artifactStage, 'release-manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    mutateManifest(manifest);
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const packed = spawnSync('tar', [
        '-czf', fixture.artifact,
        '-C', path.dirname(fixture.artifactStage),
        path.basename(fixture.artifactStage),
    ], { encoding: 'utf8' });
    assert.equal(packed.status, 0, packed.stderr || packed.stdout);
}

function validateStagingInputs(fixture, extractName) {
    return spawnSync('python3', [
        validateInputsScript,
        '--source-bundle', fixture.bundle,
        '--module-artifact', fixture.artifact,
        '--config-env-file', fixture.configEnv,
        '--expected-source-commit', sourceCommit,
        '--expected-source-tree', sourceTree,
        '--extract-source', path.join(fixture.root, extractName),
    ], { cwd: repoRoot, encoding: 'utf8' });
}

function writeEnabledTestConfig(fixture, migrationValue) {
    const lines = [
        'PANEL_DOMAIN=test.infograd.online',
        'L2TP_EXECUTION_ENABLED=true',
    ];
    if (migrationValue !== undefined) {
        lines.push(`L2TP_MIGRATIONS_ENABLED=${migrationValue}`);
    }
    lines.push('');
    fs.writeFileSync(fixture.configEnv, lines.join('\n'), { mode: 0o600 });
}

function runDeployPlan(fixture) {
    const mongoDumpHook = path.join(fixture.root, 'mongo-dump-hook.sh');
    fs.writeFileSync(mongoDumpHook, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    return run(deployScript, [
        ...fixture.args,
        '--operation-id', '20260922T120000Z',
        '--mongo-dump-hook', mongoDumpHook,
        '--plan-only', 'true',
    ], { env: fixture.env });
}

function createRollbackFixture() {
    const fixture = createMinimalPrecheckFixture();
    const testFsRoot = path.join(fixture.root, 'fs-root');
    const backupId = '20260922T120000Z-aaaaaaaaaaaa';
    const logicalBackupDir = `/opt/hysteria-panel-test-backups/${backupId}`;
    const backupDir = path.join(testFsRoot, logicalBackupDir);
    const sourceStage = path.join(fixture.root, 'rollback-source');
    const hookLog = path.join(fixture.root, 'mongo-restore-hook.log');
    const mongoRestoreHook = path.join(fixture.root, 'mongo-restore-hook.sh');
    const manifestPath = path.join(backupDir, 'backup-manifest.env');
    const checksumsPath = path.join(backupDir, 'SHA256SUMS');
    const manifest = {
        schema_version: '1',
        target: 'test',
        host_identity: 'test.infograd.online',
        install_root: '/opt/hysteria-panel',
        backup_root: '/opt/hysteria-panel-test-backups',
        backup_id: backupId,
        operation_id: '20260922T120000Z',
        compose_file: 'docker-compose.yml',
        app_service: 'backend',
        deployed_source_commit: sourceCommit,
        deployed_source_tree: sourceTree,
        config_test_present: 'false',
    };
    const checksumFiles = ['backup-manifest.env', 'config.env', 'mongo.archive.gz', 'source.tar.gz'];

    fs.mkdirSync(backupDir, { recursive: true });
    fs.mkdirSync(sourceStage, { recursive: true });
    fs.copyFileSync(path.join(fixture.root, 'bundle-stage', 'source', 'docker-compose.yml'), path.join(sourceStage, 'docker-compose.yml'));
    fs.writeFileSync(path.join(sourceStage, 'index.js'), "'use strict';\n");
    const packed = spawnSync('tar', ['-czf', path.join(backupDir, 'source.tar.gz'), '-C', sourceStage, '.'], { encoding: 'utf8' });
    assert.equal(packed.status, 0, packed.stderr);
    fs.copyFileSync(fixture.configEnv, path.join(backupDir, 'config.env'));
    fs.writeFileSync(path.join(backupDir, 'mongo.archive.gz'), 'mongo-backup-fixture\n', { mode: 0o600 });
    fs.writeFileSync(mongoRestoreHook, [
        '#!/bin/sh',
        'printf "called\\n" >> "$HOOK_LOG"',
        '',
    ].join('\n'), { mode: 0o755 });

    function writeManifest(overrides = {}) {
        Object.assign(manifest, overrides);
        fs.writeFileSync(manifestPath, Object.entries(manifest)
            .map(([key, value]) => `${key}=${value}`)
            .join('\n') + '\n');
    }

    function writeChecksums(names = checksumFiles) {
        fs.writeFileSync(checksumsPath, names
            .map(name => `${sha256(path.join(backupDir, name))} *${name}`)
            .join('\n') + '\n');
    }

    function args(mode = ['--plan-only', 'true']) {
        return [
            '--target', 'test',
            '--host-identity', 'test.infograd.online',
            '--install-root', '/opt/hysteria-panel',
            '--backup-root', '/opt/hysteria-panel-test-backups',
            '--backup-dir', logicalBackupDir,
            '--backup-manifest-sha256', sha256(manifestPath),
            '--mongo-restore-hook', mongoRestoreHook,
            ...mode,
        ];
    }

    writeManifest();
    writeChecksums();
    fs.writeFileSync(path.join(backupDir, 'STATE'), 'complete\n');

    return {
        ...fixture,
        testFsRoot,
        backupId,
        logicalBackupDir,
        backupDir,
        hookLog,
        mongoRestoreHook,
        manifestPath,
        checksumsPath,
        checksumFiles,
        manifest,
        writeManifest,
        writeChecksums,
        args,
        rollbackEnv: {
            ...fixture.env,
            CELERITY_STAGING_TEST_MODE: '1',
            CELERITY_STAGING_TEST_FS_ROOT: testFsRoot,
            HOOK_LOG: hookLog,
        },
    };
}

test('source bundle builder produces deterministic archives from an exact clean commit and tree', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'celerity-bundle-builder-'));
    try {
        const gitRoot = path.join(root, 'repo');
        fs.mkdirSync(gitRoot);
        runChecked('git', ['init', '--quiet'], { cwd: gitRoot });
        runChecked('git', ['config', 'user.name', 'Staging Test'], { cwd: gitRoot });
        runChecked('git', ['config', 'user.email', 'staging-test@example.invalid'], { cwd: gitRoot });
        fs.writeFileSync(path.join(gitRoot, 'docker-compose.yml'), 'services:\n  backend:\n    build: .\n');
        fs.writeFileSync(path.join(gitRoot, 'index.js'), "'use strict';\n");
        runChecked('git', ['add', '.'], { cwd: gitRoot });
        runChecked('git', ['commit', '--quiet', '-m', 'fixture'], { cwd: gitRoot });
        const commit = runChecked('git', ['rev-parse', 'HEAD'], { cwd: gitRoot });
        const tree = runChecked('git', ['rev-parse', 'HEAD^{tree}'], { cwd: gitRoot });
        const first = path.join(root, 'first.tar.gz');
        const second = path.join(root, 'second.tar.gz');
        const args = output => [
            '--target', 'test',
            '--repo-root', gitRoot,
            '--output', output,
            '--expected-source-commit', commit,
            '--expected-source-tree', tree,
        ];

        let result = run(buildBundleScript, args(first));
        assert.equal(result.status, 0, result.stderr || result.stdout);
        result = run(buildBundleScript, args(second));
        assert.equal(result.status, 0, result.stderr || result.stdout);
        assert.equal(sha256(first), sha256(second));
        const manifest = runChecked('tar', ['-xOf', first, 'manifest.env']);
        assert.match(manifest, new RegExp(`source_commit=${commit}`));
        assert.match(manifest, new RegExp(`source_tree=${tree}`));
        assert.match(manifest, /worktree_clean=true/);
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('staging validator accepts real source and module artifacts from the same exact commit and tree', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'celerity-staging-identity-'));
    try {
        const exactSource = path.join(root, 'exact-source');
        runChecked('git', ['clone', '--quiet', '--no-local', repoRoot, exactSource]);
        const commit = runChecked('git', ['rev-parse', 'HEAD^{commit}'], { cwd: exactSource });
        const tree = runChecked('git', ['rev-parse', 'HEAD^{tree}'], { cwd: exactSource });
        const bundle = path.join(root, 'source.tar.gz');
        const artifactOutput = path.join(root, 'artifact');
        const configEnv = path.join(root, 'test.env');
        const extractedSource = path.join(root, 'extracted-source');

        let result = run(buildBundleScript, [
            '--target', 'test',
            '--repo-root', exactSource,
            '--output', bundle,
            '--expected-source-commit', commit,
            '--expected-source-tree', tree,
        ]);
        assert.equal(result.status, 0, result.stderr || result.stdout);

        result = spawnSync(process.execPath, [
            buildArtifactScript,
            '--repo-root', exactSource,
            '--output-dir', artifactOutput,
            '--source-ref', commit,
        ], { cwd: repoRoot, encoding: 'utf8' });
        assert.equal(result.status, 0, result.stderr || result.stdout);
        const built = JSON.parse(result.stdout);
        assert.deepEqual(built.source, { commit, tree });
        fs.writeFileSync(configEnv, [
            'PANEL_DOMAIN=test.infograd.online',
            'L2TP_EXECUTION_ENABLED=true',
            'L2TP_MIGRATIONS_ENABLED=true',
            '',
        ].join('\n'));

        result = spawnSync('python3', [
            validateInputsScript,
            '--source-bundle', bundle,
            '--module-artifact', built.artifactPath,
            '--config-env-file', configEnv,
            '--expected-source-commit', commit,
            '--expected-source-tree', tree,
            '--extract-source', extractedSource,
        ], { cwd: repoRoot, encoding: 'utf8' });

        assert.equal(result.status, 0, result.stderr || result.stdout);
        assert.equal(fs.existsSync(path.join(extractedSource, 'docker-compose.yml')), true);
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('staging validator rejects missing or mismatched nested source identity despite matching legacy fields', () => {
    const cases = [
        {
            name: 'missing-commit',
            source: { tree: sourceTree },
            expected: /module artifact source commit does not match/,
        },
        {
            name: 'mismatched-commit',
            source: { commit: 'c'.repeat(40), tree: sourceTree },
            expected: /module artifact source commit does not match/,
        },
        {
            name: 'missing-tree',
            source: { commit: sourceCommit },
            expected: /module artifact source tree does not match/,
        },
        {
            name: 'mismatched-tree',
            source: { commit: sourceCommit, tree: 'd'.repeat(40) },
            expected: /module artifact source tree does not match/,
        },
    ];

    for (const testCase of cases) {
        const fixture = createMinimalPrecheckFixture();
        try {
            rewriteModuleArtifact(fixture, manifest => {
                manifest.source = testCase.source;
                manifest.sourceCommit = sourceCommit;
                manifest.sourceTree = sourceTree;
            });
            const result = validateStagingInputs(fixture, `extracted-${testCase.name}`);

            assert.notEqual(result.status, 0, `${testCase.name} must be refused`);
            assert.match(result.stderr, testCase.expected);
        } finally {
            fixture.cleanup();
        }
    }
});

test('precheck requires the explicit test target guard', () => {
    const result = run(precheckScript, ['--target', 'production']);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /--target test/);
});

test('precheck refuses a production host identity', () => {
    const result = run(precheckScript, [
        '--target', 'test',
        '--host-identity', 'panel.infograd.online',
    ]);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /host identity must be exactly test\.infograd\.online/);
});

test('deploy refuses enabled execution with missing migration bootstrap before printing a plan', () => {
    const fixture = createMinimalPrecheckFixture();
    try {
        writeEnabledTestConfig(fixture, undefined);
        const result = runDeployPlan(fixture);

        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /requires L2TP_MIGRATIONS_ENABLED=true/);
        assert.doesNotMatch(result.stdout, /deploy_plan_version/);
        assert.equal(fs.existsSync(fixture.dockerLog), false, 'config rejection must happen before Compose');
    } finally {
        fixture.cleanup();
    }
});

test('deploy refuses enabled execution with migrations explicitly disabled before printing a plan', () => {
    const fixture = createMinimalPrecheckFixture();
    try {
        writeEnabledTestConfig(fixture, 'false');
        const result = runDeployPlan(fixture);

        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /requires L2TP_MIGRATIONS_ENABLED=true/);
        assert.doesNotMatch(result.stdout, /deploy_plan_version/);
        assert.equal(fs.existsSync(fixture.dockerLog), false, 'config rejection must happen before Compose');
    } finally {
        fixture.cleanup();
    }
});

test('deploy refuses non-boolean migration flags before printing a plan', () => {
    for (const value of ['', 'TRUE', 'False', '1', '0', 'yes']) {
        const fixture = createMinimalPrecheckFixture();
        try {
            writeEnabledTestConfig(fixture, value);
            const result = runDeployPlan(fixture);

            assert.notEqual(result.status, 0, `L2TP_MIGRATIONS_ENABLED=${value}`);
            assert.match(result.stderr, /requires L2TP_MIGRATIONS_ENABLED=true exactly/);
            assert.doesNotMatch(result.stdout, /deploy_plan_version/);
            assert.equal(fs.existsSync(fixture.dockerLog), false, 'config rejection must happen before Compose');
        } finally {
            fixture.cleanup();
        }
    }
});

test('precheck rejects a source bundle checksum mismatch before extraction', () => {
    const fixture = createMinimalPrecheckFixture();
    try {
        const args = [...fixture.args];
        args[args.indexOf('--source-bundle-sha256') + 1] = '0'.repeat(64);
        const result = run(precheckScript, args);

        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /source bundle checksum mismatch/);
        assert.doesNotMatch(`${result.stdout}${result.stderr}`, /must-not-appear/);
    } finally {
        fixture.cleanup();
    }
});

test('precheck validates the pinned clean bundle, module artifact, compose layout, and test config', () => {
    const fixture = createMinimalPrecheckFixture();
    try {
        const result = run(precheckScript, fixture.args, { env: fixture.env });

        assert.equal(result.status, 0, result.stderr || result.stdout);
        assert.match(result.stdout, /precheck ok/);
        assert.doesNotMatch(`${result.stdout}${result.stderr}`, /must-not-appear/);
        assert.match(fs.readFileSync(fixture.dockerLog, 'utf8'), /config --services/);
    } finally {
        fixture.cleanup();
    }
});

test('deploy plan is deterministic, backs up source config and Mongo, and scopes restart to backend', () => {
    const fixture = createMinimalPrecheckFixture();
    try {
        const hookLog = path.join(fixture.root, 'mongo-dump-hook.log');
        const mongoDumpHook = path.join(fixture.root, 'mongo-dump-hook.sh');
        fs.writeFileSync(mongoDumpHook, [
            '#!/bin/sh',
            'printf "called\\n" >> "$HOOK_LOG"',
            ': > "$MONGO_DUMP_OUTPUT"',
            '',
        ].join('\n'), { mode: 0o755 });
        const args = [
            ...fixture.args,
            '--operation-id', '20260922T120000Z',
            '--mongo-dump-hook', mongoDumpHook,
            '--plan-only', 'true',
        ];
        const env = { ...fixture.env, HOOK_LOG: hookLog };

        const first = run(deployScript, args, { env });
        const second = run(deployScript, args, { env });
        assert.equal(first.status, 0, first.stderr || first.stdout);
        assert.equal(second.status, 0, second.stderr || second.stdout);
        assert.equal(first.stdout, second.stdout);
        assert.match(first.stdout, /backup_dir=\/opt\/hysteria-panel-test-backups\/20260922T120000Z-aaaaaaaaaaaa/);
        assert.match(first.stdout, /backup_steps=source,config,mongo/);
        assert.match(first.stdout, /container_build=backend/);
        assert.match(first.stdout, /container_restart=backend --no-deps/);
        assert.match(first.stdout, /node_mutation=none/);
        assert.match(first.stdout, /health_template=.*ps backend/);
        assert.doesNotMatch(first.stdout, /must-not-appear/);
        assert.equal(fs.existsSync(hookLog), false, 'plan-only must not execute the Mongo hook');
        const dockerCalls = fs.readFileSync(fixture.dockerLog, 'utf8');
        assert.doesNotMatch(dockerCalls, /\b(?:build|up|restart|exec)\b/);
    } finally {
        fixture.cleanup();
    }
});

test('rollback plan validates one exact backup and restores only the scoped backend service', () => {
    const fixture = createRollbackFixture();
    try {
        const first = run(rollbackScript, fixture.args(), { env: fixture.rollbackEnv });
        const second = run(rollbackScript, fixture.args(), { env: fixture.rollbackEnv });
        assert.equal(first.status, 0, first.stderr || first.stdout);
        assert.equal(second.status, 0, second.stderr || second.stdout);
        assert.equal(first.stdout, second.stdout);
        assert.match(first.stdout, new RegExp(`backup_dir=${fixture.logicalBackupDir}`));
        assert.match(first.stdout, /restore_steps=source,config,mongo/);
        assert.match(first.stdout, /container_restart=backend --no-deps/);
        assert.match(first.stdout, /node_mutation=none/);
        assert.match(first.stdout, /health_template=.*ps backend/);
        assert.doesNotMatch(first.stdout, /must-not-appear/);
        assert.equal(fs.existsSync(fixture.hookLog), false, 'plan-only must not execute the Mongo restore hook');
        assert.equal(fs.existsSync(fixture.dockerLog), false, 'rollback plan must not invoke Docker');
    } finally {
        fixture.cleanup();
    }
});

test('rollback refuses production identities and non-test control paths before reading a backup', () => {
    const cases = [
        ['--target', 'production', /--target test/],
        ['--host-identity', 'panel.infograd.online', /host identity must be exactly test\.infograd\.online/],
        ['--install-root', '/opt/hysteria-panel-production', /install root must be exactly \/opt\/hysteria-panel/],
        ['--backup-root', '/opt/hysteria-panel-backups', /backup root must be exactly \/opt\/hysteria-panel-test-backups/],
    ];

    for (const [flag, value, expectedError] of cases) {
        const fixture = createRollbackFixture();
        try {
            const args = fixture.args();
            args[args.indexOf(flag) + 1] = value;
            const result = run(rollbackScript, args, { env: fixture.rollbackEnv });
            assert.notEqual(result.status, 0, `${flag}=${value} must be refused`);
            assert.match(result.stderr, expectedError);
            assert.equal(fs.existsSync(fixture.hookLog), false);
            assert.equal(fs.existsSync(fixture.dockerLog), false);
        } finally {
            fixture.cleanup();
        }
    }
});

test('rollback rejects backup traversal and backup directories outside the exact test backup root', () => {
    const fixture = createRollbackFixture();
    try {
        const unsafePaths = [
            `/opt/hysteria-panel-test-backups/../production-backups/${fixture.backupId}`,
            `${fixture.logicalBackupDir}/nested`,
            `/opt/hysteria-panel-test-backups/${fixture.backupId}/..`,
        ];
        for (const unsafePath of unsafePaths) {
            const args = fixture.args();
            args[args.indexOf('--backup-dir') + 1] = unsafePath;
            const result = run(rollbackScript, args, { env: fixture.rollbackEnv });
            assert.notEqual(result.status, 0, unsafePath);
            assert.match(result.stderr, /backup directory must be one exact timestamped child/);
        }
        assert.equal(fs.existsSync(fixture.hookLog), false);
        assert.equal(fs.existsSync(fixture.dockerLog), false);
    } finally {
        fixture.cleanup();
    }
});

test('rollback rejects a test filesystem prefix symlink that escapes the isolated root', () => {
    const fixture = createRollbackFixture();
    try {
        const mappedOpt = path.join(fixture.testFsRoot, 'opt');
        const escapedOpt = path.join(fixture.root, 'escaped-opt');
        fs.renameSync(mappedOpt, escapedOpt);
        fs.symlinkSync(escapedOpt, mappedOpt, 'dir');

        const result = run(rollbackScript, fixture.args(), { env: fixture.rollbackEnv });
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /test filesystem path escaped its isolated root/);
        assert.equal(fs.existsSync(fixture.hookLog), false);
        assert.equal(fs.existsSync(fixture.dockerLog), false);
    } finally {
        fixture.cleanup();
    }
});

test('rollback rejects a checksum-valid manifest whose test identity does not match', () => {
    const fixture = createRollbackFixture();
    try {
        fixture.writeManifest({ host_identity: 'panel.infograd.online' });
        fixture.writeChecksums();
        const result = run(rollbackScript, fixture.args(), { env: fixture.rollbackEnv });

        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /backup manifest host identity does not match/);
        assert.equal(fs.existsSync(fixture.hookLog), false);
        assert.equal(fs.existsSync(fixture.dockerLog), false);
    } finally {
        fixture.cleanup();
    }
});

test('rollback rejects missing, mismatched, and traversal checksum references before execution', () => {
    const cases = [
        {
            mutate(fixture) {
                fs.rmSync(path.join(fixture.backupDir, 'mongo.archive.gz'));
            },
            expected: /Mongo backup must reference a non-empty regular file/,
        },
        {
            mutate(fixture) {
                fs.appendFileSync(path.join(fixture.backupDir, 'source.tar.gz'), 'tampered');
            },
            expected: /source backup checksum mismatch/,
        },
        {
            mutate(fixture) {
                fs.writeFileSync(path.join(fixture.backupDir, 'config.env'), [
                    'PANEL_DOMAIN=panel.infograd.online',
                    'L2TP_EXECUTION_ENABLED=true',
                    '',
                ].join('\n'));
                fixture.writeChecksums();
            },
            expected: /config backup PANEL_DOMAIN must match the test host exactly once/,
        },
        {
            mutate(fixture) {
                fs.appendFileSync(fixture.checksumsPath, `${'0'.repeat(64)} *..\/production.env\n`);
            },
            expected: /unsafe or invalid backup checksum reference/,
        },
    ];

    for (const { mutate, expected } of cases) {
        const fixture = createRollbackFixture();
        try {
            mutate(fixture);
            const result = run(rollbackScript, fixture.args(), { env: fixture.rollbackEnv });
            assert.notEqual(result.status, 0);
            assert.match(result.stderr, expected);
            assert.equal(fs.existsSync(fixture.hookLog), false);
            assert.equal(fs.existsSync(fixture.dockerLog), false);
        } finally {
            fixture.cleanup();
        }
    }
});

test('rollback execute restores source config and Mongo before touching only backend', () => {
    const fixture = createRollbackFixture();
    try {
        const configBackupStage = path.join(fixture.root, 'rollback-config');
        fs.mkdirSync(path.join(configBackupStage, 'test'), { recursive: true });
        fs.writeFileSync(path.join(configBackupStage, 'test', 'worker.conf'), 'restored-test-config\n', { mode: 0o600 });
        const configPacked = spawnSync('tar', [
            '-czf', path.join(fixture.backupDir, 'config-test.tar.gz'),
            '-C', configBackupStage,
            'test',
        ], { encoding: 'utf8' });
        assert.equal(configPacked.status, 0, configPacked.stderr);
        fixture.writeManifest({ config_test_present: 'true' });
        fixture.writeChecksums([...fixture.checksumFiles, 'config-test.tar.gz']);

        const installDir = path.join(fixture.testFsRoot, '/opt/hysteria-panel');
        fs.mkdirSync(path.join(installDir, 'config', 'test'), { recursive: true });
        fs.writeFileSync(path.join(installDir, 'docker-compose.yml'), 'old source\n');
        fs.writeFileSync(path.join(installDir, '.env'), 'OLD_SECRET=must-not-appear\n', { mode: 0o600 });
        fs.writeFileSync(path.join(installDir, 'config', 'test', 'obsolete.conf'), 'obsolete\n');
        fs.writeFileSync(path.join(installDir, 'obsolete.js'), "'use strict';\n");

        const result = run(rollbackScript, fixture.args(['--execute', 'true']), { env: fixture.rollbackEnv });
        assert.equal(result.status, 0, result.stderr || result.stdout);
        assert.match(result.stdout, /rollback ok/);
        assert.doesNotMatch(`${result.stdout}${result.stderr}`, /must-not-appear/);
        assert.equal(fs.readFileSync(fixture.hookLog, 'utf8'), 'called\n');
        assert.equal(fs.existsSync(path.join(installDir, 'obsolete.js')), false);
        assert.equal(fs.existsSync(path.join(installDir, 'config', 'test', 'obsolete.conf')), false);
        assert.equal(
            fs.readFileSync(path.join(installDir, 'config', 'test', 'worker.conf'), 'utf8'),
            'restored-test-config\n',
        );
        assert.equal(sha256(path.join(installDir, '.env')), sha256(path.join(fixture.backupDir, 'config.env')));

        const dockerCalls = fs.readFileSync(fixture.dockerLog, 'utf8');
        assert.match(dockerCalls, /build backend/);
        assert.match(dockerCalls, /up -d --no-deps backend/);
        assert.match(dockerCalls, /ps --status running --services backend/);
        assert.doesNotMatch(dockerCalls, /(?:build|up -d|restart) (?:caddy|mongo|redis|updater)/);
    } finally {
        fixture.cleanup();
    }
});
