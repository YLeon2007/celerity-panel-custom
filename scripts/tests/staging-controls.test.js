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

function readEnvFile(filePath) {
    return Object.fromEntries(fs.readFileSync(filePath, 'utf8').trimEnd().split('\n')
        .map(line => line.split(/=(.*)/s, 2)));
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
    const commandLog = path.join(root, 'commands.log');
    const dockerState = path.join(root, 'docker-state');
    const untouchedServices = ['mongo', 'redis', 'caddy', 'updater'];
    const untouchedState = Object.fromEntries(untouchedServices.map((service, index) => [service, {
        id: String(index + 1).repeat(64),
        restartCount: String(index),
    }]));

    fs.mkdirSync(sourceRoot, { recursive: true });
    fs.mkdirSync(artifactStage, { recursive: true });
    fs.mkdirSync(mockBin, { recursive: true });
    fs.mkdirSync(dockerState, { recursive: true });
    for (const [service, state] of Object.entries(untouchedState)) {
        fs.writeFileSync(path.join(dockerState, `${service}.id`), `${state.id}\n`);
        fs.writeFileSync(path.join(dockerState, `${service}.restart`), `${state.restartCount}\n`);
    }
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
        '[ -z "${MOCK_COMMAND_LOG:-}" ] || printf "docker %s\\n" "$*" >> "$MOCK_COMMAND_LOG"',
        'project_directory=',
        'config_env_file=',
        'previous=',
        'for argument do',
        '  case "$previous" in',
        '    project-directory) project_directory=$argument ;;',
        '    env-file) config_env_file=$argument ;;',
        '  esac',
        '  case "$argument" in',
        '    --project-directory) previous=project-directory ;;',
        '    --env-file) previous=env-file ;;',
        '    *) previous= ;;',
        '  esac',
        'done',
        'if [ "${MOCK_REQUIRE_SERVICE_ENV:-0}" = 1 ]; then',
        '  case " $* " in',
        '    *" config --quiet "*|*" config --services "*)',
        '      service_env_file=$project_directory/.env',
        '      [ -f "$config_env_file" ] || exit 94',
        '      [ -f "$service_env_file" ] || exit 95',
        '      service_env_mode=$(stat -c %a "$service_env_file") || exit 96',
        '      [ "$service_env_mode" = 600 ] || exit 97',
        '      cmp -s "$config_env_file" "$service_env_file" || exit 98',
        '      printf "service-env=%s mode=%s\\n" "$service_env_file" "$service_env_mode" >> "$MOCK_DOCKER_LOG"',
        '      ;;',
        '  esac',
        'fi',
        'if [ "${1:-}" = "inspect" ]; then',
        '  [ "$#" -eq 4 ] || exit 96',
        '  [ "$2" = "--format" ] || exit 96',
        '  [ "$3" = "{{.Id}} {{.RestartCount}}" ] || exit 96',
        '  container_id=$4',
        '  for service in mongo redis caddy updater; do',
        '    current_id=$(tr -d "\\n" < "$MOCK_DOCKER_STATE/$service.id")',
        '    if [ "$container_id" = "$current_id" ]; then',
        '      restart_count=$(tr -d "\\n" < "$MOCK_DOCKER_STATE/$service.restart")',
        '      printf "%s %s\\n" "$current_id" "$restart_count"',
        '      exit 0',
        '    fi',
        '  done',
        '  exit 96',
        'fi',
        'case " $* " in',
        '  *" config --services "*) printf "backend\\ncaddy\\nmongo\\nredis\\nupdater\\n" ;;',
        '  *" config --quiet "*) : ;;',
        '  *" build backend "*) : ;;',
        '  *" up -d --no-deps backend "*)',
        '    case "${MOCK_MUTATE_SERVICE:-}" in',
        '      mongo|redis|caddy|updater)',
        '        [ -z "${MOCK_AFTER_ID:-}" ] || printf "%s\\n" "$MOCK_AFTER_ID" > "$MOCK_DOCKER_STATE/$MOCK_MUTATE_SERVICE.id"',
        '        [ -z "${MOCK_AFTER_RESTART_COUNT:-}" ] || printf "%s\\n" "$MOCK_AFTER_RESTART_COUNT" > "$MOCK_DOCKER_STATE/$MOCK_MUTATE_SERVICE.restart"',
        '        ;;',
        '      "") : ;;',
        '      *) exit 96 ;;',
        '    esac',
        '    ;;',
        '  *" ps --status running --services backend "*)',
        '    if [ -n "${MOCK_BACKEND_RUNNING_OUTPUT+x}" ]; then',
        '      printf "%s" "$MOCK_BACKEND_RUNNING_OUTPUT"',
        '    else',
        '      printf "backend\\n"',
        '    fi',
        '    ;;',
        '  *" ps --status running --quiet "*)',
        '    service=',
        '    for argument in "$@"; do service=$argument; done',
        '    case "$service" in mongo|redis|caddy|updater) ;; *) exit 96 ;; esac',
        '    [ -s "$MOCK_DOCKER_STATE/$service.id" ] || exit 96',
        '    cat "$MOCK_DOCKER_STATE/$service.id"',
        '    ;;',
        '  *) exit 97 ;;',
        'esac',
        '',
    ].join('\n'), { mode: 0o755 });
    const curlMock = path.join(mockBin, 'curl');
    fs.writeFileSync(curlMock, [
        '#!/bin/sh',
        'printf "curl %s\\n" "$*" >> "$MOCK_COMMAND_LOG"',
        '[ "$#" -eq 6 ] || exit 98',
        '[ "$1" = "--fail" ] || exit 98',
        '[ "$2" = "--silent" ] || exit 98',
        '[ "$3" = "--show-error" ] || exit 98',
        '[ "$4" = "--max-time" ] || exit 98',
        '[ "$5" = "10" ] || exit 98',
        '[ "$6" = "https://test.infograd.online/health" ] || exit 98',
        'exit "${MOCK_CURL_EXIT:-0}"',
        '',
    ].join('\n'), { mode: 0o755 });
    const rsyncMock = path.join(mockBin, 'rsync');
    const realRsync = runChecked('sh', ['-c', 'command -v rsync']);
    fs.writeFileSync(rsyncMock, [
        '#!/bin/sh',
        '[ -z "${MOCK_COMMAND_LOG:-}" ] || printf "rsync %s\\n" "$*" >> "$MOCK_COMMAND_LOG"',
        'exec "$MOCK_REAL_RSYNC" "$@"',
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
        commandLog,
        dockerState,
        untouchedServices,
        untouchedState,
        env: {
            PATH: `${mockBin}:${process.env.PATH}`,
            MOCK_DOCKER_LOG: dockerLog,
            MOCK_COMMAND_LOG: commandLog,
            MOCK_DOCKER_STATE: dockerState,
            MOCK_REAL_RSYNC: realRsync,
            MOCK_REQUIRE_SERVICE_ENV: '1',
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

function createDeployExecuteFixture() {
    const fixture = createMinimalPrecheckFixture();
    const testFsRoot = path.join(fixture.root, 'fs-root');
    const installDir = path.join(testFsRoot, '/opt/hysteria-panel');
    const backupRootDir = path.join(testFsRoot, '/opt/hysteria-panel-test-backups');
    const hookLog = path.join(fixture.root, 'mongo-dump-hook.log');
    const mongoDumpHook = path.join(fixture.root, 'mongo-dump-hook.sh');

    fs.mkdirSync(path.join(installDir, 'config', 'test'), { recursive: true });
    fs.mkdirSync(backupRootDir, { recursive: true });
    fs.copyFileSync(
        path.join(fixture.root, 'bundle-stage', 'source', 'docker-compose.yml'),
        path.join(installDir, 'docker-compose.yml'),
    );
    fs.copyFileSync(fixture.configEnv, path.join(installDir, '.env'));
    fs.writeFileSync(path.join(installDir, 'old.js'), "'use strict';\n");
    fs.writeFileSync(path.join(installDir, 'config', 'test', 'old.conf'), 'old-test-config\n');
    runChecked('git', ['init', '--quiet'], { cwd: installDir });
    runChecked('git', ['config', 'user.name', 'Staging Test'], { cwd: installDir });
    runChecked('git', ['config', 'user.email', 'staging-test@example.invalid'], { cwd: installDir });
    fs.writeFileSync(path.join(installDir, '.git', 'info', 'exclude'), [
        '.env',
        '.celerity-staging-source.env',
        'config/test/',
        '',
    ].join('\n'));
    runChecked('git', ['add', 'docker-compose.yml', 'old.js'], { cwd: installDir });
    runChecked('git', ['commit', '--quiet', '-m', 'predeploy baseline'], { cwd: installDir });
    const baselineCommit = runChecked('git', ['rev-parse', 'HEAD^{commit}'], { cwd: installDir });
    const baselineTree = runChecked('git', ['rev-parse', 'HEAD^{tree}'], { cwd: installDir });
    fs.writeFileSync(mongoDumpHook, [
        '#!/bin/sh',
        'printf "called\\n" >> "$HOOK_LOG"',
        'printf "mongo-backup\\n" > "$MONGO_DUMP_OUTPUT"',
        '',
    ].join('\n'), { mode: 0o755 });

    return {
        ...fixture,
        testFsRoot,
        installDir,
        backupRootDir,
        baselineCommit,
        baselineTree,
        hookLog,
        mongoDumpHook,
        deployArgs: [
            ...fixture.args,
            '--operation-id', '20260922T120000Z',
            '--mongo-dump-hook', mongoDumpHook,
            '--execute', 'true',
        ],
        deployEnv: {
            ...fixture.env,
            CELERITY_STAGING_TEST_MODE: '1',
            CELERITY_STAGING_TEST_FS_ROOT: testFsRoot,
            HOOK_LOG: hookLog,
        },
    };
}

function createRollbackFixture() {
    const fixture = createMinimalPrecheckFixture();
    const testFsRoot = path.join(fixture.root, 'fs-root');
    const sourceStage = path.join(fixture.root, 'rollback-source');
    const hookLog = path.join(fixture.root, 'mongo-restore-hook.log');
    const mongoRestoreHook = path.join(fixture.root, 'mongo-restore-hook.sh');

    fs.mkdirSync(sourceStage, { recursive: true });
    fs.copyFileSync(path.join(fixture.root, 'bundle-stage', 'source', 'docker-compose.yml'), path.join(sourceStage, 'docker-compose.yml'));
    fs.writeFileSync(path.join(sourceStage, 'index.js'), "'use strict';\n");
    fs.writeFileSync(path.join(sourceStage, '.gitignore'), [
        '.env',
        '.celerity-staging-source.env',
        'config/test/',
        '',
    ].join('\n'));
    runChecked('git', ['init', '--quiet'], { cwd: sourceStage });
    runChecked('git', ['config', 'user.name', 'Staging Test'], { cwd: sourceStage });
    runChecked('git', ['config', 'user.email', 'staging-test@example.invalid'], { cwd: sourceStage });
    runChecked('git', ['add', '.'], { cwd: sourceStage });
    runChecked('git', ['commit', '--quiet', '-m', 'recorded rollback baseline'], { cwd: sourceStage });
    const deployedSourceCommit = runChecked('git', ['rev-parse', 'HEAD^{commit}'], { cwd: sourceStage });
    const deployedSourceTree = runChecked('git', ['rev-parse', 'HEAD^{tree}'], { cwd: sourceStage });
    const backupId = `20260922T120000Z-${deployedSourceCommit.slice(0, 12)}`;
    const logicalBackupDir = `/opt/hysteria-panel-test-backups/${backupId}`;
    const backupDir = path.join(testFsRoot, logicalBackupDir);
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
        deployed_source_commit: deployedSourceCommit,
        deployed_source_tree: deployedSourceTree,
        config_test_present: 'false',
    };
    const checksumFiles = ['backup-manifest.env', 'config.env', 'mongo.archive.gz', 'source.tar.gz'];

    fs.mkdirSync(backupDir, { recursive: true });
    const packed = spawnSync('tar', [
        '--exclude=./.git',
        '-czf', path.join(backupDir, 'source.tar.gz'),
        '-C', sourceStage,
        '.',
    ], { encoding: 'utf8' });
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
        sourceStage,
        deployedSourceCommit,
        deployedSourceTree,
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

function prepareRollbackInstall(fixture) {
    const installDir = path.join(fixture.testFsRoot, '/opt/hysteria-panel');
    runChecked('git', ['clone', '--quiet', '--no-local', fixture.sourceStage, installDir]);
    fs.writeFileSync(path.join(installDir, 'docker-compose.yml'), 'candidate source\n');
    fs.writeFileSync(path.join(installDir, '.env'), 'OLD_SECRET=must-not-appear\n', { mode: 0o600 });
    fs.writeFileSync(path.join(installDir, 'obsolete.js'), "'use strict';\n");
    return installDir;
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
        const dockerCalls = fs.readFileSync(fixture.dockerLog, 'utf8');
        assert.match(dockerCalls, /config --services/);
        const temporaryEnvs = [...dockerCalls.matchAll(/^service-env=(.+) mode=(\d+)$/gm)];
        assert.equal(temporaryEnvs.length, 2, dockerCalls);
        for (const [, serviceEnv, mode] of temporaryEnvs) {
            assert.equal(mode, '600');
            assert.notEqual(serviceEnv, fixture.configEnv, '--env-file must not substitute service env_file');
            assert.equal(fs.existsSync(serviceEnv), false, 'temporary Compose env must be cleaned up');
        }
        const archiveEntries = runChecked('tar', ['-tzf', fixture.bundle]).split('\n');
        assert.equal(archiveEntries.includes('source/.env'), false, 'temporary Compose env must not enter source bundle');
    } finally {
        fixture.cleanup();
    }
});

test('deploy execute honors the guarded isolated test filesystem', () => {
    const fixture = createDeployExecuteFixture();
    try {
        const result = run(deployScript, fixture.deployArgs, { env: fixture.deployEnv });

        assert.equal(result.status, 0, result.stderr || result.stdout);
        assert.match(result.stdout, /deploy ok/);
        assert.doesNotMatch(`${result.stdout}${result.stderr}`, /must-not-appear/);
        assert.equal(fs.readFileSync(fixture.hookLog, 'utf8'), 'called\n');
        assert.equal(fs.existsSync(path.join(fixture.installDir, 'old.js')), false);
    } finally {
        fixture.cleanup();
    }
});

test('deploy backup provenance uses the clean predeploy Git baseline instead of the candidate', () => {
    const fixture = createDeployExecuteFixture();
    try {
        assert.notEqual(fixture.baselineCommit, sourceCommit);
        assert.notEqual(fixture.baselineTree, sourceTree);

        const result = run(deployScript, fixture.deployArgs, { env: fixture.deployEnv });
        assert.equal(result.status, 0, result.stderr || result.stdout);

        const backupId = `20260922T120000Z-${fixture.baselineCommit.slice(0, 12)}`;
        const backupDir = path.join(fixture.backupRootDir, backupId);
        assert.match(result.stdout, new RegExp(`backup_dir=/opt/hysteria-panel-test-backups/${backupId}`));
        const manifest = readEnvFile(path.join(backupDir, 'backup-manifest.env'));
        assert.equal(manifest.backup_id, backupId);
        assert.equal(manifest.deployed_source_commit, fixture.baselineCommit);
        assert.equal(manifest.deployed_source_tree, fixture.baselineTree);

        const archivedBaseline = runChecked('tar', ['-xOf', path.join(backupDir, 'source.tar.gz'), './old.js']);
        assert.equal(archivedBaseline, "'use strict';");
        const marker = readEnvFile(path.join(fixture.installDir, '.celerity-staging-source.env'));
        assert.equal(marker.candidate_source_commit, sourceCommit);
        assert.equal(marker.candidate_source_tree, sourceTree);
        assert.equal(marker.candidate_source_bundle_sha256, sha256(fixture.bundle));
        assert.equal(marker.candidate_module_artifact_sha256, sha256(fixture.artifact));
    } finally {
        fixture.cleanup();
    }
});

test('deploy rejects an untracked source file before creating the baseline backup', () => {
    const fixture = createDeployExecuteFixture();
    try {
        fs.writeFileSync(path.join(fixture.installDir, 'rogue-source.js'), "'use strict';\n");

        const result = run(deployScript, fixture.deployArgs, { env: fixture.deployEnv });
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /installed source must be clean before backup/);
        assert.equal(fs.existsSync(fixture.hookLog), false, 'dirty baseline must be rejected before Mongo backup');
        const backupEntries = fs.readdirSync(fixture.backupRootDir);
        assert.deepEqual(backupEntries, []);
        const calls = fs.readFileSync(fixture.commandLog, 'utf8');
        assert.doesNotMatch(calls, /^rsync /m, 'dirty baseline must be rejected before replacement');
    } finally {
        fixture.cleanup();
    }
});

test('deploy rejects Git metadata symlinks before trusting the predeploy identity', () => {
    const fixture = createDeployExecuteFixture();
    try {
        const gitMetadata = path.join(fixture.installDir, '.git');
        const externalGitMetadata = path.join(fixture.root, 'external-git-metadata');
        fs.renameSync(gitMetadata, externalGitMetadata);
        fs.symlinkSync(externalGitMetadata, gitMetadata, 'dir');

        const result = run(deployScript, fixture.deployArgs, { env: fixture.deployEnv });
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /installed source Git metadata must be a real directory/);
        assert.equal(fs.existsSync(fixture.hookLog), false);
        assert.deepEqual(fs.readdirSync(fixture.backupRootDir), []);
    } finally {
        fixture.cleanup();
    }
});

test('deploy rejects a symlinked Git HEAD before trusting the predeploy identity', () => {
    const fixture = createDeployExecuteFixture();
    try {
        const gitHead = path.join(fixture.installDir, '.git', 'HEAD');
        const externalHead = path.join(fixture.root, 'external-git-head');
        fs.renameSync(gitHead, externalHead);
        fs.symlinkSync(externalHead, gitHead);

        const result = run(deployScript, fixture.deployArgs, { env: fixture.deployEnv });
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /installed source Git HEAD must be a regular file/);
        assert.equal(fs.existsSync(fixture.hookLog), false);
        assert.deepEqual(fs.readdirSync(fixture.backupRootDir), []);
    } finally {
        fixture.cleanup();
    }
});

test('deploy rejects a symlinked Git HEAD reference before trusting the predeploy identity', () => {
    const fixture = createDeployExecuteFixture();
    try {
        const headReference = runChecked('git', ['symbolic-ref', 'HEAD'], { cwd: fixture.installDir });
        const referencePath = path.join(fixture.installDir, '.git', ...headReference.split('/'));
        const externalReference = path.join(fixture.root, 'external-git-reference');
        fs.renameSync(referencePath, externalReference);
        fs.symlinkSync(externalReference, referencePath);

        const result = run(deployScript, fixture.deployArgs, { env: fixture.deployEnv });
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /installed source Git HEAD reference must be a regular file/);
        assert.equal(fs.existsSync(fixture.hookLog), false);
        assert.deepEqual(fs.readdirSync(fixture.backupRootDir), []);
    } finally {
        fixture.cleanup();
    }
});

test('deploy rejects path traversal in the Git HEAD reference', () => {
    const fixture = createDeployExecuteFixture();
    try {
        fs.writeFileSync(path.join(fixture.installDir, '.git', 'HEAD'), 'ref: refs/heads/../../external-ref\n');
        fs.writeFileSync(path.join(fixture.installDir, '.git', 'external-ref'), `${fixture.baselineCommit}\n`);

        const result = run(deployScript, fixture.deployArgs, { env: fixture.deployEnv });
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /installed source Git HEAD reference is unsafe/);
        assert.equal(fs.existsSync(fixture.hookLog), false);
        assert.deepEqual(fs.readdirSync(fixture.backupRootDir), []);
    } finally {
        fixture.cleanup();
    }
});

test('deploy rejects symlinks in the Git HEAD reference path', () => {
    const fixture = createDeployExecuteFixture();
    try {
        const refsPath = path.join(fixture.installDir, '.git', 'refs');
        const externalRefs = path.join(fixture.root, 'external-git-refs');
        fs.renameSync(refsPath, externalRefs);
        fs.symlinkSync(externalRefs, refsPath, 'dir');

        const result = run(deployScript, fixture.deployArgs, { env: fixture.deployEnv });
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /installed source Git HEAD reference path must use real directories/);
        assert.equal(fs.existsSync(fixture.hookLog), false);
        assert.deepEqual(fs.readdirSync(fixture.backupRootDir), []);
    } finally {
        fixture.cleanup();
    }
});

test('deploy rejects symlinked packed refs used by Git HEAD', () => {
    const fixture = createDeployExecuteFixture();
    try {
        runChecked('git', ['pack-refs', '--all', '--prune'], { cwd: fixture.installDir });
        const packedRefs = path.join(fixture.installDir, '.git', 'packed-refs');
        const externalPackedRefs = path.join(fixture.root, 'external-packed-refs');
        fs.renameSync(packedRefs, externalPackedRefs);
        fs.symlinkSync(externalPackedRefs, packedRefs);

        const result = run(deployScript, fixture.deployArgs, { env: fixture.deployEnv });
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /installed source Git packed references must be a regular file/);
        assert.equal(fs.existsSync(fixture.hookLog), false);
        assert.deepEqual(fs.readdirSync(fixture.backupRootDir), []);
    } finally {
        fixture.cleanup();
    }
});

test('deploy checks public HTTPS health with fixed curl semantics after backend update', () => {
    const fixture = createDeployExecuteFixture();
    try {
        const result = run(deployScript, fixture.deployArgs, { env: fixture.deployEnv });
        assert.equal(result.status, 0, result.stderr || result.stdout);

        const calls = fs.readFileSync(fixture.commandLog, 'utf8').trim().split('\n');
        const backendUpdate = calls.findIndex(call => call.includes(' up -d --no-deps backend'));
        const backendRunning = calls.findIndex(call => call.includes(' ps --status running --services backend'));
        const publicHealth = calls.indexOf(
            'curl --fail --silent --show-error --max-time 10 https://test.infograd.online/health',
        );
        assert.ok(backendUpdate >= 0, 'backend update command must be executed');
        assert.ok(backendRunning > backendUpdate, 'backend running check must follow its update');
        assert.ok(publicHealth > backendRunning, 'public HTTPS health must follow the backend running check');
    } finally {
        fixture.cleanup();
    }
});

test('deploy snapshots and rechecks untouched container identities and restart counts', () => {
    const fixture = createDeployExecuteFixture();
    try {
        const result = run(deployScript, fixture.deployArgs, { env: fixture.deployEnv });
        assert.equal(result.status, 0, result.stderr || result.stdout);

        const calls = fs.readFileSync(fixture.commandLog, 'utf8').trim().split('\n');
        const sourceReplacement = calls.findIndex(call => call.startsWith('rsync --archive --delete '));
        const backendUpdate = calls.findIndex(call => call.includes(' up -d --no-deps backend'));
        const publicHealth = calls.indexOf(
            'curl --fail --silent --show-error --max-time 10 https://test.infograd.online/health',
        );
        assert.ok(sourceReplacement >= 0, 'source replacement must be executed');
        assert.ok(backendUpdate > sourceReplacement, 'backend update must follow source replacement');
        assert.ok(publicHealth > backendUpdate, 'public health must follow backend update');

        for (const service of fixture.untouchedServices) {
            const expected = fixture.untouchedState[service];
            const psSuffix = ` ps --status running --quiet ${service}`;
            const psCalls = calls
                .map((call, index) => ({ call, index }))
                .filter(entry => entry.call.endsWith(psSuffix));
            const inspectCall = `docker inspect --format {{.Id}} {{.RestartCount}} ${expected.id}`;
            const inspectCalls = calls
                .map((call, index) => ({ call, index }))
                .filter(entry => entry.call === inspectCall);

            assert.equal(psCalls.length, 2, `${service} identity must be queried before and after`);
            assert.equal(inspectCalls.length, 2, `${service} restart count must be inspected before and after`);
            assert.ok(psCalls[0].index < sourceReplacement, `${service} identity must be captured before source replacement`);
            assert.ok(inspectCalls[0].index < sourceReplacement, `${service} restart count must be captured before source replacement`);
            assert.ok(psCalls[1].index > publicHealth, `${service} identity must be rechecked after public health`);
            assert.ok(inspectCalls[1].index > publicHealth, `${service} restart count must be rechecked after public health`);
        }
    } finally {
        fixture.cleanup();
    }
});

test('deploy fails closed when an untouched service is missing before replacement', () => {
    const fixture = createDeployExecuteFixture();
    try {
        fs.writeFileSync(path.join(fixture.dockerState, 'mongo.id'), '');
        const result = run(deployScript, fixture.deployArgs, { env: fixture.deployEnv });

        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /untouched service mongo is not running/);
        assert.doesNotMatch(result.stdout, /deploy ok/);
        const calls = fs.readFileSync(fixture.commandLog, 'utf8');
        assert.doesNotMatch(calls, /^rsync /m, 'source replacement must not start without the snapshot');
    } finally {
        fixture.cleanup();
    }
});

test('deploy fails closed when an untouched service container identity changes', () => {
    const fixture = createDeployExecuteFixture();
    try {
        const result = run(deployScript, fixture.deployArgs, {
            env: {
                ...fixture.deployEnv,
                MOCK_MUTATE_SERVICE: 'mongo',
                MOCK_AFTER_ID: '9'.repeat(64),
            },
        });

        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /untouched service mongo container identity changed/);
        assert.doesNotMatch(result.stdout, /deploy ok/);
    } finally {
        fixture.cleanup();
    }
});

test('deploy fails closed when an untouched service restart count changes', () => {
    const fixture = createDeployExecuteFixture();
    try {
        const result = run(deployScript, fixture.deployArgs, {
            env: {
                ...fixture.deployEnv,
                MOCK_MUTATE_SERVICE: 'updater',
                MOCK_AFTER_RESTART_COUNT: '4',
            },
        });

        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /untouched service updater restart count changed/);
        assert.doesNotMatch(result.stdout, /deploy ok/);
    } finally {
        fixture.cleanup();
    }
});

test('deploy fails closed unless the running service result is exactly backend', () => {
    const fixture = createDeployExecuteFixture();
    try {
        const result = run(deployScript, fixture.deployArgs, {
            env: { ...fixture.deployEnv, MOCK_BACKEND_RUNNING_OUTPUT: 'backend\nmongo\n' },
        });

        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /backend is not reported running after deploy/);
        assert.doesNotMatch(result.stdout, /deploy ok/);
        const calls = fs.readFileSync(fixture.commandLog, 'utf8');
        assert.doesNotMatch(calls, /^curl /m, 'public request must not run after the backend gate fails');
    } finally {
        fixture.cleanup();
    }
});

test('deploy fails closed when the public HTTPS health request fails', () => {
    const fixture = createDeployExecuteFixture();
    try {
        const result = run(deployScript, fixture.deployArgs, {
            env: { ...fixture.deployEnv, MOCK_CURL_EXIT: '22' },
        });

        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /public HTTPS health validation failed/);
        assert.doesNotMatch(result.stdout, /deploy ok/);
        const calls = fs.readFileSync(fixture.commandLog, 'utf8').trim().split('\n');
        for (const service of fixture.untouchedServices) {
            const psSuffix = ` ps --status running --quiet ${service}`;
            assert.equal(
                calls.filter(call => call.endsWith(psSuffix)).length,
                1,
                `${service} post-check must not run after public health fails`,
            );
        }
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
        assert.match(first.stdout, /backup_dir=\/opt\/hysteria-panel-test-backups\/20260922T120000Z-<predeploy-commit-prefix>/);
        assert.match(first.stdout, /backup_id_source=predeploy-git-head/);
        assert.match(first.stdout, new RegExp(`candidate_source_commit=${sourceCommit}`));
        assert.match(first.stdout, new RegExp(`candidate_source_tree=${sourceTree}`));
        assert.doesNotMatch(first.stdout, /backup_dir=.*aaaaaaaaaaaa/);
        assert.match(first.stdout, /backup_steps=source,config,mongo/);
        assert.match(first.stdout, /container_build=backend/);
        assert.match(first.stdout, /container_restart=backend --no-deps/);
        assert.match(first.stdout, /untouched_services=mongo,redis,caddy,updater/);
        assert.match(first.stdout, /untouched_verification=container-id,restart-count/);
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

test('rollback refuses to restore when the retained install Git identity differs from the recorded baseline', () => {
    const fixture = createRollbackFixture();
    try {
        const installDir = path.join(fixture.testFsRoot, '/opt/hysteria-panel');
        fs.mkdirSync(installDir, { recursive: true });
        fs.writeFileSync(path.join(installDir, 'docker-compose.yml'), 'candidate source\n');
        fs.writeFileSync(path.join(installDir, '.gitignore'), '.env\n');
        fs.copyFileSync(fixture.configEnv, path.join(installDir, '.env'));
        fs.chmodSync(path.join(installDir, '.env'), 0o600);
        runChecked('git', ['init', '--quiet'], { cwd: installDir });
        runChecked('git', ['config', 'user.name', 'Staging Test'], { cwd: installDir });
        runChecked('git', ['config', 'user.email', 'staging-test@example.invalid'], { cwd: installDir });
        runChecked('git', ['add', 'docker-compose.yml', '.gitignore'], { cwd: installDir });
        runChecked('git', ['commit', '--quiet', '-m', 'different baseline'], { cwd: installDir });

        const result = run(rollbackScript, fixture.args(['--execute', 'true']), { env: fixture.rollbackEnv });
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /install Git identity does not match the recorded baseline/);
        assert.equal(fs.existsSync(fixture.hookLog), false);
        const calls = fs.existsSync(fixture.commandLog) ? fs.readFileSync(fixture.commandLog, 'utf8') : '';
        assert.doesNotMatch(calls, /^rsync /m, 'mismatched Git identity must be rejected before replacement');
    } finally {
        fixture.cleanup();
    }
});

test('rollback rejects symlinked retained Git metadata before source restoration', () => {
    const fixture = createRollbackFixture();
    try {
        const installDir = path.join(fixture.testFsRoot, '/opt/hysteria-panel');
        runChecked('git', ['clone', '--quiet', '--no-local', fixture.sourceStage, installDir]);
        fs.copyFileSync(fixture.configEnv, path.join(installDir, '.env'));
        fs.chmodSync(path.join(installDir, '.env'), 0o600);
        const gitMetadata = path.join(installDir, '.git');
        const externalGitMetadata = path.join(fixture.root, 'external-retained-git-metadata');
        fs.renameSync(gitMetadata, externalGitMetadata);
        fs.symlinkSync(externalGitMetadata, gitMetadata, 'dir');

        const result = run(rollbackScript, fixture.args(['--execute', 'true']), { env: fixture.rollbackEnv });
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /install Git metadata must be a real directory/);
        assert.equal(fs.existsSync(fixture.hookLog), false);
        const calls = fs.existsSync(fixture.commandLog) ? fs.readFileSync(fixture.commandLog, 'utf8') : '';
        assert.doesNotMatch(calls, /^rsync /m, 'unsafe Git metadata must be rejected before replacement');
    } finally {
        fixture.cleanup();
    }
});

test('rollback fails closed when public health or an untouched container check fails', () => {
    const cases = [
        {
            name: 'public health',
            env: { MOCK_CURL_EXIT: '22' },
            expected: /public HTTPS health validation failed/,
        },
        {
            name: 'untouched container identity',
            env: { MOCK_MUTATE_SERVICE: 'mongo', MOCK_AFTER_ID: 'f'.repeat(64) },
            expected: /untouched service mongo container identity changed/,
        },
    ];
    for (const testCase of cases) {
        const fixture = createRollbackFixture();
        try {
            prepareRollbackInstall(fixture);
            const result = run(rollbackScript, fixture.args(['--execute', 'true']), {
                env: { ...fixture.rollbackEnv, ...testCase.env },
            });
            assert.notEqual(result.status, 0, testCase.name);
            assert.match(result.stderr, testCase.expected);
            assert.doesNotMatch(result.stdout, /rollback ok/);
            assert.doesNotMatch(`${result.stdout}${result.stderr}`, /must-not-appear/);
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
        runChecked('git', ['clone', '--quiet', '--no-local', fixture.sourceStage, installDir]);
        fs.mkdirSync(path.join(installDir, 'config', 'test'), { recursive: true });
        fs.writeFileSync(path.join(installDir, 'docker-compose.yml'), 'candidate source\n');
        fs.writeFileSync(path.join(installDir, '.env'), 'OLD_SECRET=must-not-appear\n', { mode: 0o600 });
        fs.writeFileSync(path.join(installDir, '.celerity-staging-source.env'), 'candidate_source_commit=cccccccccccccccccccccccccccccccccccccccc\n');
        fs.writeFileSync(path.join(installDir, 'config', 'test', 'obsolete.conf'), 'obsolete\n');
        fs.writeFileSync(path.join(installDir, 'obsolete.js'), "'use strict';\n");

        const result = run(rollbackScript, fixture.args(['--execute', 'true']), { env: fixture.rollbackEnv });
        assert.equal(result.status, 0, result.stderr || result.stdout);
        assert.match(result.stdout, /rollback ok/);
        assert.doesNotMatch(`${result.stdout}${result.stderr}`, /must-not-appear/);
        assert.equal(fs.readFileSync(fixture.hookLog, 'utf8'), 'called\n');
        assert.equal(fs.existsSync(path.join(installDir, 'obsolete.js')), false);
        assert.equal(fs.existsSync(path.join(installDir, '.celerity-staging-source.env')), false);
        assert.equal(fs.existsSync(path.join(installDir, 'config', 'test', 'obsolete.conf')), false);
        assert.equal(runChecked('git', ['rev-parse', 'HEAD^{commit}'], { cwd: installDir }), fixture.deployedSourceCommit);
        assert.equal(runChecked('git', ['rev-parse', 'HEAD^{tree}'], { cwd: installDir }), fixture.deployedSourceTree);
        assert.equal(runChecked('git', ['status', '--porcelain=v1', '--untracked-files=no'], { cwd: installDir }), '');
        assert.equal(
            fs.readFileSync(path.join(installDir, 'index.js'), 'utf8'),
            fs.readFileSync(path.join(fixture.sourceStage, 'index.js'), 'utf8'),
        );
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
        const commandCalls = fs.readFileSync(fixture.commandLog, 'utf8').trim().split('\n');
        const backendUpdate = commandCalls.findIndex(call => call.endsWith(' up -d --no-deps backend'));
        const backendRunning = commandCalls.findIndex(call => call.endsWith(' ps --status running --services backend'));
        const publicHealth = commandCalls.indexOf(
            'curl --fail --silent --show-error --max-time 10 https://test.infograd.online/health',
        );
        assert.ok(backendUpdate >= 0);
        assert.ok(backendRunning > backendUpdate);
        assert.ok(publicHealth > backendRunning);
        for (const service of fixture.untouchedServices) {
            const expected = fixture.untouchedState[service];
            const psSuffix = ` ps --status running --quiet ${service}`;
            const psCalls = commandCalls.filter(call => call.endsWith(psSuffix));
            const inspectCall = `docker inspect --format {{.Id}} {{.RestartCount}} ${expected.id}`;
            const inspectCalls = commandCalls.filter(call => call === inspectCall);
            assert.equal(psCalls.length, 2, `${service} identity must be checked before and after`);
            assert.equal(inspectCalls.length, 2, `${service} restart count must be checked before and after`);
        }
    } finally {
        fixture.cleanup();
    }
});
