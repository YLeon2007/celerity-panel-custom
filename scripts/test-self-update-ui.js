const assert = require('assert');
const fs = require('fs');
const path = require('path');

const panelIndex = fs.readFileSync(path.join(__dirname, '..', 'src/routes/panel/index.js'), 'utf8');
const settingsRoutes = fs.readFileSync(path.join(__dirname, '..', 'src/routes/panel/settings.js'), 'utf8');
const appJs = fs.readFileSync(path.join(__dirname, '..', 'public/js/app.js'), 'utf8');
const layout = fs.readFileSync(path.join(__dirname, '..', 'views/layout.ejs'), 'utf8');
const maintenance = fs.readFileSync(path.join(__dirname, '..', 'views/partials/settings/maintenance.ejs'), 'utf8');

assert(!layout.includes('panelUpdateWidget'), 'global topbar update widget must be removed');
assert(!layout.includes('panelUpdateAction'), 'global check-update button must be removed');
assert(!layout.includes('panelUpdateModal'), 'obsolete global update modal must be removed');
assert(maintenance.includes('updateCheckBtn') && maintenance.includes('checkForUpdates()'),
    'update check must remain available in Settings → Maintenance');
assert(maintenance.includes("document.body.appendChild(el)"),
    'update progress overlay must be moved outside transformed settings containers');
assert(maintenance.includes('id="updateAuthFields"') && maintenance.includes('onclick="submitUpdate()"'),
    'credentials and the real submit action must be directly visible in the maintenance card');
assert(!maintenance.includes('id="updateModal"') && !maintenance.includes('openUpdateModal'),
    'there must be no intermediate hidden confirmation modal');
assert(!maintenance.includes('for (let i = 0; i < 3; i++)'),
    'maintenance UI must not truncate version comparison to three components');
assert(maintenance.includes('Math.max(pa.length, pb.length, 4)'),
    'maintenance UI must compare four-component custom versions');
assert(maintenance.includes('id="updateApplyBtn"') && maintenance.includes('type="button"'),
    'update controls must not accidentally submit a surrounding settings form');

assert(!panelIndex.includes("require('./update')") && !panelIndex.includes('updateRoutes'),
    'obsolete legacy update routes must not be mounted');
assert(settingsRoutes.includes("router.get('/settings/update-status'")
    && settingsRoutes.includes("router.post('/settings/check-updates', checkUpdatesLimiter")
    && settingsRoutes.includes("router.post('/settings/apply-update', applyUpdateLimiter"),
    'Maintenance must use the current settings update endpoints and rate limits');
assert(settingsRoutes.includes('Admin.verifyPassword(req.session.adminUsername, currentPassword)')
    && settingsRoutes.includes('admin.twoFactor?.enabled')
    && settingsRoutes.includes('updateService.isKnownRelease(version)')
    && settingsRoutes.includes('updateService.startUpdateFlow(version, { backup: wantBackup })'),
    'update apply must re-authenticate, enforce TOTP/release whitelist, and start the guarded flow');
assert(
    appJs.includes('transientFailures') && appJs.includes('i18n.reconnecting'),
    'update modal polling must survive transient backend/rate-limit failures'
);


const selfUpdate = fs.readFileSync(path.join(__dirname, '..', 'scripts/self-update.sh'), 'utf8');

assert(
    selfUpdate.includes('detect_compose_project()') && selfUpdate.includes('com.docker.compose.project'),
    'self-update script must detect the existing Docker Compose project from running containers'
);
assert(
    selfUpdate.includes('docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml')
        && selfUpdate.includes('docker-compose -p "$COMPOSE_PROJECT" -f docker-compose.yml'),
    'self-update script must pass a stable project name to docker compose/docker-compose'
);
assert(
    selfUpdate.includes('SELF_UPDATE_DETACHED_HELPER:-1')
        && selfUpdate.includes('docker run -d --rm')
        && selfUpdate.includes('-v /var/run/docker.sock:/var/run/docker.sock')
        && selfUpdate.includes('Detached helper launched'),
    'self-update script must hand off rebuild to a detached helper by default so backend recreation does not kill the update'
);
assert(
    selfUpdate.includes('SELF_UPDATE_HELPER_IMAGE')
        && selfUpdate.includes('docker-cli-compose')
        && selfUpdate.includes('docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml up -d --build'),
    'detached helper must run host-side docker compose with the existing project name'
);
assert(
    selfUpdate.includes("printf 'hysteria-panel'"),
    'self-update script must have a stable fallback project name'
);
assert(
    selfUpdate.includes('awk -v dest="$REPO_PATH"')
        && selfUpdate.includes('*/hysteria-panel-host)')
        && selfUpdate.includes('${REPO_PATH%-host}'),
    'self-update helper must resolve container repo paths such as /opt/hysteria-panel-host to a real host bind source'
);

console.log('self-update UI tests passed');
