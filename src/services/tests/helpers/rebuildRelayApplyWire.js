'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const { join, dirname } = require('node:path');
const { generateBridgeSystemdService } = require('../../configGenerator');

// Closed model of the ordinary rebuild transport's shell frames. Nothing here
// invokes a shell. In particular, staging alone doesn't change the live runtime.
module.exports = ({ root, records, writeRecords, mainPath, bridgePath }) => {
    const x = 'xray.service', b = 'xray-bridge.service';
    const xl = 'xl2tpd.service', net = 'celerity-rebuild-l2tp-network.service';
    const paths = { [x]: mainPath, [b]: bridgePath }, staged = new Set();
    const at = path => join(root, path);
    const exists = path => fs.existsSync(at(path));
    const ok = (stdout = '') => ({ status: 0, stdout, stderr: '' });
    const inactive = { ActiveState: 'inactive', SubState: 'dead', MainPID: '0', InvocationID: '' };
    const unitFile = '/etc/systemd/system/' + b;
    let token;
    return (command, stdin) => {
        const manager = records();
        const { units, effects, running, owners } = manager;
        const change = (verb, unit) => { effects.push(['apply', verb, ...(unit ? [unit] : [])]); writeRecords(manager); return ok(); };
        if (command === '/usr/local/bin/xray version' && stdin === undefined) return ok('Xray 26.3.27 (fixture)\n');
        const ids = [...new Set([...command.matchAll(/\.rebuild-([a-f0-9-]{36})\.json/g)].map(m => m[1]))];
        if (ids.length) {
            assert.equal(ids.length, 1);
            assert.match(ids[0], /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
            token ??= ids[0];
            assert.equal(ids[0], token);
        }
        const temp = path => `${path}.rebuild-${token}.json`;
        for (const [unit, path] of Object.entries(paths)) {
            if (stdin === undefined && command === `if test -f ${path}; then cat ${path}; elif test ! -e ${path}; then printf 'C3_CLASSIC_PROFILE_ABSENT'; else exit 1; fi`) {
                return ok(exists(path) ? fs.readFileSync(at(path), 'utf8') : 'C3_CLASSIC_PROFILE_ABSENT');
            }
            for (const property of ['LoadState', 'ExecStart']) {
                if (stdin === undefined && command === `systemctl show -p ${property} --value ${unit}`) return ok((units[unit][property] ?? '') + '\n');
            }
            const dir = dirname(path), file = temp(path);
            if (ids.length && command === `set -eu; umask 077; test ! -L ${dir}; test ! -L ${path}; if ! test -d ${dir}; then install -d -m 0755 ${dir}; fi; (set -C; cat > ${file}); /usr/local/bin/xray run -test -config ${file} >/dev/null 2>&1`) {
                assert.equal(typeof stdin, 'string');
                const config = JSON.parse(stdin);
                assert.ok(Array.isArray(config.inbounds) && Array.isArray(config.outbounds) && Array.isArray(config.routing?.rules));
                fs.mkdirSync(at(dir), { recursive: true, mode: 0o755 });
                fs.writeFileSync(at(file), stdin, { flag: 'wx', mode: 0o600 });
                staged.add(file);
                return change('stage', unit);
            }
            if (stdin === undefined && ids.length && command === `set -eu; if test -f ${path}; then chown --reference=${path} ${file}; chmod --reference=${path} ${file}; else chown root:$(id -gn nobody) ${file}; chmod 0640 ${file}; fi; mv -fT ${file} ${path}`) {
                assert.ok(staged.delete(file));
                const original = exists(path) ? fs.statSync(at(path)) : null;
                fs.chmodSync(at(file), original ? original.mode & 0o777 : 0o640);
                owners[fs.statSync(at(file)).ino] = original ? owners[original.ino] ?? [0, 0] : [0, 65534];
                fs.renameSync(at(file), at(path));
                return change('replace', unit);
            }
            if (stdin === undefined && command === `systemctl enable ${unit} && systemctl restart ${unit} && systemctl is-active --quiet ${unit}`) {
                assert.equal(units[unit].LoadState, 'loaded');
                const pid = String(++manager.nextPid);
                Object.assign(units[unit], { UnitFileState: 'enabled', ActiveState: 'active', SubState: 'running', MainPID: pid, InvocationID: 'apply-' + pid });
                running[unit] = JSON.parse(fs.readFileSync(at(path), 'utf8'));
                // A restart of a required unit can stop xl2tpd and leave its
                // oneshot failed on the existing kernel objects. They remain
                // quiescent; the live IKE and resident firewall are not erased.
                if (unit === x && units[net]?.ActiveState === 'active') {
                    Object.assign(units[xl], inactive);
                    Object.assign(units[net], inactive, { ActiveState: 'failed', SubState: 'failed', InvocationID: 'apply-net-' + pid });
                }
                return change('restart', unit);
            }
        }
        if (stdin === undefined && command === 'systemctl stop ' + b) {
            assert.equal(units[b].LoadState, 'loaded');
            Object.assign(units[b], inactive);
            delete running[b];
            return change('stop', b);
        }
        if (stdin === undefined && command === 'systemctl disable ' + b) {
            assert.equal(units[b].ActiveState, 'inactive');
            units[b].UnitFileState = 'disabled';
            return change('disable', b);
        }
        if (command === `set -eu; test ! -e ${unitFile}; test ! -L ${unitFile}; (umask 022; set -C; cat > ${unitFile}); systemctl daemon-reload`) {
            assert.equal(stdin, generateBridgeSystemdService());
            fs.mkdirSync(dirname(at(unitFile)), { recursive: true });
            fs.writeFileSync(at(unitFile), stdin, { flag: 'wx', mode: 0o644 });
            Object.assign(units[b], { ...inactive, LoadState: 'loaded', UnitFileState: 'disabled', FragmentPath: unitFile,
                ExecStart: `{ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config ${bridgePath} ; }` });
            return change('create', b);
        }
        if (stdin === undefined && ids.length && command === `rm -f -- ${temp(mainPath)} ${temp(bridgePath)}`) {
            for (const path of [mainPath, bridgePath]) {
                staged.delete(temp(path));
                fs.rmSync(at(temp(path)), { force: true });
            }
            return change('cleanup');
        }
        assert.fail('unexpected Apply SSH command');
    };
};
