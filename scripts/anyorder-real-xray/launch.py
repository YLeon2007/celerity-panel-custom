#!/usr/bin/env python3
"""Finite local fixture; private Podman wrapper only, exact-owned teardown.

No production env, credentials, endpoints, services, host namespace, socket,
privilege, device, published port, image pull/build or package installation.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tarfile
import time
import uuid

WRAPPER = Path('/home/leon/c3-portal-bridge-delivery-20261103/sandbox/podman.sh')
DEPS = Path('/home/leon/celerity-l2tp-dev/node_modules')
ENDPOINT = 'localhost/c3-pb-20261103-endpoint:fixture'
ENDPOINT_ID = '5af7de0b2c5de24f3d5d03cb9b0a3a2d2a05e13b30881b80097b0085a529ea20'
RUNNER = 'localhost/c3-pb-20261103-runner:fixture'
RUNNER_ID = '579e72bd5e5ab06d5d96ea1787b4da1ac6f182840febbb7e9350df82f722c87c'
EVIDENCE = Path('/home/leon/c3-anyorder-execution-20261104/xray-wave7')
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
NETWORK = ipaddress.ip_network('10.203.117.0/24')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def protobuf_bytes(field, data):
    def varint(n):
        result = bytearray()
        while n >= 128:
            result.append((n & 127) | 128)
            n >>= 7
        result.append(n)
        return bytes(result)
    return varint(field * 8 + 2) + varint(len(data)) + data


def private_geoip():
    # Deliberately synthetic protobuf GeoIPList, not a national geodata claim.
    record = protobuf_bytes(1, b'PRIVATE')
    for cidr in ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']:
        net = ipaddress.ip_network(cidr)
        record += protobuf_bytes(2, protobuf_bytes(1, net.network_address.packed) + bytes([16, net.prefixlen]))
    return protobuf_bytes(1, record)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--execute-local-fixture', action='store_true', required=True)
    args = parser.parse_args()
    assert args.execute_local_fixture and os.geteuid() != 0
    os.umask(0o077)
    EVIDENCE.mkdir(exist_ok=True)
    run_id = 'anyorder-' + secrets.token_hex(6)
    run = EVIDENCE / run_id
    run.mkdir(mode=0o700)
    owned = {}
    network_id = None
    result_code = 1
    log = (run / 'launcher.log').open('w', buffering=1)

    def save(name, data):
        (run / name).write_text(json.dumps(data, indent=2) + '\n')

    def pod(*args, check=True, timeout=90):
        # stdin is never used for credentials here; no values are logged.
        p = subprocess.run(['sh', str(WRAPPER), *map(str, args)], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, timeout=timeout)
        log.write(json.dumps({'action': args[0], 'exit': p.returncode, 'stderr': p.stderr[:2000]}) + '\n')
        if check and p.returncode:
            raise RuntimeError(f'private Podman {args[0]} exit={p.returncode}: {p.stderr[:1000]}')
        return p

    def inspect(names):
        if not names:
            return []
        return json.loads(pod('inspect', *names).stdout)

    def historic_snapshot(names):
        result = []
        for c in inspect(names):
            data = c.get('GraphDriver', {}).get('Data') or {}
            root = data.get('UpperDir') or data.get('MergedDir') or data.get('Dir')
            if not root and c.get('GraphDriver', {}).get('Name') == 'vfs':
                store = Path('/home/leon/c3-portal-bridge-delivery-20261103/podman-root')
                rows = json.loads((store / 'vfs-containers/containers.json').read_text())
                layer = next(row['layer'] for row in rows if row['id'] == c['Id'])
                root = str(store / 'vfs/dir' / layer)
            hashes = {}
            if root:
                for suffix in ['usr/local/etc/xray/config.json', 'usr/local/etc/xray-bridge/config.json',
                               'etc/systemd/system/xray.service', 'etc/systemd/system/xray-bridge.service']:
                    file = Path(root) / suffix
                    try:
                        hashes[suffix] = digest(file.read_bytes())
                    except (FileNotFoundError, PermissionError) as exc:
                        hashes[suffix] = type(exc).__name__
            result.append({'id': c['Id'], 'name': c['Name'], 'state': {k: c['State'].get(k) for k in
                           ['Status', 'Pid', 'StartedAt', 'FinishedAt']}, 'profileHashes': hashes})
        return result

    names = json.loads(pod('ps', '-a', '--format', 'json').stdout)
    existing_names = [c['Names'][0] if isinstance(c['Names'], list) else c['Names'] for c in names]
    before = historic_snapshot(existing_names)
    save('historical-before.json', before)
    existing_networks = json.loads(pod('network', 'inspect', *pod('network', 'ls', '--format', '{{.Name}}').stdout.split()).stdout)
    for network in existing_networks:
        for subnet in network.get('subnets', []):
            assert not NETWORK.overlaps(ipaddress.ip_network(subnet['subnet']))
    save('networks-before.json', existing_networks)
    for image, expected in [(ENDPOINT, ENDPOINT_ID), (RUNNER, RUNNER_ID)]:
        assert json.loads(pod('image', 'inspect', image).stdout)[0]['Id'].removeprefix('sha256:') == expected
    mem = {a.rstrip(':'): int(b.split()[0]) for a, b in
           (line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())}
    # New maximum 5*256MiB; reserve another 1.4GiB worker plus 1GiB headroom.
    assert mem['MemAvailable'] > (1280 + 1400 + 1024) * 1024, 'insufficient live memory reserve'
    save('resources-before.json', {'memAvailableKiB': mem['MemAvailable'], 'newMemoryMaxMiB': 1280,
                                 'reservedOtherWorkerMiB': 1400, 'reservedHeadroomMiB': 1024,
                                 'endpointImage': ENDPOINT_ID, 'runnerImage': RUNNER_ID})
    source = run / 'candidate'
    source.mkdir()
    archive = run / 'source.tar'
    head = subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip()
    subprocess.run(['git', '-C', str(REPO), 'archive', '-o', str(archive), head], check=True)
    with tarfile.open(archive) as tar:
        tar.extractall(source, filter='data')
    archive.unlink()
    assert not (source / '.env').exists(), 'candidate may not carry a production environment'
    save('pins.json', {'sourceCommit': head, 'sourceTree': subprocess.check_output(
        ['git', '-C', str(REPO), 'rev-parse', 'HEAD^{tree}'], text=True).strip(),
        'harness': {p.name: digest(p.read_bytes()) for p in HERE.iterdir() if p.is_file()},
        'packageLock': digest((source / 'package-lock.json').read_bytes()),
        'installedLock': digest((DEPS / '.package-lock.json').read_bytes()),
        'wrapper': digest(WRAPPER.read_bytes())})
    fixture = {'runId': run_id, 'nodes': {}, 'clientUuid': str(uuid.uuid4()),
               'linkUuids': {link: str(uuid.uuid4()) for link in ['pb1', 'pr', 'rb1', 'rb2']}}
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', run_id,
                    '-f', str(run / 'client-key')], check=True)
    fixture['sshPrivateKey'] = (run / 'client-key').read_text()
    (run / 'idle.json').write_text('{"inbounds":[],"outbounds":[{"protocol":"blackhole","tag":"block"}]}\n')
    (run / 'geoip.dat').write_bytes(private_geoip())
    frozen_harness = run / 'harness'
    frozen_harness.mkdir()
    for file in HERE.iterdir():
        if file.is_file():
            shutil.copy2(file, frozen_harness / file.name)
    network_name = run_id + '-net'
    try:
        pod('network', 'create', '--internal', '--subnet', str(NETWORK), network_name)
        network_id = json.loads(pod('network', 'inspect', network_name).stdout)[0]['id']
        for index, (node, role) in enumerate([('p', 'portal'), ('r', 'relay'), ('b1', 'bridge'), ('b2', 'bridge')], 11):
            directory = run / node
            directory.mkdir()
            hostkey = directory / 'hostkey'
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', run_id + '-' + node,
                            '-f', str(hostkey)], check=True)
            public = (directory / 'hostkey.pub').read_text().split()[1]
            import base64
            machine = secrets.token_hex(16)
            (directory / 'machine-id').write_text(machine + '\n')
            for service in ['xray', 'xray-bridge']:
                (directory / (service + '.service')).write_text('[Unit]\nDescription=Anyorder private fixture ' + service +
                    '\nAfter=network.target\n[Service]\nEnvironment=GOMAXPROCS=2\nType=simple\n'
                    'ExecStart=/usr/local/bin/xray run -config /usr/local/etc/' + service + '/config.json\nRestart=no\n')
            ip = str(NETWORK.network_address + index)
            name = run_id + '-' + node
            cid = pod('create', '--pull=never', '--name', name, '--hostname', name,
                      '--network', network_name, '--ip', ip, '--systemd=always', '--cgroupns=private',
                      '--pid=private', '--memory=256m', '--memory-swap=256m', '--cpus=0.3',
                      '--pids-limit=128', '--security-opt=no-new-privileges',
                      '--volume', f'{directory / "machine-id"}:/etc/machine-id:ro', ENDPOINT).stdout.strip()
            owned[name] = cid
            save('owned.json', {'runId': run_id, 'containers': owned, 'network': network_name, 'networkId': network_id})
            for src, dest in [(run / 'client-key.pub', '/root/.ssh/authorized_keys'),
                              (hostkey, '/etc/ssh/ssh_host_ed25519_key'),
                              (directory / 'hostkey.pub', '/etc/ssh/ssh_host_ed25519_key.pub'),
                              (run / 'idle.json', '/usr/local/etc/xray/config.json'),
                              (run / 'idle.json', '/usr/local/etc/xray-bridge/config.json'),
                              (directory / 'xray.service', '/etc/systemd/system/xray.service'),
                              (directory / 'xray-bridge.service', '/etc/systemd/system/xray-bridge.service'),
                              (HERE / 'target.py', '/root/anyorder-target.py'),
                              (source / 'src/modules/relay-l2tp/node-artifacts/topology/runner.sh',
                               '/usr/local/bin/celerity-topology-node-runner-v2')]:
                pod('cp', src, name + ':' + dest)
            pod('start', name)
            for _ in range(30):
                if pod('exec', name, 'systemctl', 'is-active', 'ssh', check=False).returncode == 0:
                    break
                time.sleep(0.3)
            else:
                raise RuntimeError('own endpoint SSH service did not start')
            pod('exec', name, 'install', '-d', '-m', '0755', '/usr/local/share/xray')
            pod('cp', run / 'geoip.dat', name + ':/usr/local/share/xray/geoip.dat')
            (directory / 'target.service').write_text('[Unit]\nDescription=Anyorder loopback exit witness\n'
                '[Service]\nType=simple\nExecStart=/usr/bin/python3 /root/anyorder-target.py ' + node + ' ' + machine + '\nRestart=no\n')
            pod('cp', directory / 'target.service', name + ':/etc/systemd/system/anyorder-target.service')
            pod('exec', name, 'sh', '-c', "chmod 0600 /etc/ssh/ssh_host_ed25519_key /root/.ssh/authorized_keys; "
                "chmod 0750 /usr/local/bin/celerity-topology-node-runner-v2; chmod 0644 /usr/local/share/xray/geoip.dat; "
                "printf '\n127.0.0.1 geo.anyorder.test\n' >> /etc/hosts; systemctl daemon-reload; systemctl start anyorder-target.service")
            boot = pod('exec', name, 'cat', '/proc/sys/kernel/random/boot_id').stdout.strip()
            fixture['nodes'][node] = {'role': role, 'ip': ip, 'nodeId': secrets.token_hex(12),
                'machineId': machine, 'bootId': boot, 'containerId': cid,
                'pin': {'expectedEndpoint': {'ip': ip, 'port': 22, 'username': 'root'},
                        'expectedHostKeySha256': digest(base64.b64decode(public))}}
        client_unit = run / 'client.service'
        client_unit.write_text('[Unit]\nDescription=Anyorder loopback VLESS probe\n[Service]\nEnvironment=GOMAXPROCS=2\nType=simple\n'
                              'ExecStart=/usr/local/bin/xray run -config /root/anyorder-client.json\nRestart=no\n')
        p_name = run_id + '-p'
        pod('cp', client_unit, p_name + ':/etc/systemd/system/anyorder-client.service')
        pod('exec', p_name, 'systemctl', 'daemon-reload')
        save('fixture.private.json', fixture)
        name = run_id + '-runner'
        (source / 'logs').mkdir(exist_ok=True)
        (run / 'logs').mkdir()
        args = ['create', '--pull=never', '--name', name, '--network', network_name,
                '--ip', str(NETWORK.network_address + 20), '--memory=256m', '--memory-swap=256m',
                '--cpus=0.5', '--pids-limit=96', '--cap-drop=all', '--security-opt=no-new-privileges',
                '--read-only', '--tmpfs', '/tmp:rw,size=32m', '--cgroupns=private', '--pid=private',
                '--volume', f'{source}:/candidate:ro', '--volume', f'{DEPS}:/deps:ro',
                '--volume', f'{run / "logs"}:/candidate/logs:rw',
                '--volume', f'{frozen_harness}:/harness:ro', '--volume', f'{run}:/work:rw',
                '--env', 'NODE_PATH=/deps', '--env', 'C3_CANDIDATE_ROOT=/candidate',
                '--env', 'C3_FIXTURE_WORK=/work', '--env', 'PANEL_DOMAIN=anyorder.invalid',
                '--env', 'ACME_EMAIL=fixture@anyorder.invalid', '--env', 'ENCRYPTION_KEY=' + secrets.token_hex(32),
                '--env', 'SESSION_SECRET=' + secrets.token_hex(32), '--env', 'LOG_LEVEL=error',
                '--workdir', '/work', RUNNER, 'node', '/harness/run.cjs']
        cid = pod(*args).stdout.strip()
        owned[name] = cid
        save('owned.json', {'runId': run_id, 'containers': owned, 'network': network_name, 'networkId': network_id})
        # Exact inspect confirms no host namespace, port publication or privilege.
        raw = inspect(list(owned))
        safe = []
        for c in raw:
            h = c['HostConfig']
            assert not h['Privileged'] and not h.get('PortBindings')
            assert h['NetworkMode'] != 'host' and h['PidMode'] != 'host'
            assert not any('/docker.sock' in m.get('Source', '') or '/podman.sock' in m.get('Source', '') for m in c['Mounts'])
            safe.append({'id': c['Id'], 'name': c['Name'], 'privileged': h['Privileged'],
                'networkMode': h['NetworkMode'], 'pidMode': h['PidMode'], 'memory': h['Memory'],
                'memorySwap': h['MemorySwap'], 'pidsLimit': h['PidsLimit'], 'ports': h.get('PortBindings'),
                'mounts': [{k: m.get(k) for k in ['Source', 'Destination', 'RW']} for m in c['Mounts']]})
        save('isolation.json', safe)
        pod('start', name)
        waited = pod('wait', '--condition', 'exited', name, timeout=1100)
        result_code = int(waited.stdout.strip())
        logs = pod('logs', name, check=False)
        (run / 'runner.log').write_text(logs.stdout + logs.stderr)
        save('exit.json', {'runnerExit': result_code})
    except Exception as exc:
        save('launcher-error.json', {'type': type(exc).__name__, 'message': str(exc)})
        raise
    finally:
        cleanup = {'containers': [], 'network': None}
        for name, cid in reversed(list(owned.items())):
            current = inspect([name])[0]
            assert current['Id'] == cid, 'cleanup identity changed'
            stopped = pod('stop', '--time', '4', name, check=False)
            removed = pod('rm', name, check=False)
            absent = pod('container', 'exists', cid, check=False).returncode == 1
            cleanup['containers'].append({'name': name, 'id': cid, 'stopExit': stopped.returncode,
                                           'removeExit': removed.returncode, 'absent': absent})
        if network_id:
            current = json.loads(pod('network', 'inspect', network_name).stdout)[0]
            assert current['id'] == network_id
            removed = pod('network', 'rm', network_name, check=False)
            absent = pod('network', 'exists', network_name, check=False).returncode == 1
            cleanup['network'] = {'name': network_name, 'removeExit': removed.returncode, 'absent': absent}
        after = historic_snapshot(existing_names)
        save('historical-after.json', after)
        cleanup['historicalUnchanged'] = before == after
        cleanup['complete'] = all(c['absent'] for c in cleanup['containers']) and bool(cleanup['network'] and cleanup['network']['absent']) and before == after
        save('cleanup.json', cleanup)
        print(json.dumps({'run': str(run), 'runnerExit': result_code, 'cleanup': cleanup['complete']}), flush=True)
        log.close()
        assert cleanup['complete'], 'exact-owned cleanup or historical preservation verification failed'
    return result_code


if __name__ == '__main__':
    raise SystemExit(main())
