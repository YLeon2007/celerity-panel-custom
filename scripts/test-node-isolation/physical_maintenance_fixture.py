"""TEST ONLY: simulated UID/physical/guard/SSH/systemd; real files + attestor serve.

Not an installed CLI. The production attestor has no root/path/command selector.
"""
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('maintenance_attestor_fixture', HERE / 'physical_attestor.py')
assert spec and spec.loader
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
value = json.loads(sys.argv[1])
root = Path(value['maintenanceRoot'])
paths = {'config': str(root / 'config.json'), 'unit': str(root / 'xray.service')}


def read(path, directory=False):
    p = Path(path)
    st = p.lstat()
    return (b'' if directory else p.read_bytes(), SimpleNamespace(st_uid=0, st_gid=0, st_mode=st.st_mode))


class Host:
    def physical(self):
        return value['physical']  # explicitly simulated independent fixture

    def unit(self, name):
        state = json.loads((root / 'service-state.json').read_bytes())
        return {'Id': name, 'LoadState': 'loaded', 'FragmentPath': paths['unit'], 'DropInPaths': '',
                'ActiveState': state['serviceActive'], 'UnitFileState': state['serviceEnabled'], 'Job': ''}


class Engine:
    host = Host()
    plan_hash = value['planHash']
    plan = {**value['physical'], 'nodeId': value['nodeId'], 'targetProfile': value['targetProfile'],
            'maintenanceId': value['maintenanceId'], 'endpointIp': value['endpoint']['ip']}

    def assert_held(self):
        a.need((root / 'guard-alive').read_text() == 'held', 'SIMULATED_GUARD_LOST')
        return {'guard': value['guard']}


original_snapshot = a.config_snapshot
original_installation = a.installation
setattr(a, 'config_snapshot', lambda profile, host: original_snapshot(profile, host, read=read, paths=paths))
setattr(a, 'installation', lambda profile, host: original_installation(profile, host, read=read,
    paths={'runner': str(root / 'runner'), 'config': str(root / 'config-directory'), 'unit': paths['unit']}))
# This fixture exercises maintenance, not runner journal authority (covered by
# actual runner_state tests). Physical guard and systemd observations are simulated.
setattr(a, 'runner_state', lambda *_: {'head': None, 'journal': 'absent', 'legacyState': 'absent', 'terminal': None})
original_observe = a.observe


def observe(*args):
    result = original_observe(*args)
    if value.get('snapshotFault') == 'oversize':
        import base64
        result['configTransfer']['configBase64'] = base64.b64encode(b'x' * (512 * 1024 + 1)).decode('ascii')
    return result


setattr(a, 'observe', observe)
m = SimpleNamespace(STATE=str(root), decode_json=json.loads)
try:
    a.serve(Engine(), m, None)
except BaseException:
    # Production also emits only redacted retained-unknown errors, not bytes.
    sys.exit(75)
