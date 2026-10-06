import json
from pathlib import Path
import sys
import subprocess

def validate(path):
    raw = Path(path).read_bytes()
    assert not raw.startswith(b'\xef\xbb\xbf'), 'UTF-8 output must have no BOM'
    report = json.loads(raw.decode('utf-8'))
    assert report['schema_version'] == '1.0.0'
    assert [u['name'] for u in report['users']] == sorted(u['name'] for u in report['users'])
    assert [g['name'] for g in report['groups']] == sorted(g['name'] for g in report['groups'])
    for entity in report['users'] + report['groups']:
        for value in entity['fields'].values():
            assert value['status'] == 'available' or value['value'] is None
    for user in report['users']:
        for key in ('enabled', 'password_required', 'password_never_expires'):
            field = user['fields'][key]
            assert field['status'] != 'available' or type(field['value']) is bool
        assert user['local_groups'] == sorted(set(user['local_groups']))
    for group in report['groups']:
        assert [m['sid'] for m in group['members']] == sorted(m['sid'] for m in group['members'])
    if Path(path).name == 'fixture.json':
        ordinary = next(u for u in report['users'] if u['name'] == 'Z ordinary')
        assert ordinary['fields']['description']['value'] == '雪\n"test"\\\t'
        assert ordinary['fields']['logon_count']['value'] == 0
        assert ordinary['fields']['last_logon'] == {'status': 'unknown', 'value': None}
        assert any(u['name'] == 'Администратор' for u in report['users'])
        assert any(u['name'] == 'Invité' for u in report['users'])
    print(f'PASS: independent Python UTF-8 parsing, types, escaping and ordering: {path}')

for filename in sys.argv[1:3]:
    validate(filename)

if len(sys.argv) > 3:
    proc = subprocess.Popen([sys.argv[3], '--json'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdout.close()
    diagnostic = proc.stderr.read()
    assert proc.wait(timeout=30) == 1, 'Broken output must be fatal exit 1'
    assert b'Cannot write output' in diagnostic, diagnostic
    print('PASS: CLI output failure returns fatal exit 1')
