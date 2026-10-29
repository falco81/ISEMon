#!/usr/bin/env python3
"""1.10.199: one sign-in ended from its row in "Who is signed in", not only
all of them at once.

    ./test/fixes199.py
"""
import json
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
folder = tempfile.mkdtemp(prefix='isemon-199-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.BACKUP_DIR = Path(folder) / 'b'
isemon.DUMP_DIR = Path(folder) / 'd'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.TOKEN_FILE = Path(folder) / 'api-token'
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
api = isemon.ApiServer(daemon, port=__import__('os').getpid() % 20000 + 30000)
port = api.httpd.server_address[1]
api.start()


def call(path, body=None, sess=''):
    req = urllib.request.Request(
        'http://127.0.0.1:%d%s' % (port, path),
        data=None if body is None else json.dumps(body).encode(),
        headers={'X-Isemon-Token': isemon.API_TOKEN, 'X-Isemon-Session': sess,
                 'Content-Type': 'application/json', 'X-Isemon-Client': '10.0.0.5'})
    try:
        r = urllib.request.urlopen(req)
        return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


daemon.add_user('boss', 'password123', 'fulladmin')
daemon.add_user('viewer', 'password123', 'readonly')
mine = daemon.login('boss', 'password123', ip='10.0.0.5')['token']
other = daemon.login('boss', 'password123', ip='10.0.0.9')['token']
third = daemon.login('viewer', 'password123', ip='10.0.0.7')['token']

print('\nThe list')
st, d = call('/api/sessions', sess=mine)
rows = d.get('sessions') or []
ok('every sign-in has an id', all(r.get('id') for r in rows) and len(rows) == 3)
ok('...that is not the token', any(r['id'] in (mine, other, third) for r in rows), False)
ok('the asker\'s own is marked', [r['ip'] for r in rows if r.get('mine')], ['10.0.0.5'])

print('\nEnding one')
gone = [r for r in rows if r['ip'] == '10.0.0.9'][0]
st, d = call('/api/sessions', {'drop': gone['id']}, sess=mine)
ok('the one asked for ends', (st, store.session(other) is None), (200, True))
ok('...and only that one', (store.session(mine) is not None, store.session(third) is not None),
   (True, True))
st, d = call('/api/sessions', {'drop': gone['id']}, sess=mine)
ok('asked again: already ended', (st, d.get('ok')), (400, False))
st, d = call('/api/sessions', {'drop': 'nonsense'}, sess=mine)
ok('a made-up id ends nothing', st, 400)
st, d = call('/api/sessions', {'drop': [r for r in rows if r['ip'] == '10.0.0.5'][0]['id']},
             sess=third)
ok('a read-only account cannot end one', (st, store.session(mine) is not None), (403, True))
st, d = call('/api/sessions', sess=third)
ok('...and sees only its own', [r['name'] for r in d.get('sessions') or []], ['viewer'])

print('\nThe page')
ok('a button on every row', "'Name', 'Role', 'From', 'Signed in', 'Last seen', ''" in page
   and "api('sessions', {drop: one.id})" in page)
ok('ending your own is said to be signing out first', "'Sign me out', go);" in page)

api.stop()
shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
