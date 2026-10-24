#!/usr/bin/env python3
"""1.10.220: the dashboard's php2shell notice put away from the command line until the
daemon starts again - held in memory only, nothing saved.

    ./test/fixes220.py
"""
import json
import random
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19000 + random.randint(0, 900)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def call(path, method='GET', payload=None, session=None):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                 data=json.dumps(payload).encode() if payload is not None
                                 else None, method=method)
    req.add_header('X-Isemon-Token', isemon.API_TOKEN)
    if session:
        req.add_header('X-Isemon-Session', session)
    if payload is not None:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=60) as answer:
            return answer.status, json.loads(answer.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')


folder = tempfile.mkdtemp(prefix='isemon-220-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.TOKEN_FILE = Path(folder) / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'ise_paths': [folder], 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
daemon.add_user('guard', 'another-long-password', 'banadmin', by='test')
daemon.add_user('watcher', 'a-third-long-password', 'readonly', by='test')

print('\nIn the daemon')
ok('shown at the start', daemon.php_notice(), {'hidden': False})
said = daemon.php_notice(True, by='boss')
ok('hidden, with who and when', (said['hidden'], said['by'], abs(said['at'] - time.time()) < 5),
   (True, 'boss', True))
ok('...said in the status', daemon.status()['php_notice']['hidden'], True)
ok('nothing of it is saved: not in the settings', any('notice' in k for k in isemon.CONFIG), False)
meta = store.get_meta('php_notice', None) if hasattr(store, 'get_meta') else None
ok('...nor in the database', meta, None)
cfg_text = isemon.CONFIG_FILE.read_text() if isemon.CONFIG_FILE.exists() else ''
ok('...nor in the config file', 'notice' in cfg_text, False)
ok('written in the events', 'PHP version notice' in str(store.events(limit=20)))
again = isemon.Daemon(store)
ok('a daemon started again shows it', again.php_notice(), {'hidden': False})
ok('shown again on asking', daemon.php_notice(False, by='boss'), {'hidden': False})

print('\nThrough the API')
api = isemon.ApiServer(daemon, PORT)
api.start()
time.sleep(0.4)
try:
    tokens = {}
    for name, pw in (('boss', 'a-long-enough-password'), ('guard', 'another-long-password'),
                     ('watcher', 'a-third-long-password')):
        tokens[name] = call('/api/auth/login', 'POST', {'name': name, 'password': pw})[1]['token']
    status, said = call('/api/php-notice', session=tokens['watcher'])
    ok('anybody signed in may ask', (status, said.get('hidden')), (200, False))
    ok('nobody signed out may', call('/api/php-notice')[0] in (401, 403), True)
    for who in ('watcher', 'guard'):
        status, said = call('/api/php-notice', 'POST', {'notice': 'hide'}, session=tokens[who])
        ok('a %s may not hide it' % who, status, 403)
    ok('...and it is still shown', daemon.php_notice()['hidden'], False)
    status, said = call('/api/php-notice', 'POST', {'notice': 'hide'}, session=tokens['boss'])
    ok('an administrator may', (status, said.get('hidden'), said.get('by')), (200, True, 'boss'))
    status, said = call('/api/status', session=tokens['watcher'])
    ok('the status says so', said.get('php_notice', {}).get('hidden'), True)
    status, said = call('/api/php-notice', 'POST', {'notice': 'maybe'}, session=tokens['boss'])
    ok('anything but hide or show is refused', status, 400)
    status, said = call('/api/php-notice', 'POST', {'notice': 'show'}, session=tokens['boss'])
    ok('show brings it back', (status, said), (200, {'ok': True, 'hidden': False}))
finally:
    api.stop() if hasattr(api, 'stop') else None

print('\nThe command line')
p = isemon.build_parser() if hasattr(isemon, 'build_parser') else None
src = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
ok('--php-notice takes hide, show, or nothing',
   "choices=['hide', 'show', 'state'], dest='php_notice'" in src
   and "nargs='?', const='state'" in src.split("'--php-notice'")[1][:200])
ok('...and is a command of its own', '(bool(args.php_notice), cmd_php_notice)' in src)

print('\nThe page')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
ok('the notice follows the status at load',
   'box.hidden = !!(STATUS && STATUS.php_notice && STATUS.php_notice.hidden);' in page)
ok('...and on every status after', 'phpBox.hidden = !!(data.php_notice && data.php_notice.hidden);'
   in page)
ok('...only ever a notice that was wanted', 'if (phpBox && phpBox.dataset.wanted)' in page)
ok('it says how to hide it', 'isemon --php-notice hide' in page)
cs = (HERE.parent / 'web' / 'lang' / 'cs.json').read_text(encoding='utf-8')
ok('...in Czech as well', 'Skrytí této hlášky do restartu isemonu' in cs)

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
