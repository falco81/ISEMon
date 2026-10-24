#!/usr/bin/env python3
"""A time window chosen by its dates.

From 1.10.152 every list searched over time can be given a window by its two
ends, picked on a bar from the first record this machine holds to now - and
"until now" keeps the end at the moment of each search. The lists already
took `from` and `to`; here: the daemon says when the first record of each
kind is, the Traffic tab's cards and chart take a window by its dates too,
and the page has what it needs.

    ./test/windows.py
"""
import json
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

PAGE_SRC = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
PASS = FAIL = 0
PORT = 19875


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


folder = tempfile.mkdtemp(prefix='isemon-windows-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'w.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'w.log'
isemon.TOKEN_FILE = Path(folder) / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'ise_paths': [folder]})

store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
daemon.add_user('watcher', 'another-long-password', 'readonly', by='test')
api = isemon.ApiServer(daemon, PORT)
api.start()
time.sleep(0.4)
print('  (engine: %s)' % store.dialect.name)

now = time.time()
try:
    status, data = call('/api/auth/login', 'POST', {'name': 'watcher',
                                                    'password': 'another-long-password'})
    looker = data['token']

    print('\nWhere the bar starts')
    status, said = call('/api/first?what=failed', session=looker)
    ok('nothing kept yet: no first record', (status, said.get('ts')), (200, 0))
    for n in range(4):
        store.add_failed({'session': 'w/%d' % n, 'ts': now - 3 * 86400 + n * 3600,
                          'ip': '203.0.113.%d' % (n + 1), 'username': 'INVALID',
                          'server': 'ise2', 'detail': '{}'})
    daemon._held = {} if hasattr(daemon, '_held') else None
    status, said = call('/api/first?what=passed', session=looker)
    ok('another kind is asked of its own table', (status, said.get('ts')), (200, 0))
    status, said = call('/api/first?what=failed&x=1', session=looker)
    for one in ('fw', 'win'):
        status, got = call('/api/first?what=%s' % one, session=looker)
        ok('the firewall’s and the domain’s are asked too (%s)' % one,
           (status, 'ts' in got), (200, True))
    status, said = call('/api/first?what=users', session=looker)
    ok('nothing but those four', status, 400)
    status, said = call('/api/first?what=failed')
    ok('nobody signed in is told', status, 401)

    print('\nThe lists by a window’s two ends')
    status, data = call('/api/failed?from=%d&to=%d' % (int(now - 3 * 86400 - 60),
                                                      int(now - 3 * 86400 + 5400)),
                        session=looker)
    ok('both ends', (status, data.get('total')), (200, 2))
    status, data = call('/api/failed?from=%d' % int(now - 3 * 86400 + 5400), session=looker)
    ok('...and "until now": no end, so it is now whenever it is asked',
       (status, data.get('total')), (200, 2))

    print('\nThe Traffic tab’s cards and chart by a window’s two ends')
    a, b = int(now - 2 * 86400), int(now - 86400)
    status, d = call('/api/fw?from=%d&to=%d' % (a, b), session=looker)
    ok('answered for that window: its start and its end', (status, d.get('until'),
       d.get('since', 0) <= a and d.get('since', 0) > a - 86400), (200, b, True))
    status, d = call('/api/fw?from=%d' % a, session=looker)
    ok('...or up to now', (status, d.get('until')), (200, 0))
    status, d = call('/api/fw?hours=24', session=looker)
    ok('...and by its length, as before', (status, d.get('hours'), d.get('until')),
       (200, 24, 0))

    print('\nThe page')
    ok('"choose dates…" on all four lists searched over time',
       PAGE_SRC.count('<option value="pick">choose dates…</option>') == 4
       and "['f-hours', 'p-hours', 'w-hours', 't-window'].forEach(windowInstall);" in PAGE_SRC,
       True)
    ok('...a bar from the first record to now with a handle at each end, the two moments, '
       'ready-made windows and "until now"', 'function windowPick(id, done)' in PAGE_SRC
       and "parts.lo.type = 'range';" in PAGE_SRC and "parts.from.type = 'datetime-local';"
       in PAGE_SRC and 'the end moves on with every search' in PAGE_SRC,
       True)
    ok('...asked as from and to, with no end for "until now"',
       "return 'from=' + Math.floor(w.from) + (w.to ? '&to=' + Math.floor(w.to) : '');"
       in PAGE_SRC and PAGE_SRC.count("windowArgs('f-hours')") >= 2
       and PAGE_SRC.count("windowArgs('p-hours')") >= 2 and "windowArgs('w-hours')" in PAGE_SRC
       and "api('fw&' + tWindowArgs() + tFwArg()" in PAGE_SRC, True)
    ok('the chart is drawn over the window’s own ends',
       'var end = Math.floor((d.until || Date.now() / 1000) / span) * span;' in PAGE_SRC, True)
finally:
    api.stop()
    shutil.rmtree(folder, ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
