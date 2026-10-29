#!/usr/bin/env python3
"""1.10.233: going back to an older version is offered only when switched on
(off as it comes) - the card, the page's button, isemon --downgrade and the
console alike - and every older version says what changed in it, read from
this version's own README, which keeps every version's entry.

    ./test/fixes233.py
"""
import json
import os
import random
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
os.environ['ISEMON_UPGRADE_HELPER'] = '1'
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19300 + random.randint(0, 90)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


work = Path(tempfile.mkdtemp(prefix='isemon-233-'))
state = work / 'state'
(state / 'upgrade').mkdir(parents=True)
isemon.STATE_DIR = state
isemon.DB_FILE = state / 'd.db'
isemon.BACKUP_DIR = state / 'backups'
isemon.RUN_DIR = state
isemon.LOG_DIR = state
isemon.CONFIG_FILE = state / 'config.json'
isemon._LOG_PATH = state / 'd.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'mikrotik1': 0, 'upgrade_check': 0})
(state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
up = daemon.upgrades
FLOOR = isemon.DOWNGRADE_FLOOR
a, b, c = (int(x) for x in isemon.__version__.split('.')[:3])
OLDER = '%d.%d.%d' % (a, b, c - 1)

try:
    print('\nOff as it comes')
    ok('downgrade_offered is 0 as it comes', isemon.DEFAULTS['downgrade_offered'], 0)
    ok('...a switch with a name and words', all(
        'downgrade_offered' in d for d in (isemon.Daemon.TUNABLE, isemon.Daemon.NAMES,
                                           isemon.Daemon.SAYS)))
    ok('off: going back is refused, and says where it is switched on',
       'isemon --set downgrade_offered=1' in up.back_refused(OLDER))
    ok('...and the page is told so', up.back_view()['offered'], False)
    isemon.CONFIG['downgrade_offered'] = 1
    ok('on: a safe one is not refused', up.back_refused(OLDER), '')
    ok('...and the page is told so', up.back_view()['offered'], True)

    print('\nWhat changed in each older version')
    ok('read from this version’s own README', up.changelog_of(OLDER).startswith('- '))
    ok('...the entry of that version and no other',
       '1.10.%d' % (c - 2) not in up.changelog_of(OLDER).split('\n')[0])
    ok('the floor’s too', bool(up.changelog_of(FLOOR)), True)
    ok('a version with no entry: nothing', up.changelog_of('9.9.9'), '')

    WEB = {}
    API = 'https://api.github.com/repos/falco81/ISEMon/contents/release?ref=main'
    RAW = 'https://raw.githubusercontent.com/falco81/ISEMon/main/release/'
    WEB[API] = (json.dumps([{'type': 'file', 'name': 'isemon-%s.tar.gz' % v,
                             'download_url': RAW + 'isemon-%s.tar.gz' % v}
                            for v in (OLDER, FLOOR)]).encode(), 'application/json')

    def fake_get(url, limit=4 * 1024 * 1024, accept='*/*', timeout=30):
        if url not in WEB:
            raise urllib.error.URLError('no answer from %s' % url)
        return WEB[url][0], WEB[url][1], url
    isemon.Upgrades.online_get = staticmethod(fake_get)
    up.online_look('boss')
    back = up.back_view()
    ok('each older version carries what changed in it',
       [bool(p.get('changelog')) for p in back['older']], [True, True])

    print('\nThrough the API')
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    api = isemon.ApiServer(daemon, PORT)
    api.start()
    time.sleep(0.4)

    def call(path, payload=None, session=None):
        req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                     data=json.dumps(payload).encode() if payload is not None
                                     else None, method='POST' if payload is not None else 'GET')
        req.add_header('X-Isemon-Token', isemon.API_TOKEN)
        req.add_header('Content-Type', 'application/json')
        if session:
            req.add_header('X-Isemon-Session', session)
        try:
            with urllib.request.urlopen(req, timeout=120) as answer:
                return answer.status, json.loads(answer.read().decode() or '{}')
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')
    tok = call('/api/auth/login', {'name': 'boss', 'password': 'a-long-enough-password'})[1]
    isemon.CONFIG['downgrade_offered'] = 0
    st, d = call('/api/upgrade', {'action': 'go_back', 'version': OLDER}, session=tok['token'])
    ok('switched off: going back refused through the API too, nothing laid down for root',
       (st, 'switched off' in d.get('error', ''), (state / 'upgrade' / 'request.json').exists()),
       (400, True, False))
    api.stop() if hasattr(api, 'stop') else None

    print('\nThe page, the command line and the console')
    page = (ROOT / 'web' / 'index.php').read_text(encoding='utf-8')
    ok('the card is hidden until it is switched on', all(w in page for w in (
        'id="up-back-card" hidden', "$('up-back-card').hidden = !b.offered;",
        "upgrade: ['upgrade_check', 'upgrade_url', 'downgrade_offered']")))
    ok('...shown or taken away as soon as the switch is saved',
       "'downgrade_offered' in want" in page)
    ok('a What changed button on every older version', all(w in page for w in (
        "cmdButton('What changed', 'list', 'small')", 'function upChangelog(p)')))
    src = (ROOT / 'isemon.py').read_text(encoding='utf-8')
    ok('isemon --downgrade-check --changes', "'--changes'" in src)
    ok('the console offers what changed before it goes back',
       "('changes', 'What changed in %s' % ver)" in src)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
