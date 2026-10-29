#!/usr/bin/env python3
"""1.10.228: new versions from the web - upgrade_url asked once a day and on
Look now, a GitHub folder read through its API (and through its own page
when the API refuses), a listing, one package's address; the newest newer
one offered, fetched, checked by root's helper exactly as one sent by hand,
and begun only when asked. The web itself is not reached: what it would
answer is handed in.

    ./test/fixes228_upgrade.py
"""
import json
import os
import random
import shutil
import subprocess
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
PORT = 19700 + random.randint(0, 90)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def sh(*args, **kw):
    return subprocess.run(list(args), capture_output=True, text=True, **kw)


work = Path(tempfile.mkdtemp(prefix='isemon-228u-'))
state = work / 'state'
(state / 'upgrade').mkdir(parents=True)
isemon.STATE_DIR = state
isemon.DB_FILE = state / 'd.db'
isemon.BACKUP_DIR = state / 'backups'
isemon.DUMP_DIR = state / 'dumps'
isemon.RUN_DIR = state
isemon.LOG_DIR = state
isemon.CONFIG_FILE = state / 'config.json'
isemon._LOG_PATH = state / 'd.log'
isemon.TOKEN_FILE = state / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'mikrotik1': 0})
(state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
up = daemon.upgrades

# A release key and packages signed with it, as tools/release.py signs them.
keys = work / 'keys'
keys.mkdir()
sh('openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(keys / 'r.key'))
sh('openssl', 'pkey', '-in', str(keys / 'r.key'), '-pubout', '-out', str(keys / 'test.pub'))
os.environ['ISEMON_RELEASE_KEYS'] = str(keys)
lib = work / 'lib'
lib.mkdir()
(lib / 'isemon.py').write_text("__version__ = '%s'\n" % isemon.__version__)
os.environ['ISEMON_LIB'] = str(lib)
a, b, c = (int(x) for x in isemon.__version__.split('.')[:3])
NEXT = '%d.%d.%d' % (a, b, c + 1)
OLDER = '%d.%d.%d' % (a, b, c - 1)


def package(version):
    top = work / 'pk' / ('isemon-%s' % version)
    shutil.rmtree(str(top.parent), ignore_errors=True)
    (top / 'deploy' / 'release-keys').mkdir(parents=True)
    shutil.copy(str(keys / 'test.pub'), str(top / 'deploy' / 'release-keys'))
    (top / 'isemon.py').write_text("__version__ = '%s'\n" % version)
    (top / 'README.md').write_text('## Version\n\n%s\n\n- from the web\n\n1.0.0\n\n- old\n'
                                   % version)
    (top / 'install.sh').write_text('#!/bin/bash\necho done here\n')
    out = work / ('isemon-%s.tar.gz' % version)
    got = sh(sys.executable, str(ROOT / 'tools' / 'release.py'), str(top), str(keys / 'r.key'),
             str(out))
    if got.returncode:
        print(got.stdout, got.stderr)
    return out.read_bytes()


# What the web would answer, address by address.
WEB = {}
ASKED = []


def fake_get(url, limit=4 * 1024 * 1024, accept='*/*', timeout=30):
    ASKED.append(url)
    if not str(url).startswith('https://'):
        raise ValueError('only https:// addresses are asked: %s' % url)
    if url not in WEB:
        raise urllib.error.URLError('no answer from %s' % url)
    body, ctype = WEB[url]
    if isinstance(body, Exception):
        raise body
    if len(body) > limit:
        raise ValueError('too big')
    return body, ctype, url


isemon.Upgrades.online_get = staticmethod(fake_get)

try:
    print('\nThe setting')
    ok('looked for once a day, at the release folder of the repository',
       (isemon.DEFAULTS['upgrade_check'], isemon.DEFAULTS['upgrade_url']),
       (1, 'https://github.com/falco81/ISEMon/tree/main/release'))
    ok('an https address is taken', isemon.check_setting('upgrade_url', ' https://x.example/r/ '),
       'https://x.example/r/')
    for bad in ('http://x.example/r', 'ftp://x', 'https://x.example/a b', 'javascript:x'):
        try:
            isemon.check_setting('upgrade_url', bad)
            ok('refused: %s' % bad, False)
        except ValueError:
            ok('refused: %s' % bad, True)
    ok('...and empty is taken (nothing looked at)', isemon.check_setting('upgrade_url', ''), '')

    print('\nWhat the address has')
    API = 'https://api.github.com/repos/falco81/ISEMon/contents/release?ref=main'
    WEB[API] = (json.dumps([
        {'type': 'file', 'name': 'isemon-%s.tar.gz' % OLDER, 'size': 100,
         'download_url': 'https://raw.githubusercontent.com/falco81/ISEMon/main/release/'
                         'isemon-%s.tar.gz' % OLDER},
        {'type': 'file', 'name': 'isemon-%s.tar.gz' % NEXT, 'size': 200,
         'download_url': 'https://raw.githubusercontent.com/falco81/ISEMon/main/release/'
                         'isemon-%s.tar.gz' % NEXT},
        {'type': 'file', 'name': 'README.md', 'download_url': 'https://x/README.md'},
        {'type': 'dir', 'name': 'isemon-9.9.9.tar.gz', 'download_url': 'https://x/d'},
    ]).encode(), 'application/json')
    got = up.online_list(isemon.DEFAULTS['upgrade_url'])
    ok('a GitHub folder, through its API: the packages, newest first, nothing else',
       [p['version'] for p in got], [NEXT, OLDER])
    ok('...from where GitHub keeps the files', got[0]['url'].startswith(
        'https://raw.githubusercontent.com/falco81/ISEMon/main/release/'))
    # The API refusing: the folder's own page is read for the names.
    WEB[API] = (urllib.error.HTTPError(API, 403, 'rate limited', {}, None), '')
    WEB[isemon.DEFAULTS['upgrade_url']] = (
        ('<a href="/falco81/ISEMon/blob/main/release/isemon-%s.tar.gz">isemon-%s.tar.gz</a>'
         % (NEXT, NEXT)).encode(), 'text/html')
    got = up.online_list(isemon.DEFAULTS['upgrade_url'])
    ok('GitHub’s API refusing: the names read off the folder’s own page',
       [(p['version'], p['url']) for p in got],
       [(NEXT, 'https://raw.githubusercontent.com/falco81/ISEMon/main/release/isemon-%s.tar.gz'
         % NEXT)])
    WEB['https://dl.example.cz/isemon/'] = (
        ('<a href="isemon-%s.tar.gz">a</a> <a href=\'isemon-%s.tar.gz\'>b</a> '
         '<a href="http://evil.example/isemon-9.9.9.tar.gz">c</a> <a href="otp-1.0.1.tar.gz">'
         % (OLDER, NEXT)).encode(), 'text/html')
    got = up.online_list('https://dl.example.cz/isemon/')
    ok('a folder listing: its links to packages, none that is not https',
       [(p['version'], p['url']) for p in got],
       [(NEXT, 'https://dl.example.cz/isemon/isemon-%s.tar.gz' % NEXT),
        (OLDER, 'https://dl.example.cz/isemon/isemon-%s.tar.gz' % OLDER)])
    got = up.online_list('https://github.com/falco81/ISEMon/blob/main/release/isemon-%s.tar.gz'
                         % NEXT)
    ok('one package’s GitHub page: read as the file itself', [p['url'] for p in got],
       ['https://raw.githubusercontent.com/falco81/ISEMon/main/release/isemon-%s.tar.gz' % NEXT])

    print('\nLooked at, and offered')
    del ASKED[:]
    WEB[API] = (json.dumps([{'type': 'file', 'name': 'isemon-%s.tar.gz' % NEXT,
                             'download_url': 'https://raw.githubusercontent.com/falco81/ISEMon/'
                                             'main/release/isemon-%s.tar.gz' % NEXT}]).encode(),
                'application/json')
    row = up.online_look('boss')
    ok('a newer one is there', (row.get('newer'), (row.get('newest') or {}).get('version')),
       (True, NEXT))
    ok('...said once, in the events', len([e for e in store.events(limit=50)[0]
                                            if 'is out' in (e['detail'] or '')]), 1)
    up.online_look('boss')
    ok('...and not again for the same version', len([e for e in store.events(limit=50)[0]
                                                      if 'is out' in (e['detail'] or '')]), 1)
    view = up.page(True)['online']
    ok('the page has it', (view['online'].get('newer'), view['check'], view['url']),
       (True, True, isemon.DEFAULTS['upgrade_url']))
    ok('nothing was fetched, and nothing waits', up.package(), None)
    WEB[API] = (urllib.error.URLError('blocked'), '')
    WEB.pop(isemon.DEFAULTS['upgrade_url'], None)
    row = up.online_look('boss')
    ok('an address that does not answer is said so, not thrown', bool(row.get('error')), True)

    print('\nOnce a day, behind the loop')
    started = []
    real_thread = isemon.threading.Thread

    class NoThread(object):
        def __init__(self, target=None, **kw):
            self.target = target

        def start(self):
            started.append(1)
            self.target()
    isemon.threading.Thread = NoThread
    try:
        up._online_tried = 0
        up.online_tick()
        ok('just looked: not again within the day', started, [])
        store.set_meta(up.ONLINE_META, json.dumps({'at': time.time() - 90000,
                                                   'url': up.online_url()}))
        up._online_tried = 0
        up.online_tick()
        ok('a day on: looked at again', started, [1])
        up._online_tried = 0
        isemon.CONFIG['upgrade_check'] = 0
        store.set_meta(up.ONLINE_META, '{}')
        up.online_tick()
        ok('switched off: never by itself', started, [1])
        isemon.CONFIG['upgrade_check'] = 1
        isemon.CONFIG['upgrade_url'] = 'https://elsewhere.example/r/'
        store.set_meta(up.ONLINE_META, json.dumps({'at': time.time(),
                                                   'url': isemon.DEFAULTS['upgrade_url']}))
        up._online_tried = 0
        up.online_tick()
        ok('...and asked at once when the address changed', started, [1, 1])
        isemon.CONFIG['upgrade_url'] = isemon.DEFAULTS['upgrade_url']
    finally:
        isemon.threading.Thread = real_thread

    print('\nFetched, and checked as a package sent by hand')
    RAW = 'https://raw.githubusercontent.com/falco81/ISEMon/main/release/isemon-%s.tar.gz' % NEXT
    WEB[API] = (json.dumps([{'type': 'file', 'name': 'isemon-%s.tar.gz' % NEXT,
                             'download_url': RAW}]).encode(), 'application/json')
    good = package(NEXT)
    WEB[RAW] = (good[:-200] + b'\0' * 200, 'application/gzip')
    try:
        up.online_fetch(NEXT, 'boss')
        ok('a package changed on the way is refused', False)
    except isemon.WebRootError as e:
        ok('a package changed on the way is refused', 'refused' in str(e))
    ok('...and nothing waits', up.package(), None)
    WEB[RAW] = (good, 'application/gzip')
    kept = up.online_fetch(NEXT, 'boss')
    ok('the signed one is taken, and waits', (kept['version'], (up.package() or {}).get('version')),
       (NEXT, NEXT))
    ok('...what changed in it read from its README', kept.get('changelog'), '- from the web')
    try:
        up.online_fetch(OLDER, 'boss')
        ok('a version that is not there any more is refused', False)
    except isemon.WebRootError:
        ok('a version that is not there any more is refused', True)
    up.forget('boss')

    print('\nThrough the API')
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    daemon.add_user('watcher', 'a-third-long-password', 'readonly', by='test')
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
    tok = {n: call('/api/auth/login', {'name': n, 'password': p})[1]['token']
           for n, p in (('boss', 'a-long-enough-password'), ('watcher', 'a-third-long-password'))}
    st, d = call('/api/upgrade', session=tok['watcher'])
    ok('read only sees what the web has', (st, 'online' in d), (200, True))
    ok('...but may not ask it', call('/api/upgrade', {'action': 'online_look'},
                                     session=tok['watcher'])[0], 403)
    st, d = call('/api/upgrade', {'action': 'online_look'}, session=tok['boss'])
    ok('Look now', (st, d['online']['online'].get('newer'), d['message']),
       (200, True, 'isemon %s is there' % NEXT))
    st, d = call('/api/upgrade', {'action': 'online_fetch', 'version': NEXT},
                 session=tok['boss'])
    ok('Only fetch it: checked and waiting, not begun',
       (st, (d.get('package') or {}).get('version'), d.get('running'),
        (state / 'upgrade' / 'request.json').exists()), (200, NEXT, False, False))
    st, d = call('/api/upgrade', {'action': 'online_fetch', 'version': NEXT, 'start': True},
                 session=tok['boss'])
    ok('Upgrade now: fetched, checked and begun - the request laid down for root',
       (st, d.get('running'), (state / 'upgrade' / 'request.json').exists()), (200, True, True))
    st, d = call('/api/upgrade', {'action': 'online_fetch', 'version': NEXT, 'start': True},
                 session=tok['boss'])
    ok('...and not a second time while it runs', st, 400)
    api.stop() if hasattr(api, 'stop') else None

    print('\nThe command line and the page')
    src = (ROOT / 'isemon.py').read_text(encoding='utf-8')
    for opt in ('--upgrade-check', '--upgrade-online', '--upgrade-follow', '--upgrade-status'):
        ok('isemon %s' % opt, "'%s'" % opt in src)
    ok('the bar of the command line', isemon.upgrade_bar(50, 10), '[#####-----]  50 %')
    page = (ROOT / 'web' / 'index.php').read_text(encoding='utf-8')
    ok('the page: From the web, Look now, Upgrade now, Only fetch it',
       all(w in page for w in ('<h2>From the web</h2>', "'Look now'", "'Only fetch it'",
                                "action: 'online_fetch'", 'id="sect-upgrade"')))
    ok('...and the settings drawn there', "upgrade: ['upgrade_check', 'upgrade_url'" in page)
    ok('the settings menu in groups', all(('<div class="ctl-group">%s</div>' % g) in page for g in (
        'Logs read', 'Banning', 'The firewall', 'Access', 'Server', 'Data',
        'Monitoring and updates')))
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
