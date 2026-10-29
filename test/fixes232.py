#!/usr/bin/env python3
"""1.10.232: going back to an older version - only as far back as can still
run on the database as it is, which is never copied or put back.

* DOWNGRADE_FLOOR: the oldest version that can run on a database this one has
  used. The shape of the database it was set for is held here; when the
  shape changes this suite fails until the floor is raised and the new shape
  is written down.
* the floor in the database only ever rises; the daemon refuses below it and
  while anything is half done; root refuses below its own copy's floor, and
  below the one the daemon passes; going back to a version with no console
  takes the console's login script away.
* the page, the API, the command line and the console.

    ./test/fixes232.py
"""
import hashlib
import importlib.util
import json
import os
import random
import re
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
PORT = 19400 + random.randint(0, 90)

# The shape of the database DOWNGRADE_FLOOR was set for: every table, every
# column added later, every index, the split tables, the columns each engine
# treats apart. The same in 1.10.226 and 1.10.232.
FLOOR_SHAPE = {'floor': '1.10.226',
               'sha256': 'bd9faa25c4715226358c5d8575a5afd00c60ee62bcbafc02fcf79a153c279194'}


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


def shape(m):
    out = {}
    for n in ('SCHEMA', 'WIN_SCHEMA', 'LIST_TABLES', 'SECRET_TABLES', 'CARRY_TABLE'):
        out[n] = getattr(m, n, None)
    for cls in ('Storage', 'Dialect', 'SqliteDialect', 'ServerDialect', 'MariaDialect',
                'PostgresDialect'):
        c = getattr(m, cls, None)
        for k, v in vars(c).items() if c else []:
            if k.isupper() and re.search(r'COLUMNS|INDEXES|INDEX$|^SPLIT$|TABLES|SCHEMA', k) \
                    and not re.search(r'MOST|LOOK|TRIES|RETRY|LOCK', k):
                out['%s.%s' % (cls, k)] = v
    def plain(v):
        # Sets in an order that is the same on every run (a set's own order
        # is not, from one start of Python to the next).
        if isinstance(v, (set, frozenset)):
            return sorted(plain(x) for x in v)
        if isinstance(v, dict):
            return {str(k): plain(x) for k, x in v.items()}
        if isinstance(v, (list, tuple)):
            return [plain(x) for x in v]
        return v if isinstance(v, (str, int, float, bool, type(None))) else str(v)
    return hashlib.sha256(json.dumps(plain(out), sort_keys=True).encode()).hexdigest()


# Before anything is opened: an engine sets a few of these as it starts.
SHAPE_NOW = shape(isemon)
work = Path(tempfile.mkdtemp(prefix='isemon-232-'))
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
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'mikrotik1': 0, 'upgrade_check': 0,
                      'downgrade_offered': 1})     # switched on (1.10.233: off as it comes)
(state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
up = daemon.upgrades
HERE_V = isemon.__version__
a, b, c = (int(x) for x in HERE_V.split('.')[:3])
OLDER = '%d.%d.%d' % (a, b, c - 1)
FLOOR = isemon.DOWNGRADE_FLOOR
BELOW = '%s.%s.%d' % tuple(FLOOR.split('.')[:2] + [int(FLOOR.split('.')[2]) - 1])

try:
    print('\nThe floor, and the shape of the database it was set for')
    ok('DOWNGRADE_FLOOR is %s, and older than this version' % FLOOR,
       (FLOOR, isemon.Upgrades.ver_tuple(FLOOR) < isemon.Upgrades.ver_tuple(HERE_V)),
       (FLOOR_SHAPE['floor'], True))
    ok('the database has the shape the floor was set for - if this fails, the shape changed: '
       'raise DOWNGRADE_FLOOR to this version and write the new shape down here',
       SHAPE_NOW, FLOOR_SHAPE['sha256'])
    ok('written as root reads it: a line of its own', bool(re.search(
        r"^DOWNGRADE_FLOOR = '[0-9.]+'$", (ROOT / 'isemon.py').read_text(encoding='utf-8'),
        re.M)))
    ok('written into the database it runs on', store.get_meta('downgrade_floor'), FLOOR)
    store.set_meta('downgrade_floor', OLDER)
    ok('one written by a later version raises it', up.floor(), OLDER)
    up.note_floor()
    ok('...and this one never lowers it', store.get_meta('downgrade_floor'), OLDER)
    store.set_meta('downgrade_floor', FLOOR)
    ok('...and it is only ever this version’s own or higher', up.floor(), FLOOR)

    print('\nWhat is refused')
    ok('not older: refused', 'not older' in up.back_refused(HERE_V))
    ok('older than the floor: refused, said why',
       'oldest version that can run on this database' in up.back_refused(BELOW))
    ok('the floor itself: safe', up.back_refused(FLOOR), '')
    ok('...and one between: safe', up.back_refused(OLDER), '')
    np = daemon.netpower
    np._put('fw:trial', {'id': 'x', 'until': time.time() + 300, 'by': 'boss', 'min': 5})
    ok('not while a change waits to be kept', up.back_refused(OLDER).startswith('not now'))
    np._put('fw:trial', {})
    job = daemon.job_start('rescan', lambda progress: time.sleep(1.5), label='going back over')
    ok('not while a long job is going', 'going back over is going' in up.back_refused(OLDER))
    time.sleep(2)
    ok('...and safe again once it is done', up.back_refused(OLDER), '')

    print('\nRoot, from its own copy of the program')
    keys = work / 'keys'
    keys.mkdir()
    sh('openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(keys / 'r.key'))
    sh('openssl', 'pkey', '-in', str(keys / 'r.key'), '-pubout', '-out', str(keys / 'test.pub'))
    lib = work / 'lib'
    lib.mkdir()
    os.environ.update(ISEMON_RELEASE_KEYS=str(keys), ISEMON_LIB=str(lib),
                      ISEMON_CONSOLE_PROFILE=str(work / 'zz-isemon-console.sh'))

    def installed(version, floor=None):
        (lib / 'isemon.py').write_text("__version__ = '%s'\n%s" % (
            version, ("DOWNGRADE_FLOOR = '%s'\n" % floor) if floor else ''))

    def package(version, console=False):
        top = work / 'pk' / ('isemon-%s' % version)
        shutil.rmtree(str(top.parent), ignore_errors=True)
        (top / 'deploy' / 'release-keys').mkdir(parents=True)
        shutil.copy(str(keys / 'test.pub'), str(top / 'deploy' / 'release-keys'))
        if console:
            (top / 'deploy' / 'isemon-console-login.sh').write_text('# console\n')
        (top / 'isemon.py').write_text("__version__ = '%s'\n" % version)
        (top / 'install.sh').write_text('#!/bin/bash\necho put in here\n')
        out = work / ('isemon-%s.tar.gz' % version)
        got = sh(sys.executable, str(ROOT / 'tools' / 'release.py'), str(top),
                 str(keys / 'r.key'), str(out))
        if got.returncode:
            print(got.stdout, got.stderr)
        return out

    spec = importlib.util.spec_from_file_location('upg', str(ROOT / 'deploy' /
                                                              'isemon_upgrade.py'))
    upg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(upg)
    installed(HERE_V, FLOOR)
    ok('root reads the floor of the version installed', upg.installed_floor(), FLOOR)
    installed('1.10.231')
    ok('...and of one that does not say, nothing', upg.installed_floor(), '')
    if os.geteuid() == 0:
        installed('1.10.231')
        pk = package(FLOOR)
        try:
            upg.put_in(str(pk), downgrade=True)
            ok('a version that does not say how far back is safe: refused', False)
        except upg.Refused as e:
            ok('a version that does not say how far back is safe: refused',
               'does not say how far back' in str(e))
        installed(HERE_V, FLOOR)
        try:
            upg.put_in(str(pk))
            ok('older, not asked for as going back: refused', False)
        except upg.Refused as e:
            ok('older, not asked for as going back: refused', 'going back is asked' in str(e))
        try:
            upg.put_in(str(package(BELOW)), downgrade=True)
            ok('below the floor: refused by root too', False)
        except upg.Refused as e:
            ok('below the floor: refused by root too', 'oldest version' in str(e))
        try:
            upg.put_in(str(package(FLOOR)), downgrade=True, want_floor=OLDER)
            ok('the database’s higher floor, passed by the daemon, is kept to', False)
        except upg.Refused as e:
            ok('the database’s higher floor, passed by the daemon, is kept to',
               OLDER in str(e))
        try:
            upg.put_in(str(package(FLOOR)), downgrade=True, want_floor='1.0.0')
            ok('...but a lower one passed changes nothing', True)
        except upg.Refused as e:
            ok('...but a lower one passed changes nothing', str(e))
        prof = work / 'zz-isemon-console.sh'
        prof.write_text('# login\n')
        rc, info, lines = upg.put_in(str(package(FLOOR)), downgrade=True)
        ok('to the floor: put in', (rc, info['version']), (0, FLOOR))
        ok('...said as going back, the database left as it is',
           any('the database is left as it is' in l for l in lines))
        ok('...the console’s login script taken away, %s having none' % FLOOR,
           prof.exists(), False)
        prof.write_text('# login\n')
        rc, info, lines = upg.put_in(str(package(OLDER, console=True)), downgrade=True)
        ok('...kept when the older version has a console too', (rc, prof.exists()), (0, True))
    else:
        print('  (not root: put_in is not run here)')

    print('\nFrom upgrade_url, through the API')
    WEB = {}
    API = 'https://api.github.com/repos/falco81/ISEMon/contents/release?ref=main'
    RAW = 'https://raw.githubusercontent.com/falco81/ISEMon/main/release/'
    WEB[API] = (json.dumps([{'type': 'file', 'name': 'isemon-%s.tar.gz' % v,
                             'download_url': RAW + 'isemon-%s.tar.gz' % v}
                            for v in (OLDER, FLOOR, BELOW)]).encode(), 'application/json')
    installed(HERE_V, FLOOR)

    def fake_get(url, limit=4 * 1024 * 1024, accept='*/*', timeout=30):
        if url not in WEB:
            raise urllib.error.URLError('no answer from %s' % url)
        return WEB[url][0], WEB[url][1], url
    isemon.Upgrades.online_get = staticmethod(fake_get)
    WEB[RAW + 'isemon-%s.tar.gz' % OLDER] = (package(OLDER).read_bytes(), 'application/gzip')
    up.online_look('boss')
    back = up.back_view()
    ok('the older versions there, each safe or why not',
       [(p['version'], p['safe']) for p in back['older']],
       [(OLDER, True), (FLOOR, True), (BELOW, False)])
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
    ok('anybody signed in sees what going back can reach', (st, d['back']['floor']), (200, FLOOR))
    ok('...read only may not go', call('/api/upgrade', {'action': 'go_back', 'version': OLDER},
                                       session=tok['watcher'])[0], 403)
    st, d = call('/api/upgrade', {'action': 'go_back', 'version': BELOW}, session=tok['boss'])
    ok('below the floor: refused, nothing fetched', (st, (state / 'upgrade' /
                                                          'request.json').exists()), (400, False))
    st, d = call('/api/upgrade', {'action': 'go_back', 'version': OLDER}, session=tok['boss'])
    req = json.loads((state / 'upgrade' / 'request.json').read_text()) \
        if (state / 'upgrade' / 'request.json').exists() else {}
    ok('a safe one: fetched, checked and begun', (st, d.get('running'), req.get('version')),
       (200, True, OLDER))
    ok('...asked of root as going back, with the database’s floor',
       (req.get('downgrade'), req.get('floor')), (True, FLOOR))
    ok('...and the package waiting says so', (up.package() or {}).get('downgrade'), True)
    ok('Events says it', any('going back to isemon %s' % OLDER in (e['detail'] or '')
                             for e in store.events(limit=30)[0]))
    api.stop() if hasattr(api, 'stop') else None

    print('\nThe command line, the console and the page')
    src = (ROOT / 'isemon.py').read_text(encoding='utf-8')
    ok('isemon --downgrade-check and --downgrade VERSION', all(
        o in src for o in ("'--downgrade-check'", "'--downgrade', metavar='VERSION'")))
    ok('the console: Upgrades - Go back to an older version',
       "('6', 'Go back to an older version', back)" in src)
    page = (ROOT / 'web' / 'index.php').read_text(encoding='utf-8')
    ok('the page: a card of its own, the version typed before it goes', all(w in page for w in (
        '<h2>Going back to an older version</h2>', "action: 'go_back'",
        "'Type the version to go back to'")))
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
