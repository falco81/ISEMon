#!/usr/bin/env python3
"""1.10.229: Settings - About says what this server runs on, as otp's does:
isemon, Python and its modules, the libraries under them, the database, the
programs beside it, the system - and, from the page itself, its PHP and the
extensions php-fpm has loaded.

    ./test/fixes229.py
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
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19600 + random.randint(0, 90)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


work = Path(tempfile.mkdtemp(prefix='isemon-229-'))
state = work / 'state'
state.mkdir()
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

try:
    print('\nWhat this server runs on')
    sw = isemon.software_info(store)
    ok('isemon, Python, its OpenSSL and SQLite, the kernel', all(sw.get(k) for k in (
        'isemon', 'python', 'python_path', 'openssl', 'sqlite', 'kernel')))
    ok('...the version is this one', sw['isemon'], isemon.__version__)
    ok('...the database as it says itself', sw.get('database', '').startswith('SQLite '), True)
    ok('...the modules asked for, there or not', sorted(sw['modules']),
       ['colorama', 'psycopg2', 'pymysql'])
    ok('...programs only where they are', all(v for v in sw['programs'].values()), True)
    t0 = time.time()
    isemon.software_info(store)
    ok('asked again within the hour: from what was kept', time.time() - t0 < 0.5)

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
            with urllib.request.urlopen(req, timeout=60) as answer:
                return answer.status, json.loads(answer.read().decode() or '{}')
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')
    tok = call('/api/auth/login', {'name': 'watcher', 'password': 'a-third-long-password'})[1]
    st, d = call('/api/software', session=tok['token'])
    ok('anybody signed in may look', (st, d['software']['isemon']), (200, isemon.__version__))
    ok('...nobody else', call('/api/software')[0], 401)
    api.stop() if hasattr(api, 'stop') else None

    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text(encoding='utf-8')
    ok('its PHP and extensions added by the page itself', all(w in page for w in (
        "$what === 'software' && !$post", 'get_loaded_extensions()', "'opcache' =>")))
    ok('About draws it', 'drawSoftware(host);' in page and "'What it runs on'" in page)
    php = shutil.which('php')
    if php:
        ok('the page is PHP that reads', subprocess.run([php, '-l', str(ROOT / 'web' / 'index.php')],
                                                       capture_output=True).returncode, 0)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
