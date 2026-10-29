#!/usr/bin/env python3
"""1.10.230: the console when root signs in, switched on Settings - About -
the same choice as `isemon --console-at-login on|off`, written by root
(isemon_web.py) into /etc/isemon-console-login, which the isemon account may
not write itself.

    ./test/fixes230.py
"""
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
work = Path(tempfile.mkdtemp(prefix='isemon-230-'))
state = work / 'state'
(state / 'web').mkdir(parents=True)
FLAG = work / 'console-login'
PROFILE = work / 'zz-isemon-console.sh'
os.environ.update(ISEMON_CONSOLE_FLAG=str(FLAG), ISEMON_CONSOLE_PROFILE=str(PROFILE),
                  ISEMON_WEB_HELPER='1')
sys.path.insert(0, str(ROOT))
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19500 + random.randint(0, 90)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


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
np = daemon.netpower
HELPER_ENV = dict(os.environ, ISEMON_STATE=str(state), ISEMON_WEB_NO_SERVICES='1',
                  ISEMON_NGINX_CONF=str(work / 'none.conf'), ISEMON_CERT_DIR=str(work),
                  ISEMON_RSYSLOG=str(work / 'none'))
stop = []


def root_loop():
    """isemon-web.path and its service, as systemd would start them."""
    while not stop:
        if (state / 'web' / 'net.ask').exists():
            subprocess.run([sys.executable, '-I', str(ROOT / 'deploy' / 'isemon_web.py')],
                           env=HELPER_ENV, capture_output=True)
        time.sleep(0.2)


threading.Thread(target=root_loop, daemon=True).start()
try:
    print('\nThe choice, as root keeps it')
    ok('no file: off', np.console_view()['on'], False)
    PROFILE.write_text('# the login script\n')
    got = np.console_set(True, 'boss')
    ok('switched on: root wrote it', (FLAG.read_text(), got['on']), ('on\n', True))
    ok('...a plain file anybody may read and only root write', oct(FLAG.stat().st_mode & 0o777),
       '0o644')
    ok('...the same thing --console-at-login reads', isemon.console_at_login(), True)
    ok('...and Events says who', any('switched the console at login on' in (e['detail'] or '')
                                     for e in store.events(limit=20)[0]), True)
    FLAG.unlink()
    os.symlink(str(work / 'elsewhere'), str(FLAG))
    np.console_set(False, 'boss')
    ok('a link in its place is replaced, never followed',
       (FLAG.is_symlink(), FLAG.read_text(), (work / 'elsewhere').exists()), (False, 'off\n', False))
    PROFILE.unlink()
    got = np.console_set(True, 'boss')
    ok('the login script missing is said', any('install.sh' in w for w in got['said']), True)
    PROFILE.write_text('# the login script\n')

    print('\nRoot checks it again')
    np.daemon.webroot.write('net.ask', {'do': 'console', 'on': 'yes', 'id': 'x1'})
    deadline = time.time() + 10
    said = {}
    while time.time() < deadline:
        said = np.daemon.webroot.read('net.json') or {}
        if said.get('id') == 'x1':
            break
        time.sleep(0.2)
    ok('anything but on or off is refused', (said.get('ok'), 'on or off' in said.get('said', '')),
       (False, True))

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
    tok = {n: call('/api/auth/login', {'name': n, 'password': p})[1]['token']
           for n, p in (('boss', 'a-long-enough-password'), ('watcher', 'a-third-long-password'))}
    st, d = call('/api/console-login', session=tok['watcher'])
    ok('read only sees it, and may not switch it', (st, d['on'], d['may']), (200, True, False))
    ok('...and is refused when it tries', call('/api/console-login', {'on': False},
                                               session=tok['watcher'])[0], 403)
    st, d = call('/api/console-login', {'on': False}, session=tok['boss'])
    ok('a full administrator switches it off', (st, d['on'], FLAG.read_text()), (200, False, 'off\n'))
    ok('...on or off only', call('/api/console-login', {'on': 'yes'}, session=tok['boss'])[0], 400)
    api.stop() if hasattr(api, 'stop') else None

    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text(encoding='utf-8')
    ok('About has the switch', all(w in page for w in (
        'id="about-console"', "'Open the console when root signs in'", "'console-login'")))
    ok('...put in by the save bar, not the moment it is pressed (1.10.234)', all(
        w in page for w in ("extraPending('console', {", "api('console-login', {on: on})")))
finally:
    stop.append(1)
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
