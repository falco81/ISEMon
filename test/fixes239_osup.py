#!/usr/bin/env python3
"""1.10.239: Settings - System updates, as otp 1.0.158-1.0.160 has it, for one
server.

Root's half (isemon_web.py) is run here for real, with the package manager
played by a small script of the test's own (ISEMON_OSUP_PM) and the lock in
the test's folder (ISEMON_OSUP_LOCK); the work it starts runs as a process
of its own, as systemd-run would start it. A thread plays the path unit:
osup.ask (and net.ask, for a restart) handed to the helper at once. A
reboot is a new boot time (ISEMON_BTIME_FILE).

    ./test/fixes239_osup.py
"""
import importlib.util
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
sys.path.insert(0, str(ROOT))

work = Path(tempfile.mkdtemp(prefix='isemon-239osup-'))
state = work / 'state'
(state / 'web').mkdir(parents=True)
PM_STATE = work / 'pm.json'
PM = work / 'fake-dnf'
LOCK = work / 'osup.lock'
POWER = work / 'power.log'
BTIME = work / 'btime'
BTIME.write_text('1000\n')

os.environ.update(ISEMON_WEB_HELPER='1', ISEMON_BTIME_FILE=str(BTIME))
HELPER_ENV = dict(os.environ, ISEMON_STATE=str(state), ISEMON_WEB_NO_SERVICES='1',
                  ISEMON_OSUP_PM=str(PM), ISEMON_OSUP_LOCK=str(LOCK),
                  ISEMON_POWER_CMD=str(POWER), ISEMON_RSYSLOG=str(work / 'none'),
                  ISEMON_NGINX_CONF=str(work / 'none.conf'))

# ---- the fake package manager ---------------------------------------------------
PY = sys.executable
PM.write_text('''#!%s
import json, sys, time
p = %r
s = json.load(open(p))
a = sys.argv[1]
if a == 'check':
    print('# Last metadata expiration check: 0:01:00 ago')
    for x in s['pk']:
        print(x)
        sys.stdout.flush()
        time.sleep(s.get('slow_check', 0))
elif a == 'upgrade':
    print('Dependencies resolved.')
    print('Downloading Packages:')
    sys.stdout.flush()
    n = len(s['pk'])
    for i, x in enumerate(s['pk'], 1):
        time.sleep(s.get('slow', 0))
        print('  Upgrading        : %%s   %%d/%%d' %% (x.split()[0], i, n))
        sys.stdout.flush()
        if s.get('fail') and i == n:
            print('Error: Transaction test error: file /x conflicts')
            sys.exit(1)
    for i, x in enumerate(s['pk'], 1):
        print('  Verifying        : %%s   %%d/%%d' %% (x.split()[0], i, n))
    print('Complete!')
    s['upgraded'] = s.get('upgraded', 0) + 1
    if s.get('needs_after'):
        s['needs'] = True
    s['pk'] = []
    json.dump(s, open(p, 'w'))
elif a == 'needs-restart':
    sys.exit(1 if s.get('needs') else 0)
else:
    sys.exit(2)
''' % (PY, str(PM_STATE)))
PM.chmod(0o755)
PKGS = ['kernel-core.x86_64 5.14.0-503.el9', 'openssl.x86_64 3.2.2-6.el9 security',
        'nginx.x86_64 1.20.1-20.el9']


def pm(**kw):
    s = json.loads(PM_STATE.read_text()) if PM_STATE.exists() else {}
    s.update(kw)
    PM_STATE.write_text(json.dumps(s))
    return s


pm(pk=PKGS, needs=False)


def reboot():
    BTIME.write_text(str(float(BTIME.read_text()) + 100) + '\n')


def run_helper(*args):
    return subprocess.run(['python3', '-I', str(ROOT / 'deploy' / 'isemon_web.py')] + list(args),
                          capture_output=True, text=True, env=HELPER_ENV)


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


def wait_for(fn, secs=20):
    end = time.time() + secs
    while time.time() < end:
        try:
            if fn():
                return True
        except Exception:                               # noqa: BLE001
            pass
        time.sleep(0.1)
    return False


def said():
    try:
        return json.loads((state / 'web' / 'osup.json').read_text())
    except (OSError, ValueError):
        return {}


def answer():
    return json.loads((state / 'web' / 'osup.ans').read_text())


def ask(body):
    (state / 'web' / 'osup.ask').write_text(json.dumps(body))
    run_helper()
    return answer()


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
os.environ['ISEMON_UPGRADE_HELPER'] = '1'
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
np = daemon.netpower

# The path unit, played by a thread.
STOP = threading.Event()
UNIT = {'on': True}


def path_unit():
    while not STOP.is_set():
        if UNIT['on'] and ((state / 'web' / 'osup.ask').exists() or
                           (state / 'web' / 'net.ask').exists()):
            run_helper()
        time.sleep(0.05)


def osup_meta():
    return {k: store.get_meta(k, '') for k in ('osup:plan', 'osup:row', 'osup:check',
                                                'osup:checkwant', 'osup:seen', 'osup:cleared')}


def looked():
    """Every look asked for has been made, and is over."""
    want = json.loads(store.get_meta('osup:checkwant', '') or '{}')
    c = isemon.osup_check(store)
    return c.get('state') == 'done' and want.get('id') in (c.get('asked') or [])


def tick_until(fn, secs=30):
    def go():
        isemon.osup_tick(daemon)
        return fn()
    return wait_for(go, secs)


try:
    # ------------------------------------------------------------------------
    print('\nNothing happens until somebody asks')
    isemon.osup_tick(daemon)
    ok('a pass of the daemon asks root nothing and keeps nothing',
       ((state / 'web' / 'osup.ask').exists(), set(osup_meta().values())), (False, {''}))
    v = isemon.osup_view(daemon, True)
    ok('the page: nothing looked at, no update, root\'s half there',
       (v['plan'], v['nodes'][0]['check'], v['nodes'][0]['row'], v['helper'], v['cluster'],
        v['refused']), ({}, {}, {}, True, False, ''))
    ok('...and still nothing kept', set(osup_meta().values()), {''})

    # ------------------------------------------------------------------------
    print('\nRoot\'s helper')
    spec = importlib.util.spec_from_file_location('isemon_web_t', str(ROOT / 'deploy' /
                                                                      'isemon_web.py'))
    W = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(W)
    ok('the packages a restart is needed for, from the names',
       W.reboot_for(['kernel-core.x86_64 5.14', 'glibc.x86_64 2.34', 'nginx.x86_64 1.20',
                     'linux-firmware.noarch 2024', 'linux-image-6.1.0-26-amd64 6.1',
                     'systemd 252']),
       ['glibc', 'kernel-core', 'linux-firmware', 'linux-image-6.1.0-26-amd64', 'systemd'])
    a = ask({'do': 'run', 'kind': 'check', 'id': 'c1', 'at': time.time()})
    ok('a look asked: answered at once, under its id', (a['ok'], a['id'], a['data']),
       (True, 'c1', {'started': 'check', 'pm': 'fake'}))
    ok('...the asking file taken away', (state / 'web' / 'osup.ask').exists(), False)
    ok('...the work done by a process of its own, into osup.json',
       wait_for(lambda: said().get('id') == 'c1' and said().get('state') == 'done'))
    s = said()
    ok('what is waiting, how many of it security, the package manager',
       (s['packages'], s['count'], s['security'], s['pm'], s['kind']),
       (['kernel-core.x86_64 5.14.0-503.el9', 'openssl.x86_64 3.2.2-6.el9',
         'nginx.x86_64 1.20.1-20.el9'], 3, 1, 'fake', 'check'))
    ok('...a restart needed after it, for the kernel; none waiting now',
       (s['reboot_after'], s['reboot_why'], s['reboot_now']), (True, ['kernel-core'], False))
    ok('...and what it said, line by line',
       s['lines'][0].startswith('$ ') and 'a restart will be needed after the update: '
                                          'kernel-core' in s['lines'])
    for body, why, words in (
            ({'do': 'run', 'kind': 'rm -rf', 'id': 'x', 'at': time.time()}, 'another kind',
             'run: check or upgrade'),
            ({'do': 'install', 'kind': 'check', 'id': 'x', 'at': time.time()}, 'another verb',
             'run: check or upgrade'),
            ({'do': 'run', 'kind': 'upgrade', 'id': 'x', 'at': time.time() - 3600},
             'an old ask - one left behind is never done later', 'an old ask, not done: ask again'),
            ({'do': 'run', 'kind': 'upgrade', 'id': 'x'}, 'an ask that does not say when',
             'the ask does not say when it was made'),
            ({'do': 'run', 'kind': 'upgrade', 'id': '', 'at': time.time()}, 'an ask with no id',
             'the ask has no id')):
        a = ask(body)
        ok('refused: %s' % why, (a['ok'], a.get('said')), (False, words))
    (state / 'web' / 'osup.ask').write_text('[1, 2]')
    run_helper()
    ok('refused: an ask that is not an object', answer().get('said'),
       'the request is not an object')
    os.symlink('/etc/passwd', str(state / 'web' / 'osup.ask'))
    run_helper()
    ok('a link in place of the ask is taken away, never followed',
       os.path.lexists(str(state / 'web' / 'osup.ask')), False)
    (state / 'web' / 'osup.ask').mkdir()
    (state / 'web' / 'osup.ask' / 'x').write_text('x')
    run_helper()
    ok('...and a folder moved aside', os.path.lexists(str(state / 'web' / 'osup.ask')), False)
    # The lock: a link in its place starts nothing.
    LOCK.unlink()
    os.symlink(str(work / 'elsewhere'), str(LOCK))
    a = ask({'do': 'run', 'kind': 'check', 'id': 'c2', 'at': time.time()})
    ok('the lock a link: nothing started, nothing made where it points',
       (a['ok'], a.get('said'), (work / 'elsewhere').exists()),
       (False, 'an update or a look for updates is going on already', False))
    r = run_helper('--os-job', 'c3', 'check')
    ok('...nor by the work itself', (r.returncode, said().get('id')), (1, 'c1'))
    LOCK.unlink()
    pm(slow_check=0.4)
    a = ask({'do': 'run', 'kind': 'check', 'id': 'c4', 'at': time.time()})
    ok('a slow look begun', (a['ok'], wait_for(lambda: said().get('id') == 'c4')), (True, True))
    a = ask({'do': 'run', 'kind': 'upgrade', 'id': 'u0', 'at': time.time()})
    ok('...one more meanwhile is refused', (a['ok'], a.get('said')),
       (False, 'an update or a look for updates is going on already'))
    r = run_helper('--os-job', 'u1', 'upgrade')
    ok('...and the work started by hand does nothing under the lock', r.returncode, 1)
    ok('...the look goes on to its end', wait_for(lambda: said().get('state') == 'done'))
    pm(slow_check=0)

    # ------------------------------------------------------------------------
    print('\nA look for updates, from the daemon')
    th = threading.Thread(target=path_unit, daemon=True)
    th.start()
    writes = []
    real_set = store.set_meta

    def counting(key, value):
        if str(key).startswith('osup:'):
            writes.append(key)
        return real_set(key, value)
    store.set_meta = counting
    pm(slow_check=1.0)
    isemon.osup_check_ask(daemon, 'boss')
    ok('asked: the look is going on', wait_for(lambda: isemon.osup_check(store).get('state') ==
                                               'running'))
    v = isemon.osup_view(daemon, True)
    ok('...shown as it goes, its lines read from what the work writes',
       wait_for(lambda: len(isemon.osup_view(daemon, True)['nodes'][0]['check'].get('lines')
                            or []) >= 2))
    try:
        isemon.osup_check_ask(daemon, 'boss')
        ok('...a second look meanwhile is refused', False)
    except isemon.WebRootError as e:
        ok('...a second look meanwhile is refused', str(e), 'a look for updates is going on '
                                                            'already')
    try:
        isemon.osup_start(daemon, 'ask', 'boss')
        ok('...and so is an update', False)
    except isemon.WebRootError as e:
        ok('...and so is an update', str(e), 'a look for updates is going on - wait for it to '
                                             'end')
    before = len(writes)
    for _ in range(4):
        isemon.osup_tick(daemon)
        isemon.osup_view(daemon, True)
        time.sleep(0.1)
    ok('...its lines are not written into the database while it runs', len(writes), before)
    ok('done', tick_until(lambda: isemon.osup_check(store).get('state') == 'done'))
    c = isemon.osup_view(daemon, True)['nodes'][0]['check']
    ok('...what is waiting kept', (c['count'], c['security'], c['pm'], c['reboot_after'],
                                   c['reboot_why'], c['reboot_now'], len(c['packages'])),
       (3, 1, 'fake', True, ['kernel-core'], False, 3))
    ok('...with who asked and its last lines', (c['by'], c['lines'][-1]),
       ('boss', 'a restart will be needed after the update: kernel-core'))
    ok('the database written a handful of times, not at the rate of the lines',
       len(writes) <= 6, True)
    store.set_meta = real_set
    pm(slow_check=0)

    # ------------------------------------------------------------------------
    print('\nAn update is refused while something else is going on')
    daemon.upgrades.folder().mkdir(parents=True, exist_ok=True)
    (daemon.upgrades.folder() / 'status.json').write_text(json.dumps(
        {'state': 'running', 'at': time.time()}))
    for setup, words, undo in (
            (lambda: None, 'an upgrade of isemon is going on - wait for it to end',
             lambda: (daemon.upgrades.folder() / 'status.json').unlink()),
            (lambda: np._put('power:plan', {'id': 'p', 'how': 'reboot', 'state': 'asked',
                                            'at': time.time()}),
             'a restart or a power-off is going on - wait for it to end',
             lambda: np._put('power:plan', {})),
            (lambda: np._put('net:job', {'id': 'n', 'state': 'trial', 'at': time.time()}),
             'a new network is on trial - keep it, or put the old one back, first',
             lambda: np._put('net:job', {})),
            (lambda: np._put('net:job', {'id': 'n', 'state': 'running', 'at': time.time(),
                                         'moved': time.time()}),
             'the network is being changed - wait for it to end',
             lambda: np._put('net:job', {}))):
        setup()
        ok('the page says why: %s' % words, isemon.osup_view(daemon, True)['refused'], words)
        try:
            isemon.osup_start(daemon, 'ask', 'boss')
            ok('...and refuses it', False)
        except isemon.WebRootError as e:
            ok('...and refuses it', str(e), words)
        undo()
    ok('nothing was started', isemon.osup_plan(store), {})

    # ------------------------------------------------------------------------
    print('\nThe update: stopped before it begins')
    plan = isemon.osup_start(daemon, 'ask', 'boss')
    ok('asked: it waits a few seconds', (plan['state'], plan['order'], plan['reboot']),
       ('running', [isemon.socket.gethostname()], 'ask'))
    isemon.osup_tick(daemon)
    ok('...and does not begin within them', (isemon.osup_row(store).get('state'),
                                             (state / 'web' / 'osup.ask').exists()),
       (None, False))
    try:
        isemon.osup_start(daemon, 'ask', 'boss')
        ok('a second one meanwhile is refused', False)
    except isemon.WebRootError as e:
        ok('a second one meanwhile is refused', str(e), 'an update is going on already')
    try:
        isemon.osup_check_ask(daemon, 'boss')
        ok('...and a look for updates', False)
    except isemon.WebRootError as e:
        ok('...and a look for updates', str(e).startswith('the system is being updated'))
    isemon.osup_cancel(daemon, 'boss')
    p = isemon.osup_plan(store)
    ok('Stop: stopped before it began', (p['state'], p['cancelled_by']), ('cancelled', 'boss'))
    p['at'] = time.time() - 60
    store.set_meta('osup:plan', json.dumps(p))
    isemon.osup_tick(daemon)
    time.sleep(0.5)
    ok('...and never begins', (isemon.osup_row(store), json.loads(PM_STATE.read_text()).get(
        'upgraded')), ({}, None))
    try:
        isemon.osup_cancel(daemon, 'boss')
        ok('nothing to stop: said so', False)
    except isemon.WebRootError as e:
        ok('nothing to stop: said so', str(e), 'no update is going on')

    # ------------------------------------------------------------------------
    print('\nThe update, with a restart needed after it')
    pm(pk=PKGS, slow=0.4, needs_after=True)
    plan = isemon.osup_start(daemon, 'ask', 'boss')
    p = isemon.osup_plan(store)
    p['at'] = time.time() - isemon.OSUP_GRACE_S - 1
    store.set_meta('osup:plan', json.dumps(p))
    ok('its turn: the package manager at work',
       tick_until(lambda: isemon.osup_row(store).get('state') == 'updating', 20))
    ok('...shown going on, with a bar and its lines',
       wait_for(lambda: isemon.osup_view(daemon, True)['nodes'][0]['row'].get('pct', 0) > 10 and
                any('Upgrading' in x for x in isemon.osup_view(daemon, True)['nodes'][0]['row']
                    ['lines'])))
    row = isemon.osup_view(daemon, True)['nodes'][0]['row']
    ok('...the phase it is in', row['phase'], 'putting the packages in')
    ok('...not kept in the database meanwhile', isemon.osup_row(store).get('lines'), [])
    try:
        isemon.osup_cancel(daemon, 'boss')
        ok('Stop once it has begun: refused, it finishes', False)
    except isemon.WebRootError as e:
        ok('Stop once it has begun: refused, it finishes', str(e).startswith('it has begun'))
    for what, fn in (('a restart', lambda: np.power_ask('reboot', 'boss')),
                     ('an upgrade of isemon', lambda: daemon.upgrades.start('boss'))):
        try:
            fn()
            ok('%s meanwhile is refused' % what, False)
        except isemon.WebRootError as e:
            ok('%s meanwhile is refused' % what, 'the system is being updated' in str(e))
    ok('done', tick_until(lambda: isemon.osup_row(store).get('state') == 'done', 30))
    v = isemon.osup_view(daemon, True)
    n = v['nodes'][0]
    ok('...it needs a restart: said, and offered', (n['row']['said'], n['row']['reboot'],
                                                     n['reboot'], v['plan']['state']),
       ('updated - it needs a restart', True, True, 'done'))
    ok('...its lines kept, the last of them its end', n['row']['lines'][-1].startswith(
        'Reboot is required') or 'Complete!' in n['row']['lines'])
    ok('...and what is waiting looked at again', tick_until(
        lambda: looked() and
        isemon.osup_check(store).get('count') == 0 and
        isemon.osup_check(store).get('reboot_now') is True, 30))
    ok('...the restart is said waiting now', isemon.osup_view(daemon, True)['nodes'][0]['reboot'])
    reboot()
    pm(needs=False)
    isemon.osup_tick(daemon)
    ok('restarted: no restart waiting any more, and looked at again',
       tick_until(lambda: not isemon.osup_view(daemon, True)['nodes'][0]['reboot'] and
                  isemon.osup_row(store).get('rebooted') is True and
                  looked() and isemon.osup_check(store).get('reboot_now') is False, 30))

    # ------------------------------------------------------------------------
    print('\nClear the window, Hide it')
    v = isemon.osup_view(daemon, True)
    ok('the window has lines', bool(v['nodes'][0]['row']['lines']))
    isemon.osup_clear(daemon, 'boss')
    v = isemon.osup_view(daemon, True)
    ok('cleared: empty, for every page and after a reload', (v['nodes'][0]['row'].get('lines'),
                                                             v['nodes'][0]['check'].get('lines')),
       ([], []))
    isemon.osup_hide(daemon)
    v = isemon.osup_view(daemon, True)
    ok('Hide this: the update is not shown any more', v['plan'], {})

    # ------------------------------------------------------------------------
    print('\nRestarted by itself when it needs it')
    pm(pk=PKGS[:1], slow=0, needs_after=True, needs=False)
    POWER.write_text('')
    np._put('power:plan', {})
    isemon.osup_start(daemon, 'auto', 'boss')
    p = isemon.osup_plan(store)
    p['at'] = time.time() - 60
    store.set_meta('osup:plan', json.dumps(p))
    ok('updated, and the restart asked', tick_until(
        lambda: isemon.osup_row(store).get('state') == 'rebooting', 30))
    ok('...root asked for it', wait_for(lambda: POWER.read_text().split()[:1] == ['reboot']))
    v = isemon.osup_view(daemon, True)
    ok('...the page sees the restart going on, and offers none', (bool(v['power'].get('id')),
                                                                 v['plan']['state']),
       (True, 'running'))
    v2 = isemon.osup_view(daemon, True)
    ok('...the window shows the new lines, not the cleared ones', any(
        'Upgrading' in x for x in v2['nodes'][0]['row']['lines']))
    reboot()
    pm(needs=False)
    np.tick()
    ok('up again: done', tick_until(lambda: isemon.osup_row(store).get('state') == 'done' and
                                    isemon.osup_plan(store).get('state') == 'done', 30))
    ok('...said so', isemon.osup_row(store)['said'], 'up again after the restart')
    ok('...and looked at again', tick_until(
        lambda: looked() and not isemon.osup_view(daemon, True)['nodes'][0]['reboot'], 30))

    # ------------------------------------------------------------------------
    print('\nAn update that fails')
    np._put('power:plan', {})
    pm(pk=PKGS, fail=True, needs_after=False)
    isemon.osup_start(daemon, 'ask', 'boss')
    p = isemon.osup_plan(store)
    p['at'] = time.time() - 60
    store.set_meta('osup:plan', json.dumps(p))
    ok('failed: said, and the plan with it', tick_until(
        lambda: isemon.osup_plan(store).get('state') == 'failed', 30))
    r = isemon.osup_row(store)
    ok('...what the package manager said is kept', (r['state'], r['said'],
                                                    any('Error:' in x for x in r['lines'])),
       ('failed', 'fake-dnf ended with 1', True))
    pm(fail=False)

    # ------------------------------------------------------------------------
    print('\nRoot\'s half missing or not answering')
    os.environ['ISEMON_WEB_HELPER'] = '0'
    try:
        isemon.osup_check_ask(daemon, 'boss')
        ok('no helper: a look is refused, and why', False)
    except isemon.WebRootError as e:
        ok('no helper: a look is refused, and why', '1.10.239' in str(e))
    ok('...the page knows', isemon.osup_view(daemon, True)['helper'], False)
    os.environ['ISEMON_WEB_HELPER'] = '1'
    UNIT['on'] = False
    try:
        isemon._osup_job(daemon, 'upgrade', wait=1)
        ok('not answered: said', False)
    except isemon.WebRootError as e:
        ok('not answered: said', 'did not answer' in str(e))
    ok('...and the ask taken away, never done later by surprise',
       (state / 'web' / 'osup.ask').exists(), False)
    UNIT['on'] = True

    # ------------------------------------------------------------------------
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
            with urllib.request.urlopen(req, timeout=120) as got:
                return got.status, json.loads(got.read().decode() or '{}')
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')
    tok = {n: call('/api/auth/login', {'name': n, 'password': p})[1]['token']
           for n, p in (('boss', 'a-long-enough-password'), ('watcher', 'a-third-long-password'))}
    ok('nobody signed in may look', call('/api/osup')[0], 401)
    st, v = call('/api/osup', session=tok['watcher'])
    ok('read only may look', (st, v['may'], v['plan']['state'], v['nodes'][0]['me']),
       (200, False, 'failed', True))
    for body in ({'action': 'check'}, {'action': 'start'}, {'action': 'clear'},
                 {'action': 'reboot'}):
        ok('...and may not %s' % body['action'], call('/api/osup', body, tok['watcher'])[0], 403)
    pm(pk=PKGS, needs_after=False, needs=False)
    st, v = call('/api/osup', {'action': 'check'}, tok['boss'])
    ok('Look for updates', (st, v['message']), (200, 'looking for updates'))
    ok('...looked', tick_until(lambda: call('/api/osup', session=tok['boss'])[1]['nodes'][0]
                               ['check'].get('count') == 3, 30))
    st, v = call('/api/osup', {'action': 'start', 'reboot': 'auto'}, tok['boss'])
    ok('Update it now', (st, v['plan']['reboot'], v['message']),
       (200, 'auto', 'the update begins in a few seconds - it can be stopped until then'))
    st, v = call('/api/osup', {'action': 'cancel'}, tok['boss'])
    ok('Stop it', (st, v['message']), (200, 'stopped - nothing was updated'))
    st, v = call('/api/osup', {'action': 'hide'}, tok['boss'])
    ok('Hide this', (st, v['plan']), (200, {}))
    st, v = call('/api/osup', {'action': 'clear'}, tok['boss'])
    ok('Clear the window', (st, v['nodes'][0]['check']['lines']), (200, []))
    st, v = call('/api/osup', {'action': 'erase'}, tok['boss'])
    ok('anything else refused', st, 400)
    POWER.write_text('')
    st, v = call('/api/osup', {'action': 'reboot'}, tok['boss'])
    ok('Restart after the update', (st, v['message'], POWER.read_text().split()[:1]),
       (200, 'the server restarts in a few seconds', ['reboot']))
    st, v = call('/api/osup', {'action': 'start'}, tok['boss'])
    ok('...and an update meanwhile refused', (st, v.get('error')),
       (400, 'a restart or a power-off is going on - wait for it to end'))
    api.stop()

    # ------------------------------------------------------------------------
    print('\nThe page, the units and the installer')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('System updates in the Settings menu, under Server, after Restart and power off',
       page.index('data-pane="power"') < page.index('data-pane="osup"') <
       page.index('<div class="ctl-group">Data</div>'))
    ok('...its pane, drawn and followed', ('id="pane-osup"' in page, 'function loadOsup()' in page,
                                           'function drawOsup(' in page,
                                           "if (name === 'osup'" in page), (True,) * 4)
    ok('...reached through the page\'s door, to look and to ask',
       page.count("'osup'         => '/api/osup'"), 2)
    unit = (ROOT / 'deploy' / 'isemon-web.path').read_text()
    ok('the path unit watches osup.ask', 'PathExists=/var/lib/isemon/web/osup.ask' in unit)
    helper = (ROOT / 'deploy' / 'isemon_web.py').read_text()
    ok('root reads osup.ask before request.json', helper.index('        osup_part()') <
       helper.index("os.replace('request.json', 'request.taken'"))
    ok('...the work runs outside root\'s own service, under a lock never followed',
       ('systemd-run' in helper, 'os.O_NOFOLLOW' in helper.split('def osup_lock_fd')[1]
        .split('def ')[0]), (True, True))
    inst = (ROOT / 'install.sh').read_text()
    ok('install.sh puts the path unit in as it did', 'deploy/isemon-web.path" "$WEB_PATH_UNIT"'
       in inst)
    doc = (ROOT / 'docs' / 'system-updates.md').read_text()
    ok('...and the docs say how it works', ('osup.ask' in doc, 'Stop' in doc), (True, True))
finally:
    STOP.set()
    time.sleep(0.2)
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
